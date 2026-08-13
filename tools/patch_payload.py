#!/usr/bin/env python3
"""RMG 闭源引擎适配补丁工具
用法:
  python3 patch_payload.py <input.so> <patch_spec.json> <output.so>

patch_spec.json 格式:
{
  "symbol_fixes": [
    {"offset": 0x67ed, "type": "mov_imm16", "old_value": 0xd2f8, "new_value": 0xd338},
    ...
  ],
  "branch_nops": [0x9480, ...],
  "forced_flags": [{"offset": 0x26dd, "bytes": "1f2003d508008052"}]
}
"""
import sys, json, struct

def encode_mov_imm16(value: int) -> bytes:
    """ARM64 mov wN, #imm (16-bit immediate) - 只处理 imm16 低 16 位编码"""
    # movz w, #imm16 → 0x52800000 | (imm16 << 5) | rd
    # 我们只改 imm16 部分：imm16 在 bits[20:5]，即编码字节的 0-1 字节
    imm = value & 0xFFFF
    return struct.pack('<I', (imm << 5) | 0x52800000)

def parse_int(v):
    return int(v, 16) if isinstance(v, str) and v.lower().startswith('0x') else int(v)

def patch_payload(input_path: str, spec_path: str, output_path: str):
    data = bytearray(open(input_path, 'rb').read())
    spec = json.load(open(spec_path))

    for fix in spec.get('symbol_fixes', []):
        off = parse_int(fix['offset'])
        if fix.get('type') == 'mov_imm16':
            # 只验证 imm16 部分一致，然后改低 16 位编码
            new_imm = parse_int(fix['new_value']) & 0xFFFF
            # MOVZ 编码: imm16 << 5
            imm_bits = new_imm << 5
            cur = struct.unpack('<I', bytes(data[off:off+4]))[0]
            # 保留指令的高位（opcode, rd, 移位），替换 imm16
            new_insn = (cur & ~(0xFFFF << 5)) | imm_bits
            data[off:off+4] = struct.pack('<I', new_insn)
            print(f"  ✓ 0x{off:06x}: imm16 -> 0x{new_imm:x}")

    for bp in spec.get('byte_patches', []):
        off = parse_int(bp['offset'])
        raw = bytes.fromhex(bp['bytes'])
        data[off:off+len(raw)] = raw
        print(f"  ✓ 0x{off:06x}: byte patch {bp['bytes']}")

    for off in spec.get('branch_nops', []):
        # b.ne / b.eq 4字节 → NOP (d503201f)
        off = parse_int(off)
        data[off:off+4] = struct.pack('<I', 0xd503201f)
        print(f"  ✓ 0x{off:06x}: branch -> nop")

    for blk in spec.get('forced_flags', []):
        off = parse_int(blk['offset'])
        raw = bytes.fromhex(blk['bytes'])
        data[off:off+len(raw)] = raw
        print(f"  ✓ 0x{off:06x}: forced {blk['bytes']}")

    open(output_path, 'wb').write(bytes(data))
    import hashlib
    print(f"  ✓ 输出 {output_path} md5={hashlib.md5(bytes(data)).hexdigest()}")

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    patch_payload(sys.argv[1], sys.argv[2], sys.argv[3])
