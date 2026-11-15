#!/usr/bin/env python3
"""Read-only inspector for Panasonic Lumix DC-GH5 firmware update (MC561 / v2.8).

Reverse-engineered UPD container layout (GH5 equivalent of the G9 inspect tool):
  0x000: header  magic 'UPD\0', model 'MC561', filesize @0x3C
  0x2EC: directory, 40 entries x 0x5C bytes, each:
     +0x00 name[12]   +0x0C fileoff(u32, rel base 0x200)   +0x10 size(u32)
     +0x14 loadaddr(u32, RAM)   +0x18 type(u32: 3=enc code, 2=data/empty)
     +0x1C sha[32]    +0x3C iv[16]   (per-entry AES-128-CBC IV)
Verified: components are contiguous and the last ends exactly at EOF.
Decryption is NOT possible from the file alone: all code (incl. loader1) is
encrypted; the key lives in the encrypted `program`, unsealed only by the SoC
boot ROM's fused key. Reflash is additionally gated by an ECDSA directory sig.
"""
import struct, sys, math, collections

BASE, START, STRIDE = 0x200, 0x2EC, 0x5C

def entropy(b):
    if not b: return 0.0
    c = collections.Counter(b)
    return -sum((n/len(b))*math.log2(n/len(b)) for n in c.values())

def main(path):
    d = open(path, 'rb').read()
    assert d[:4] == b'UPD\0', "not a UPD container"
    model = d[12:18].split(b'\0')[0].decode()
    n = d[0x2E8]  # component count (0x28 = 40 on GH5 2.8)
    print(f"model={model}  size=0x{len(d):X}  components={n}")
    print(f"{'name':<13}{'fileoff':<12}{'size':<11}{'loadaddr':<11}{'typ':<4}{'entropy':<8}verdict")
    end = 0
    for i in range(n):
        e = d[START+i*STRIDE: START+(i+1)*STRIDE]
        name = e[:12].split(b'\0')[0].decode('latin-1')
        foff, size, load, typ = struct.unpack_from('<IIII', e, 0x0C)
        off = foff + BASE
        if size:
            h = entropy(d[off:off+min(size, 0x20000)])
            v = "plaintext" if h < 6 else ("encrypted" if h > 7.8 else "mixed")
            print(f"{name:<13}0x{off:08X} 0x{size:08X} 0x{load:08X} {typ:<3} {h:<7.2f} {v}")
            end = max(end, off+size)
        else:
            print(f"{name:<13}0x{off:08X} 0x{size:08X} 0x{load:08X} {typ:<3} {'-':<7} empty")
    print(f"last component ends at 0x{end:X} (EOF=0x{len(d):X}) -> {'OK' if end==len(d) else 'MISMATCH'}")

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'GH5__V28.bin')
