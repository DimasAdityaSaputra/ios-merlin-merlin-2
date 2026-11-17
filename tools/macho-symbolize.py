#!/usr/bin/env python3
"""Resolve kernel panic addresses against a DEVELOPMENT kernel Mach-O.

Usage: macho-symbolize.py KERNEL_BIN ADDR [ADDR ...]

Addresses may be printed as 0xfffffe... (absolute kernel VA, the panic
screen format) or as bare offsets from the link base. The DEVELOPMENT
kernel keeps its symbol table (LINKEDIT), so LC_SYMTAB is enough; only
defined text symbols are considered.
"""
import struct
import sys


def load(path):
    data = open(path, "rb").read()
    if data[:4] != b"\xcf\xfa\xed\xfe":
        raise SystemExit("%s: not a little-endian 64-bit Mach-O" % path)
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    segs = []
    symtab = None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            name = data[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        elif cmd == 0x2:  # LC_SYMTAB
            symtab = struct.unpack_from("<IIII", data, off + 8)
        off += size
    if symtab is None:
        raise SystemExit("no LC_SYMTAB: this kernel has no symbols")
    symoff, nsyms, stroff, strsize = symtab
    strs = data[stroff:stroff + strsize]
    syms = []
    for i in range(nsyms):
        strx, ntype, sect, desc, value = struct.unpack_from("<IBBHQ", data, symoff + 16 * i)
        if ntype & 0x0e != 0x0e:  # N_SECT only
            continue
        if value == 0:
            continue
        end = strs.find(b"\0", strx)
        name = strs[strx:end].decode("ascii", "replace")
        if name:
            syms.append((value, name))
    syms.sort()
    return data, syms, segs


def resolve(syms, addr):
    lo, hi = 0, len(syms) - 1
    if not syms or addr < syms[0][0]:
        return None, 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if syms[mid][0] <= addr:
            lo = mid
        else:
            hi = mid - 1
    return syms[lo][1], addr - syms[lo][0]


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    data, syms, segs = load(argv[1])
    for s in segs:
        if s[0] in ("__TEXT", "__TEXT_EXEC"):
            print("# %s vmaddr 0x%x" % (s[0], s[1]))
    for a in argv[2:]:
        addr = int(a, 16)
        name, delta = resolve(syms, addr)
        if name is None:
            print("0x%x  ?? (below the first symbol)" % addr)
        else:
            print("0x%x  %s + 0x%x" % (addr, name, delta))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
