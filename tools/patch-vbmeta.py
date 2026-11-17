#!/usr/bin/env python3
"""Inspect / patch a Xiaomi vbmeta image for booting unsigned images.

Xiaomi's MTK LK does not honour the standard AVB flag bits; the October kit's
`patch-vbmeta.py` instead sets the two bits at byte offset 123 of the vbmeta
header, which is what made every unsigned merlin boot image boot (NOTES.md,
2026-11-07 "ROOT CAUSE FOUND (v5 loop...)"). The upstream vbmeta-header
`flags` field is a big-endian u32 at offset 120, so byte 123 carries bits
24/25 = Xiaomi's "hashtree disabled" / "verification disabled".

Usage:
  patch-vbmeta.py --inspect IMAGE           # print header facts, no writes
  patch-vbmeta.py IMAGE OUT                 # write OUT = IMAGE with byte 123 |= 0x03
  patch-vbmeta.py IMAGE OUT --clear         # ... with byte 123 &= ~0x03 (to restore)
"""
import sys

MAGIC = b"AVB0"
XIAOMI_FLAG_OFFSET = 123
XIAOMI_FLAG_MASK = 0x03


def read_header(b):
    if len(b) < 256 or b[:4] != MAGIC:
        raise SystemExit("not an AVB vbmeta image (magic %r)" % b[:4])
    return {
        "version_major_bytes": b[4:8].hex(" "),
        "version_minor_bytes": b[8:12].hex(" "),
        "flags_bytes": b[120:124].hex(" "),
        "flag_byte_123": b[XIAOMI_FLAG_OFFSET],
        "rollback_bytes": b[112:120].hex(" "),
        # free text some hand-built images carry after the header
        "label": b[124:140].split(b"\0")[0].decode("ascii", "replace"),
    }


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    if not args:
        raise SystemExit(__doc__)
    data = bytearray(open(args[0], "rb").read())
    info = read_header(data)
    print("vbmeta: %s" % args[0])
    for k, v in info.items():
        print("  %-20s %s" % (k, v))
    enabled = (info["flag_byte_123"] & XIAOMI_FLAG_MASK) == XIAOMI_FLAG_MASK
    print("  xiaomi disable bits  %s" % ("SET (unsigned images may boot)" if enabled
                                         else "CLEAR (LK will reject unsigned images)"))
    if "--inspect" in argv or len(args) < 2:
        return 0
    if "--clear" in argv:
        data[XIAOMI_FLAG_OFFSET] &= ~XIAOMI_FLAG_MASK & 0xff
    else:
        data[XIAOMI_FLAG_OFFSET] |= XIAOMI_FLAG_MASK
    open(args[1], "wb").write(bytes(data))
    print("wrote %s (byte %d = 0x%02x)" % (args[1], XIAOMI_FLAG_OFFSET,
                                           data[XIAOMI_FLAG_OFFSET]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
