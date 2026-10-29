# UPKR packer and unpacker for the BK-0010

(c) Manwe/SandS, October 2026
https://manwe.pdp-11.ru

Original UPKR: https://github.com/exoticorn/upkr

The BK-0010 packing format is equivalent to this command of the original packer:

    upkr -r -9 --big-endian-bitstream --invert-is-match-bit --invert-continue-value-bit --invert-new-offset-bit

## Files

| File | Description |
|---|---|
| `packer/upkr-bk.c` | packer source in C, no dependencies |
| `unpacker/unpack.mac` | compact slow unpacker (258 bytes) |
| `unpacker/unpack_fast.mac` | fast unpacker with tables (414 bytes) |

Ready-made packers for macOS (arm64) and Windows (64-bit) are attached to the [Releases](../../releases).

## Usage

Pack a file:

    upkr-bk-mac file.bin

The source file is expected to be a BK-0010 `.bin`: the first two words are the load address and the length.

Unpack:

    upkr-bk-mac -u file.bin.upk

Build the packer for another system (only a C compiler is needed):

    cc -O2 -o upkr-bk-system upkr-bk.c -lm

## Notes

The unpacker is single-use: it modifies its own data.

Limits for `unpack.mac`:
- the source file is at most 30 KB
- the end of the packed program is not above address 76374 (octal)

Limits for `unpack_fast.mac`:
- the source file is at most 27 KB
- the end of the packed program is not above address 71406 (octal)

## License

[Unlicense](LICENSE) (public domain), the same as the original UPKR.
