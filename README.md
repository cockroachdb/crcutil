# crcutil

Utilities for working with CRC checksums.

Given two CRC values computed over two byte streams of the **same length** with
the same polynomial, `crcutil` traces the difference between the checksums back
to the simplest data change that explains it: ideally a single flipped bit, or a
short burst of flipped bits confined to a few consecutive bytes. This is the
classic signature of a single-bit storage or transmission error, so the number
of flipped bits is a strong signal for whether a checksum mismatch is genuine
localized corruption rather than an unrelated change.

## How it works

CRC is linear over GF(2), so for equal-length streams the init and final-xor
constants cancel in `crc1 ^ crc2`, leaving the zero-init/zero-final CRC of the
per-byte XOR difference of the two streams. `crcutil` reverses that CRC one byte
at a time (using a reverse lookup table) to slide a window across every possible
alignment, and picks the alignment whose window has the fewest set bits. The
result is a mask of bytes which, XOR-ed into the first stream at a given offset,
turns its checksum into the second one.

Each finding comes with a false-positive probability: the chance that two
unrelated CRCs would, by chance, yield a finding at least this simple. A value
near 0 means the finding is highly distinctive (a real single-bit flip in a
short stream); a value near 1 means it is no better than what random data would
produce.

## Packages

- [`crcdiff`](crcdiff/) — the CRC-diff analysis library. Supports both CRC32
  (`hash/crc32`) and CRC64 (`hash/crc64`) with configurable polynomials.
- [`cmd/crcdiff`](cmd/crcdiff/) — a command-line tool wrapping the library.

## Library usage

```go
import "github.com/cockroachdb/crcutil/crcdiff"

f := crcdiff.Analyze32(crc32.Castagnoli, crc1, crc2, length)
if f.Plausible() {
    fmt.Println(f) // e.g. "crc32/Castagnoli: single bit flip at ..."
}
```

`Analyze32` and `Analyze64` return a `*Finding` describing the mask, its byte
offset, the number of flipped bits (`Finding.BitCount`), and the false-positive
probability (`Finding.FalsePositiveProbability`). `Finding.Plausible` applies a
default threshold; use `FalsePositiveProbability` directly for a custom rule.

## Command-line tool

```
go install github.com/cockroachdb/crcutil/cmd/crcdiff@latest
crcdiff [-length N] [-crc32 IEEE|C] [-crc64 ISO|ECMA|NVME] <crc1> <crc2>
```

or directly:

```
go run github.com/cockroachdb/crcutil/cmd/crcdiff@latest \
  [-length N] [-crc32 IEEE|C] [-crc64 ISO|ECMA|NVME] <crc1> <crc2>
```

The two CRCs are hex values with either 8 digits (CRC32) or 16 digits (CRC64); a
`0x` prefix is optional. The width selects the default polynomial — CRC32C
(Castagnoli) for 8-digit CRCs, CRC64/NVME for 16-digit CRCs — which the
`-crc32`/`-crc64` flags override.

If `-length` is omitted, the stream length is unknown: the tool searches up to
512 KiB (CRC32) or 1 GiB (CRC64) and reports the offset relative to the end of
the stream. Passing `-length` yields an accurate false-positive probability
(which grows with length).

### Examples

```
$ crcdiff -length 1000 dd2edff7 b1b11dc1
crc32/Castagnoli: single bit flip at offset 123, bit 4, mask=0x10 (false positive probability 1 in 130151)

$ crcdiff -length 1000 387e868bd14debed 474f78c3e9de5763
crc64/NVME: single bit flip at offset 900, bit 2, mask=0x04 (false positive probability 1 in 283796062672455)

$ crcdiff -length 1000 -crc64 ECMA f033761aeb8e0b26 b25908d6d19f996b
crc64/ECMA: 3 bits flipped across 2 byte(s) at offset 10, mask=0x0580 (false positive probability 1 in 421688057463)
```
