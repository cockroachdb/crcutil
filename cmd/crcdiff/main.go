// Command crcdiff traces the difference between two CRC checksums back to the
// simplest data change that explains it (a single bit flip or a short burst),
// using the crcdiff package.
//
// Usage:
//
//	crcdiff [-length N] [-crc32 IEEE|C] [-crc64 ISO|ECMA|NVME] <crc1> <crc2>
//
// The two CRCs are hex values with either 8 digits (CRC32) or 16 digits
// (CRC64); a 0x prefix is optional. The CRC width selects the default
// polynomial: CRC32C (Castagnoli) for 8-digit CRCs, CRC64/NVME for 16-digit
// CRCs. The -crc32/-crc64 flags override the polynomial.
//
// If -length is omitted, the stream length is unknown: the tool searches up to
// 512KiB (CRC32) or 1GiB (CRC64) and reports the offset relative to the end of
// the stream.
package main

import (
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/cockroachdb/crcutil/crcdiff"
)

const (
	maxLen32 = 512 * 1024         // 512 KiB
	maxLen64 = 1024 * 1024 * 1024 // 1 GiB
)

func main() {
	err := run(os.Args[1:], os.Stdout, os.Stderr)
	switch {
	case err == nil:
	case errors.Is(err, flag.ErrHelp):
		// Usage was already printed by the flag package.
		os.Exit(0)
	default:
		fmt.Fprintln(os.Stderr, "crcdiff:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("crcdiff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	length := fs.Int("length", 0,
		"stream length in bytes; if omitted, search up to 512KiB (CRC32) or 1GiB (CRC64)\nand report the offset relative to the end of the stream")
	crc32Poly := fs.String("crc32", "", "CRC32 polynomial: IEEE or C (default C / Castagnoli)")
	crc64Poly := fs.String("crc64", "", "CRC64 polynomial: ISO, ECMA, or NVME (default NVME)")
	fs.Usage = func() { usage(stderr, fs) }
	if err := fs.Parse(args); err != nil {
		return err
	}

	lengthSet := false
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name == "length" {
			lengthSet = true
		}
	})
	if lengthSet && *length <= 0 {
		return fmt.Errorf("-length must be positive")
	}

	if *crc32Poly != "" && *crc64Poly != "" {
		return fmt.Errorf("cannot specify both -crc32 and -crc64")
	}

	crcArgs := fs.Args()
	if len(crcArgs) != 2 {
		return fmt.Errorf("expected two CRC values, got %d (run with -h for usage)", len(crcArgs))
	}

	v1, w1, err := parseCRC(crcArgs[0])
	if err != nil {
		return err
	}
	v2, w2, err := parseCRC(crcArgs[1])
	if err != nil {
		return err
	}
	if w1 != w2 {
		return fmt.Errorf("the two CRCs have different widths (%d-bit vs %d-bit)", w1, w2)
	}
	width := w1

	if v1 == v2 {
		fmt.Fprintln(stdout, "the two CRCs are identical: no difference")
		return nil
	}

	// Determine the analysis length. When unset, offsets are end-relative.
	analysisLen := *length
	relativeToEnd := !lengthSet
	if relativeToEnd {
		if width == 32 {
			analysisLen = maxLen32
		} else {
			analysisLen = maxLen64
		}
	}

	var f *crcdiff.Finding
	switch width {
	case 32:
		if *crc64Poly != "" {
			return fmt.Errorf("-crc64 cannot be used with 32-bit CRCs")
		}
		poly := uint32(crc32.Castagnoli)
		if *crc32Poly != "" {
			if poly, err = poly32(*crc32Poly); err != nil {
				return err
			}
		}
		f = crcdiff.Analyze32(poly, uint32(v1), uint32(v2), analysisLen)
	case 64:
		if *crc32Poly != "" {
			return fmt.Errorf("-crc32 cannot be used with 64-bit CRCs")
		}
		poly := uint64(crcdiff.CRC64NVME)
		if *crc64Poly != "" {
			if poly, err = poly64(*crc64Poly); err != nil {
				return err
			}
		}
		f = crcdiff.Analyze64(poly, v1, v2, analysisLen)
	}

	printResult(stdout, stderr, f, relativeToEnd, analysisLen)
	return nil
}

// parseCRC parses a hex CRC value, returning its value and width in bits (32 or
// 64). A 0x prefix is optional; the value must have exactly 8 or 16 hex digits.
func parseCRC(s string) (val uint64, widthBits int, err error) {
	h := s
	if strings.HasPrefix(h, "0x") || strings.HasPrefix(h, "0X") {
		h = h[2:]
	}
	switch len(h) {
	case 8:
		widthBits = 32
	case 16:
		widthBits = 64
	default:
		return 0, 0, fmt.Errorf("CRC %q must have 8 or 16 hex digits (got %d)", s, len(h))
	}
	val, err = strconv.ParseUint(h, 16, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid hex CRC %q: %v", s, err)
	}
	return val, widthBits, nil
}

func poly32(name string) (uint32, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "IEEE":
		return crc32.IEEE, nil
	case "C", "CASTAGNOLI":
		return crc32.Castagnoli, nil
	default:
		return 0, fmt.Errorf("unknown crc32 polynomial %q (want IEEE or C)", name)
	}
}

func poly64(name string) (uint64, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "ISO":
		return crc64.ISO, nil
	case "ECMA":
		return crc64.ECMA, nil
	case "NVME":
		return crcdiff.CRC64NVME, nil
	default:
		return 0, fmt.Errorf("unknown crc64 polynomial %q (want ISO, ECMA, or NVME)", name)
	}
}

func printResult(stdout, stderr io.Writer, f *crcdiff.Finding, relativeToEnd bool, analysisLen int) {
	if relativeToEnd {
		// The false-positive probability scales with the stream length, so an
		// assumed maximum length only yields a conservative upper bound. Warn so
		// the user knows to pass -length for an accurate result.
		fmt.Fprintf(stderr,
			"warning: -length not specified; pass it for an accurate false-positive probability "+
				"(the probability grows with length). Searched up to %d bytes; "+
				"offsets are relative to the end of the stream.\n",
			analysisLen)
	}
	if f == nil || !f.Plausible() {
		fmt.Fprintln(stdout, "no plausible finding")
		return
	}
	if !relativeToEnd {
		fmt.Fprintln(stdout, f)
		return
	}
	// The length is unknown, so absolute offsets (which assume the maximum
	// search length) are meaningless. Re-express the offset as a negative
	// distance from the end of the stream.
	rel := *f
	rel.Offset = f.Offset - analysisLen
	fmt.Fprintln(stdout, &rel)
}

func usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, `Usage: crcdiff [-length N] [-crc32 IEEE|C] [-crc64 ISO|ECMA|NVME] <crc1> <crc2>

Traces the difference between two CRC checksums back to the simplest data change
(a single bit flip or short burst). CRCs are hex, 8 digits (CRC32) or 16 digits
(CRC64); a 0x prefix is optional.

By default CRC32C (Castagnoli) or CRC64/NVME is assumed based on the CRC width.

Flags:
`)
	fs.PrintDefaults()
}
