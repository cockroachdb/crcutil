package crcdiff_test

import (
	"fmt"
	"hash/crc32"

	"github.com/cockroachdb/crcutil/crcdiff"
)

// ExampleAnalyze32 recovers a single-bit flip from the change in CRC32.
func ExampleAnalyze32() {
	data := []byte("the quick brown fox")
	tab := crc32.MakeTable(crc32.Castagnoli)
	crc1 := crc32.Checksum(data, tab)

	// Corruption flips bit 5 of byte 4.
	corrupt := append([]byte(nil), data...)
	corrupt[4] ^= 1 << 5
	crc2 := crc32.Checksum(corrupt, tab)

	f := crcdiff.Analyze32(crc32.Castagnoli, crc1, crc2, len(data))
	fmt.Println(f)
	fmt.Println("plausible:", f.Plausible())
	// Output:
	// crc32/Castagnoli: single bit flip at offset 4, bit 5, mask=0x20 (false positive probability 1 in 6850028)
	// plausible: true
}
