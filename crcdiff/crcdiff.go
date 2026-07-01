// Package crcdiff traces the difference between two CRC checksums back to the
// simplest data change that explains it: ideally a single flipped bit, or a
// short burst of flipped bits confined to a few consecutive bytes.
//
// Given two CRC values computed over two byte streams of the *same* length with
// the same polynomial (as hash/crc32 and hash/crc64 produce), Analyze32 and
// Analyze64 return a Finding describing a mask of bytes which, XOR-ed into the
// first stream at a given offset, turns its checksum into the second one. This
// is the classic signature of a single-bit transmission/storage error, so the
// number of flipped bits (Finding.BitCount) is a strong plausibility signal.
//
// How it works: CRC is linear over GF(2), so for equal-length streams the init
// and final-xor constants cancel in crc1^crc2, leaving the zero-init/zero-final
// CRC of the per-byte XOR-difference of the two streams. We reverse that CRC one
// byte at a time (using a reverse lookup table) to slide a width-byte window
// across every possible alignment, and pick the alignment whose window has the
// fewest set bits.
package crcdiff

import (
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"math"
	"math/bits"
)

// DefaultMaxFalsePositive is the threshold used by Finding.Plausible: a finding
// is considered plausible when its FalsePositiveProbability is at or below this
// value. Callers wanting a different rule should use FalsePositiveProbability
// directly.
const DefaultMaxFalsePositive = 0.01

// Finding describes the simplest data difference that turns crc1 into crc2: XOR
// Mask into the (first) stream starting at byte Offset and its checksum becomes
// crc2.
type Finding struct {
	// Length is the stream length (in bytes) the finding was computed for, used
	// by FalsePositiveProbability. It is set by Analyze32/Analyze64.
	Length int
	// Kind identifies the CRC (width and polynomial) the finding was computed
	// for. It is set by Analyze32/Analyze64.
	Kind CRCKind
	// Offset is the byte offset in the stream where Mask applies.
	Offset int
	// Mask holds the bytes to XOR into the stream at Offset. Its length is
	// between 1 and Kind.Width/8, with both the first and last byte non-zero.
	Mask []byte
}

// BitCount returns the number of flipped bits, i.e. the population count of
// Mask.
func (f *Finding) BitCount() int {
	n := 0
	for _, b := range f.Mask {
		n += bits.OnesCount8(b)
	}
	return n
}

// FalsePositiveProbability estimates the probability that the difference between
// two unrelated CRCs (i.e. random data, not a genuine localized corruption)
// would, by chance, yield a finding at least as simple as this one.
//
// The search examines roughly Length alignments; at each, a random CRC produces
// a uniformly distributed width-bit window. The probability that one such window
// has at most BitCount set bits is S/2^width, where S is the number of width-bit
// values with population count <= BitCount. Union-bounding over the alignments
// gives Length*S/2^width, capped at 1.
//
// A value near 0 means the finding is highly distinctive (a real single-bit flip
// in a short stream); a value near 1 means it is no better than what random data
// would produce (e.g. a dense, full-width mask).
func (f *Finding) FalsePositiveProbability() float64 {
	width := f.Kind.Width
	count := 0.0
	for i := 0; i <= f.BitCount(); i++ {
		count += binom(width, i)
	}
	p := float64(f.Length) * count / math.Exp2(float64(width))
	return math.Min(1, p)
}

// Plausible reports whether the finding looks like genuine localized corruption,
// i.e. its FalsePositiveProbability is at or below DefaultMaxFalsePositive.
// Callers wanting a different rule should use FalsePositiveProbability directly.
func (f *Finding) Plausible() bool {
	return f.FalsePositiveProbability() <= DefaultMaxFalsePositive
}

// String returns a human-readable explanation of the finding. It returns "no
// finding" for a nil finding or one that is not Plausible.
func (f *Finding) String() string {
	if f == nil || f.Length == 0 || !f.Plausible() {
		return "no finding"
	}
	var prob string
	if fpr := f.FalsePositiveProbability(); fpr >= 0.01 {
		prob = fmt.Sprintf("%.2f%%", fpr)
	} else {
		prob = fmt.Sprintf("1 in %.0f", 1/fpr)
	}
	var desc string
	if bc := f.BitCount(); bc == 1 {
		// Mask is trimmed, so the single set bit is in Mask[0].
		bit := bits.TrailingZeros8(f.Mask[0])
		desc = fmt.Sprintf("%s: single bit flip at offset %d, bit %d, mask=0x%x",
			f.Kind, f.Offset, bit, f.Mask)
	} else {
		desc = fmt.Sprintf("%s: %d bits flipped across %d byte(s) at offset %d, mask=0x%x",
			f.Kind, bc, len(f.Mask), f.Offset, f.Mask)
	}
	return fmt.Sprintf("%s (false positive probability %s)", desc, prob)
}

// binom returns the binomial coefficient C(n, k) as a float64. float64 is used
// because the values (and their sums) can exceed 2^64 for CRCWidth==64.
func binom(n, k int) float64 {
	if k < 0 || k > n {
		return 0
	}
	if k > n-k {
		k = n - k
	}
	r := 1.0
	for i := 0; i < k; i++ {
		r = r * float64(n-i) / float64(i+1)
	}
	return r
}

// Analyze32 finds the simplest difference (fewest flipped bits) explaining the
// change from crc1 to crc2 for two streams of the given length in bytes. poly is
// the CRC32 polynomial in the same (reversed) representation used by hash/crc32,
// e.g. crc32.IEEE or crc32.Castagnoli.
//
// It returns nil if crc1 == crc2 (no difference), or if length is too small for
// any in-range explanation. The returned Mask has length 1..4.
func Analyze32(poly uint32, crc1, crc2 uint32, length int) *Finding {
	tab := ([256]uint32)(*crc32.MakeTable(poly))
	return analyze(&tab, 4, uint64(poly), crc1^crc2, length)
}

// Analyze64 is the CRC64 analogue of Analyze32. poly is a CRC64 polynomial in
// the representation used by hash/crc64, e.g. crc64.ISO or crc64.ECMA. The
// returned Mask has length 1..8.
func Analyze64(poly uint64, crc1, crc2 uint64, length int) *Finding {
	tab := ([256]uint64)(*crc64.MakeTable(poly))
	return analyze(&tab, 8, poly, crc1^crc2, length)
}

// word is the set of CRC register types supported by the generic core.
type word interface {
	~uint32 | ~uint64
}

// analyze implements the search described in the package doc. tab is the CRC
// table (tab[i] is the CRC of the single byte i), width is the CRC width in
// bytes, poly is the generator polynomial (reflected representation, recorded in
// the Finding's Kind), t is crc1^crc2, and length is the stream length in bytes.
func analyze[T word](tab *[256]T, width int, poly uint64, t T, length int) *Finding {
	if t == 0 || length < 1 {
		return nil
	}
	topShift := (width - 1) * 8

	// rev inverts the top byte of the table: rev[tab[i]>>topShift] == i. For a
	// valid CRC polynomial the top bytes of the table entries are a permutation
	// of 0..255, which makes a zero-byte CRC step invertible.
	var rev [256]uint8
	for i := 0; i < 256; i++ {
		rev[tab[i]>>topShift] = uint8(i)
	}

	// revStep undoes one zero data byte: it is the inverse of the linear map
	// s -> (s>>8) ^ tab[s&0xff].
	revStep := func(s T) T {
		i := rev[s>>topShift]
		return ((s ^ tab[i]) << 8) | T(i)
	}

	// w is the width-byte window value whose zero-init CRC equals the state
	// reached after the first (length-k) bytes of the difference stream (with
	// the remaining k bytes assumed zero). Applying revStep width times to t
	// yields that window directly (see package doc); each further revStep slides
	// the window one byte toward the start of the stream.
	//
	// For alignment k the window occupies stream bytes [length-k-width,
	// length-k); byte j of the window (j==0 is earliest) is at position
	// length-k-width+j and equals (w >> (8*j)) & 0xff.
	w := t
	for i := 0; i < width; i++ {
		w = revStep(w)
	}

	// Scan every alignment, tracking the simplest window (fewest set bits, then
	// shortest byte span, then smallest offset) with scalars only, so the hot
	// loop allocates nothing even when scanning hundreds of millions of bytes.
	var bestW T
	bestBits, bestSpan, bestOffset := 0, 0, 0
	found := false
	for k := 0; k <= length-1; k++ {
		if w != 0 {
			// lo/hi are the lowest/highest non-zero byte indices within the
			// width-byte window.
			lo := bits.TrailingZeros64(uint64(w)) / 8
			hi := (bits.Len64(uint64(w)) - 1) / 8
			offset := length - k - width + lo
			if offset >= 0 { // window does not extend before the stream
				bc := bits.OnesCount64(uint64(w))
				span := hi - lo + 1
				if !found || simpler(bc, span, offset, bestBits, bestSpan, bestOffset) {
					found = true
					bestW, bestBits, bestSpan, bestOffset = w, bc, span, offset
					if bc == 1 {
						// A single flipped bit is the optimal explanation.
						break
					}
				}
			}
		}
		w = revStep(w)
	}
	if !found {
		return nil
	}

	lo := bits.TrailingZeros64(uint64(bestW)) / 8
	hi := (bits.Len64(uint64(bestW)) - 1) / 8
	mask := make([]byte, hi-lo+1)
	for j := lo; j <= hi; j++ {
		mask[j-lo] = byte(bestW >> (8 * j))
	}
	return &Finding{
		Length: length,
		Kind:   CRCKind{Width: width * 8, Poly: poly},
		Offset: bestOffset,
		Mask:   mask,
	}
}

// simpler reports whether a candidate window (bc set bits, span bytes wide, at
// the given offset) is a simpler explanation than the current best: fewer
// flipped bits, then a shorter byte span, then a smaller offset.
func simpler(bc, span, offset, bestBits, bestSpan, bestOffset int) bool {
	if bc != bestBits {
		return bc < bestBits
	}
	if span != bestSpan {
		return span < bestSpan
	}
	return offset < bestOffset
}
