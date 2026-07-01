package crcdiff

import (
	"hash/crc32"
	"hash/crc64"
	"math"
	"math/rand"
	"strings"
	"testing"
)

// applyMask returns a copy of data with mask XOR-ed in starting at offset.
func applyMask(data []byte, offset int, mask []byte) []byte {
	out := append([]byte(nil), data...)
	for i, b := range mask {
		out[offset+i] ^= b
	}
	return out
}

func TestAnalyze32SingleBit(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	polys := map[string]uint32{"IEEE": crc32.IEEE, "Castagnoli": crc32.Castagnoli}
	for name, poly := range polys {
		tab := crc32.MakeTable(poly)
		for _, length := range []int{1, 2, 4, 5, 16, 100, 1000} {
			for trial := 0; trial < 25; trial++ {
				data := make([]byte, length)
				rng.Read(data)
				bytePos := rng.Intn(length)
				bitPos := rng.Intn(8)

				corrupt := append([]byte(nil), data...)
				corrupt[bytePos] ^= 1 << bitPos
				crc1 := crc32.Checksum(data, tab)
				crc2 := crc32.Checksum(corrupt, tab)

				f := Analyze32(poly, crc1, crc2, length)
				if f == nil {
					t.Fatalf("%s len=%d: got nil finding", name, length)
				}
				if f.BitCount() != 1 {
					t.Errorf("%s len=%d: BitCount=%d, want 1 (%s)", name, length, f.BitCount(), f)
				}
				// Positional check: the single-bit solution is unique within these lengths.
				if f.Offset != bytePos || len(f.Mask) != 1 || f.Mask[0] != 1<<bitPos {
					t.Errorf("%s len=%d: got offset=%d mask=%x, want offset=%d mask=%02x",
						name, length, f.Offset, f.Mask, bytePos, byte(1<<bitPos))
				}
				// Functional check: applying the mask reproduces crc2.
				if got := crc32.Checksum(applyMask(data, f.Offset, f.Mask), tab); got != crc2 {
					t.Errorf("%s len=%d: applying mask gives crc %#x, want %#x", name, length, got, crc2)
				}
			}
		}
	}
}

func TestAnalyze32Burst(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	var poly uint32 = crc32.IEEE
	tab := crc32.MakeTable(poly)
	const length = 256
	for trial := 0; trial < 200; trial++ {
		data := make([]byte, length)
		rng.Read(data)

		// A burst confined to a 1..4 byte span with non-zero endpoints.
		span := 1 + rng.Intn(4)
		mask := make([]byte, span)
		for {
			for i := range mask {
				// Keep the burst light so the recovered (min-weight) explanation
				// is the injected one within this length.
				mask[i] = byte(1 << rng.Intn(8))
				if rng.Intn(3) == 0 {
					mask[i] = 0
				}
			}
			mask[0] |= 1 << rng.Intn(8)
			mask[span-1] |= 1 << rng.Intn(8)
			if popcountBytes(mask) <= 4 {
				break
			}
		}
		pos := rng.Intn(length - span + 1)

		corrupt := applyMask(data, pos, mask)
		crc1 := crc32.Checksum(data, tab)
		crc2 := crc32.Checksum(corrupt, tab)

		f := Analyze32(poly, crc1, crc2, length)
		if f == nil {
			t.Fatalf("trial %d: got nil finding", trial)
		}
		// Functional check is the source of truth.
		if got := crc32.Checksum(applyMask(data, f.Offset, f.Mask), tab); got != crc2 {
			t.Errorf("trial %d: applying mask gives crc %#x, want %#x (%s)", trial, got, crc2, f)
		}
		// For these light bursts the min-weight explanation is the injected one.
		if f.Offset != pos || string(f.Mask) != string(mask) {
			t.Errorf("trial %d: got offset=%d mask=%x, want offset=%d mask=%x", trial, f.Offset, f.Mask, pos, mask)
		}
	}
}

func TestAnalyze64SingleBitAndBurst(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	polys := map[string]uint64{"ISO": crc64.ISO, "ECMA": crc64.ECMA}
	for name, poly := range polys {
		tab := crc64.MakeTable(poly)
		for _, length := range []int{1, 8, 9, 64, 500} {
			for trial := 0; trial < 25; trial++ {
				data := make([]byte, length)
				rng.Read(data)
				bytePos := rng.Intn(length)
				bitPos := rng.Intn(8)

				corrupt := append([]byte(nil), data...)
				corrupt[bytePos] ^= 1 << bitPos
				crc1 := crc64.Checksum(data, tab)
				crc2 := crc64.Checksum(corrupt, tab)

				f := Analyze64(poly, crc1, crc2, length)
				if f == nil {
					t.Fatalf("%s len=%d: got nil finding", name, length)
				}
				if f.Kind.Width != 64 {
					t.Errorf("%s: Kind.Width=%d, want 64", name, f.Kind.Width)
				}
				if f.Kind.Poly != poly {
					t.Errorf("%s: Kind.Poly=%#x, want %#x", name, f.Kind.Poly, poly)
				}
				if f.BitCount() != 1 {
					t.Errorf("%s len=%d: BitCount=%d, want 1 (%s)", name, length, f.BitCount(), f)
				}
				if f.Offset != bytePos || len(f.Mask) != 1 || f.Mask[0] != 1<<bitPos {
					t.Errorf("%s len=%d: got offset=%d mask=%x, want offset=%d mask=%02x",
						name, length, f.Offset, f.Mask, bytePos, byte(1<<bitPos))
				}
				if got := crc64.Checksum(applyMask(data, f.Offset, f.Mask), tab); got != crc2 {
					t.Errorf("%s len=%d: applying mask gives crc %#x, want %#x", name, length, got, crc2)
				}
			}
		}
	}
}

// TestAnalyzeRandomFunctional checks that even for unrelated streams the returned
// mask is a correct (if implausible) explanation of the checksum change.
func TestAnalyzeRandomFunctional(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	var poly uint32 = crc32.Castagnoli
	tab := crc32.MakeTable(poly)
	const length = 777
	for trial := 0; trial < 100; trial++ {
		a := make([]byte, length)
		b := make([]byte, length)
		rng.Read(a)
		rng.Read(b)
		crc1 := crc32.Checksum(a, tab)
		crc2 := crc32.Checksum(b, tab)
		if crc1 == crc2 {
			continue
		}
		f := Analyze32(poly, crc1, crc2, length)
		if f == nil {
			t.Fatalf("trial %d: got nil finding", trial)
		}
		if got := crc32.Checksum(applyMask(a, f.Offset, f.Mask), tab); got != crc2 {
			t.Errorf("trial %d: applying mask gives crc %#x, want %#x (%s)", trial, got, crc2, f)
		}
	}
}

func TestIdenticalAndDegenerate(t *testing.T) {
	if f := Analyze32(crc32.IEEE, 0x1234, 0x1234, 100); f != nil {
		t.Errorf("equal CRCs: got %s, want nil", f)
	}
	if f := Analyze64(crc64.ISO, 0x1234, 0x1234, 100); f != nil {
		t.Errorf("equal CRCs (64): got %s, want nil", f)
	}
	if f := Analyze32(crc32.IEEE, 0, 1, 0); f != nil {
		t.Errorf("zero length: got %s, want nil", f)
	}
}

func TestFindingMethods(t *testing.T) {
	c32 := CRCKind{Width: 32, Poly: crc32.Castagnoli}
	single := &Finding{Kind: c32, Offset: 42, Mask: []byte{0x08}, Length: 100}
	if single.BitCount() != 1 {
		t.Errorf("BitCount=%d, want 1", single.BitCount())
	}
	if !single.Plausible() {
		t.Errorf("single bit should be plausible (fp=%g)", single.FalsePositiveProbability())
	}
	if s := single.String(); !strings.Contains(s, "single bit flip") ||
		!strings.Contains(s, "offset 42") || !strings.Contains(s, "crc32/Castagnoli") {
		t.Errorf("unexpected String: %q", s)
	}

	multi := &Finding{Kind: c32, Offset: 10, Mask: []byte{0x0c, 0x80}, Length: 100}
	if multi.BitCount() != 3 {
		t.Errorf("BitCount=%d, want 3", multi.BitCount())
	}
	if s := multi.String(); !strings.Contains(s, "3 bits flipped") || !strings.Contains(s, "0c80") {
		t.Errorf("unexpected String: %q", s)
	}

	// A dense, near-full-width mask is no more distinctive than random data.
	heavy := &Finding{Kind: c32, Offset: 0, Mask: []byte{0xff, 0xff}, Length: 100}
	if heavy.Plausible() {
		t.Errorf("16 bits should be implausible (fp=%g)", heavy.FalsePositiveProbability())
	}
	if s := heavy.String(); s != "no finding" {
		t.Errorf("implausible String=%q, want %q", s, "no finding")
	}

	var nilf *Finding
	if s := nilf.String(); s != "no finding" {
		t.Errorf("nil String=%q, want %q", s, "no finding")
	}
}

func TestFalsePositiveProbability(t *testing.T) {
	// A single-bit flip in a short stream is extremely distinctive.
	single := &Finding{Kind: CRCKind{Width: 32}, Mask: []byte{0x01}, Length: 100}
	// length * (C(32,0)+C(32,1)) / 2^32 = 100 * 33 / 2^32.
	want := 100.0 * 33.0 / 4294967296.0
	if got := single.FalsePositiveProbability(); math.Abs(got-want) > want*1e-9 {
		t.Errorf("single-bit FP = %g, want %g", got, want)
	}
	if got := single.FalsePositiveProbability(); got > 1e-5 {
		t.Errorf("single-bit FP = %g, want extremely small", got)
	}

	// A full-width 4-byte mask is reproducible by chance with certainty.
	full := &Finding{Kind: CRCKind{Width: 32}, Mask: []byte{0xff, 0xff, 0xff, 0xff}, Length: 50}
	if got := full.FalsePositiveProbability(); got != 1.0 {
		t.Errorf("full-width FP = %g, want 1.0", got)
	}

	// Probability scales with stream length.
	short := &Finding{Kind: CRCKind{Width: 32}, Mask: []byte{0x01}, Length: 10}
	long := &Finding{Kind: CRCKind{Width: 32}, Mask: []byte{0x01}, Length: 100000}
	if !(short.FalsePositiveProbability() < long.FalsePositiveProbability()) {
		t.Errorf("FP should grow with length: short=%g long=%g",
			short.FalsePositiveProbability(), long.FalsePositiveProbability())
	}

	// CRC64 single bit is far more distinctive than CRC32 at the same length.
	c64 := &Finding{Kind: CRCKind{Width: 64}, Mask: []byte{0x01}, Length: 100}
	if !(c64.FalsePositiveProbability() < single.FalsePositiveProbability()) {
		t.Errorf("crc64 single-bit FP %g should be < crc32 %g",
			c64.FalsePositiveProbability(), single.FalsePositiveProbability())
	}
}

func popcountBytes(b []byte) int {
	n := 0
	for _, x := range b {
		for x != 0 {
			n += int(x & 1)
			x >>= 1
		}
	}
	return n
}
