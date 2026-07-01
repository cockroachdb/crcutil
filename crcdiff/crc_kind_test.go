package crcdiff

import (
	"hash/crc32"
	"hash/crc64"
	"testing"
)

func TestCRCKindString(t *testing.T) {
	for _, tc := range []struct {
		kind CRCKind
		want string
	}{
		// Well-known polynomials render by name.
		{CRCKind{Width: 32, Poly: crc32.IEEE}, "crc32/IEEE"},
		{CRCKind{Width: 32, Poly: crc32.Castagnoli}, "crc32/Castagnoli"},
		{CRCKind{Width: 32, Poly: crc32.Koopman}, "crc32/Koopman"},
		{CRCKind{Width: 64, Poly: crc64.ISO}, "crc64/ISO"},
		{CRCKind{Width: 64, Poly: crc64.ECMA}, "crc64/ECMA"},
		{CRCKind{Width: 64, Poly: CRC64NVME}, "crc64/NVME"},

		// Unknown polynomials render with both normal and reflected forms. The
		// reflected poly 0x1 bit-reverses to the top bit of the normal form.
		{CRCKind{Width: 32, Poly: 0x1}, "crc32(normal=0x80000000, reflected=0x00000001)"},
		{CRCKind{Width: 64, Poly: 0x1}, "crc64(normal=0x8000000000000000, reflected=0x0000000000000001)"},

		// An unknown reflected CRC32 poly (arbitrary value).
		{CRCKind{Width: 32, Poly: 0x82f63b79}, "crc32(normal=0x9edc6f41, reflected=0x82f63b79)"},

		// A width the package doesn't otherwise produce falls back to the reflected
		// form only.
		{CRCKind{Width: 16, Poly: 0x8005}, "crc16(reflected=0x8005)"},
	} {
		if got := tc.kind.String(); got != tc.want {
			t.Errorf("CRCKind{Width: %d, Poly: %#x}.String() = %q, want %q",
				tc.kind.Width, tc.kind.Poly, got, tc.want)
		}
	}
}
