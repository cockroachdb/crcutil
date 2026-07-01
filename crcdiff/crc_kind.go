package crcdiff

import (
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"math/bits"
)

// CRC64NVME is the CRC-64/NVME generator polynomial in the reflected
// representation used by hash/crc64 (the reflection of the normal-form
// 0xad93d23594c93659). Unlike crc64.ISO and crc64.ECMA it is not exported by the
// standard library, so it is defined here.
const CRC64NVME = 0x9a6c9329ac4bc9b5

// CRCKind identifies a CRC algorithm by its width in bits and its generator
// polynomial, in the reflected representation used by hash/crc32 and hash/crc64
// (e.g. crc32.Castagnoli or crc64.ECMA).
type CRCKind struct {
	// Width is the CRC width in bits: 32 or 64.
	Width int
	// Poly is the generator polynomial in the reflected representation. For a
	// 32-bit CRC the value fits in the low 32 bits.
	Poly uint64
}

// String returns a short name for the CRC. Well-known polynomials are rendered
// by name (e.g. "crc32/Castagnoli", "crc64/NVME"); an unrecognized polynomial is
// rendered with both its normal and reflected hex representations.
func (k CRCKind) String() string {
	switch k.Width {
	case 32:
		switch uint32(k.Poly) {
		case crc32.IEEE:
			return "crc32/IEEE"
		case crc32.Castagnoli:
			return "crc32/Castagnoli"
		case crc32.Koopman:
			return "crc32/Koopman"
		}
		return fmt.Sprintf("crc32(normal=0x%08x, reflected=0x%08x)",
			bits.Reverse32(uint32(k.Poly)), uint32(k.Poly))
	case 64:
		switch k.Poly {
		case crc64.ISO:
			return "crc64/ISO"
		case crc64.ECMA:
			return "crc64/ECMA"
		case CRC64NVME:
			return "crc64/NVME"
		}
		return fmt.Sprintf("crc64(normal=0x%016x, reflected=0x%016x)",
			bits.Reverse64(k.Poly), k.Poly)
	default:
		return fmt.Sprintf("crc%d(reflected=0x%x)", k.Width, k.Poly)
	}
}
