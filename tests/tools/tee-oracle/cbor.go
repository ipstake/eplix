package main

import "encoding/binary"

// A small CBOR writer (RFC 8949). The Nitro cases need encodings a CBOR library will not
// produce: indefinite lengths, duplicate keys, text where bytes belong, stray tags.

func cHead(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n <= 0xff:
		return []byte{m | 24, byte(n)}
	case n <= 0xffff:
		return binary.BigEndian.AppendUint16([]byte{m | 25}, uint16(n))
	case n <= 0xffffffff:
		return binary.BigEndian.AppendUint32([]byte{m | 26}, uint32(n))
	default:
		return binary.BigEndian.AppendUint64([]byte{m | 27}, n)
	}
}

func cUint(n uint64) []byte { return cHead(0, n) }

// cNeg encodes the negative integer n (n < 0).
func cNeg(n int64) []byte { return cHead(1, uint64(-1-n)) }

func cBytes(b []byte) []byte { return append(cHead(2, uint64(len(b))), b...) }

func cText(s string) []byte { return append(cHead(3, uint64(len(s))), s...) }

func cTag(t uint64, item []byte) []byte { return append(cHead(6, t), item...) }

var cNull = []byte{0xf6}

func cArray(items ...[]byte) []byte {
	out := cHead(4, uint64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

func cArrayIndef(items ...[]byte) []byte {
	out := []byte{0x9f}
	for _, it := range items {
		out = append(out, it...)
	}
	return append(out, 0xff)
}

// cBytesIndef is a byte string in chunks of indefinite length.
func cBytesIndef(chunks ...[]byte) []byte {
	out := []byte{0x5f}
	for _, c := range chunks {
		out = append(out, cBytes(c)...)
	}
	return append(out, 0xff)
}

// entry is one map member, key and value already encoded.
type entry struct{ k, v []byte }

func cMap(es []entry) []byte {
	out := cHead(5, uint64(len(es)))
	for _, e := range es {
		out = append(append(out, e.k...), e.v...)
	}
	return out
}

func cMapIndef(es []entry) []byte {
	out := []byte{0xbf}
	for _, e := range es {
		out = append(append(out, e.k...), e.v...)
	}
	return append(out, 0xff)
}
