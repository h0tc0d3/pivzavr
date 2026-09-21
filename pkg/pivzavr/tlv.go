package pivzavr

// encodeTLV returns the BER-encoded tag-length-value field of a PIV data
// object: the tag, the length of the value and the value itself. Lengths that
// do not fit into the short form are encoded in the long form, which is the
// encoding a PIV card expects.
func encodeTLV(tag byte, value []byte) []byte {
	field := []byte{tag}
	switch {
	case len(value) < 0x80:
		field = append(field, byte(len(value))) // #nosec G115 -- the length fits into the short form.
	case len(value) <= 0xFF:
		field = append(field, 0x81, byte(len(value))) // #nosec G115 -- the length fits into one byte.
	default:
		field = append(field, 0x82, byte(len(value)>>8), byte(len(value))) // #nosec G115 -- the length fits into two bytes.
	}
	return append(field, value...)
}

// tlvValue returns the value of the first tag-length-value field in data whose
// tag matches, which is how the values of a PIV response or of a data object
// are read. A nested field has to be unwrapped by the caller, one tag at a
// time.
func tlvValue(data []byte, tag byte) ([]byte, bool) {
	for i := 0; i+2 <= len(data); {
		length, size, ok := tlvLength(data, i+1)
		if !ok || i+1+size+length > len(data) {
			return nil, false
		}
		if data[i] == tag {
			return data[i+1+size : i+1+size+length], true
		}
		i += 1 + size + length
	}
	return nil, false
}

// tlvLength returns the length of the value of the tag-length-value field whose
// length starts at offset, together with the number of bytes the length itself
// occupies.
func tlvLength(data []byte, offset int) (length, size int, ok bool) {
	if offset >= len(data) {
		return 0, 0, false
	}

	first := int(data[offset])
	if first&0x80 == 0 {
		return first, 1, true
	}

	// Long-form BER length: the number of length bytes follows the marker.
	n := first & 0x7F
	if n == 0 || n > 3 || offset+1+n > len(data) {
		return 0, 0, false
	}
	for i := 0; i < n; i++ {
		length = length<<8 | int(data[offset+1+i])
	}
	return length, 1 + n, true
}
