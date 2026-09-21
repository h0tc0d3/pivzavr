package embed

import (
	"bytes"
	"strconv"
	"strings"
)

// PDF whitespace and delimiters, as the PDF syntax defines them.
func pdfWhitespace(b byte) bool {
	switch b {
	case 0x00, 0x09, 0x0A, 0x0C, 0x0D, 0x20:
		return true
	}
	return false
}

func pdfDelimiter(b byte) bool {
	switch b {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return pdfWhitespace(b)
}

// pdfScanner walks the tokens of a PDF object.
type pdfScanner struct {
	data []byte
	pos  int
}

// skipSpace advances past whitespace and comments.
func (s *pdfScanner) skipSpace() {
	for s.pos < len(s.data) {
		switch {
		case pdfWhitespace(s.data[s.pos]):
			s.pos++
		case s.data[s.pos] == '%':
			for s.pos < len(s.data) && s.data[s.pos] != '\n' && s.data[s.pos] != '\r' {
				s.pos++
			}
		default:
			return
		}
	}
}

// token advances past one token and returns the range it occupies.
func (s *pdfScanner) token() (int, int, bool) {
	s.skipSpace()
	if s.pos >= len(s.data) {
		return 0, 0, false
	}
	start := s.pos
	switch s.data[s.pos] {
	case '<':
		if s.pos+1 < len(s.data) && s.data[s.pos+1] == '<' {
			s.pos += 2
		} else {
			s.skipHexString()
		}
	case '>':
		if s.pos+1 < len(s.data) && s.data[s.pos+1] == '>' {
			s.pos += 2
		} else {
			s.pos++
		}
	case '(', '[', ']', '{', '}':
		s.pos++
	case '/':
		s.skipName()
	default:
		for s.pos < len(s.data) && !pdfDelimiter(s.data[s.pos]) {
			s.pos++
		}
	}
	return start, s.pos, true
}

func (s *pdfScanner) skipName() {
	s.pos++
	for s.pos < len(s.data) && !pdfDelimiter(s.data[s.pos]) {
		s.pos++
	}
}

func (s *pdfScanner) skipHexString() {
	s.pos++
	for s.pos < len(s.data) && s.data[s.pos] != '>' {
		s.pos++
	}
	if s.pos < len(s.data) {
		s.pos++
	}
}

func (s *pdfScanner) skipLiteralString() {
	s.pos++
	depth := 1
	for s.pos < len(s.data) && depth > 0 {
		switch s.data[s.pos] {
		case '\\':
			s.pos += 2
			continue
		case '(':
			depth++
		case ')':
			depth--
		}
		s.pos++
	}
}

// skipValue advances past one object value: a dictionary, an array, a string, a
// name, a number, a keyword or a reference.
func (s *pdfScanner) skipValue() bool {
	s.skipSpace()
	if s.pos >= len(s.data) {
		return false
	}
	switch s.data[s.pos] {
	case '<':
		if s.pos+1 < len(s.data) && s.data[s.pos+1] == '<' {
			s.skipDict()
		} else {
			s.skipHexString()
		}
		return true
	case '(':
		s.skipLiteralString()
		return true
	case '[':
		s.skipArray()
		return true
	case '/':
		s.skipName()
		return true
	}

	start, end, ok := s.token()
	if !ok {
		return false
	}
	if !isPDFInteger(s.data[start:end]) {
		return true
	}
	// A reference is two integers followed by the R keyword.
	restore := s.pos
	start, end, ok = s.token()
	if !ok || !isPDFInteger(s.data[start:end]) {
		s.pos = restore
		return true
	}
	start, end, ok = s.token()
	if !ok || !bytes.Equal(s.data[start:end], []byte("R")) {
		s.pos = restore
	}
	return true
}

func (s *pdfScanner) skipArray() {
	s.pos++
	for {
		s.skipSpace()
		if s.pos >= len(s.data) {
			return
		}
		if s.data[s.pos] == ']' {
			s.pos++
			return
		}
		if !s.skipValue() {
			return
		}
	}
}

func (s *pdfScanner) skipDict() {
	s.pos += 2
	for {
		s.skipSpace()
		if s.pos >= len(s.data) {
			return
		}
		if s.pos+1 < len(s.data) && s.data[s.pos] == '>' && s.data[s.pos+1] == '>' {
			s.pos += 2
			return
		}
		if s.data[s.pos] != '/' {
			s.pos++
			continue
		}
		s.skipName()
		if !s.skipValue() {
			return
		}
	}
}

// isPDFInteger reports whether a token is an integer.
func isPDFInteger(token []byte) bool {
	if len(token) == 0 {
		return false
	}
	digits := 0
	for i, b := range token {
		switch {
		case b >= '0' && b <= '9':
			digits++
		case (b == '+' || b == '-') && i == 0:
		default:
			return false
		}
	}
	return digits > 0
}

// pdfIntOf returns the integer a token holds, or 0 when it holds none.
func pdfIntOf(token []byte) int {
	value, err := strconv.Atoi(strings.TrimSpace(string(token)))
	if err != nil {
		return 0
	}
	return value
}

// pdfKeyName returns the name of a dictionary key without its leading slash, so
// that callers may write a key either way.
func pdfKeyName(key string) string {
	return strings.TrimPrefix(key, "/")
}

// pdfDictOf returns the dictionary that an object body holds, or false when the
// body does not start with one.
func pdfDictOf(body []byte) ([]byte, bool) {
	s := &pdfScanner{data: body}
	s.skipSpace()
	if s.pos+1 >= len(s.data) || s.data[s.pos] != '<' || s.data[s.pos+1] != '<' {
		return nil, false
	}
	start := s.pos
	s.skipDict()
	if s.pos <= start+2 {
		return nil, false
	}
	return s.data[start:s.pos], true
}

// pdfDictValue returns the raw bytes of the value of a dictionary key. The
// value is returned as it is written, so that it can be written back unchanged.
func pdfDictValue(dict []byte, key string) ([]byte, bool) {
	s := &pdfScanner{data: dict}
	s.skipSpace()
	if s.pos+1 >= len(s.data) || s.data[s.pos] != '<' || s.data[s.pos+1] != '<' {
		return nil, false
	}
	s.pos += 2

	for {
		s.skipSpace()
		if s.pos >= len(s.data) {
			return nil, false
		}
		if s.pos+1 < len(s.data) && s.data[s.pos] == '>' && s.data[s.pos+1] == '>' {
			return nil, false
		}
		if s.data[s.pos] != '/' {
			s.pos++
			continue
		}

		nameStart := s.pos + 1
		s.skipName()
		name := s.data[nameStart:s.pos]
		s.skipSpace()
		valueStart := s.pos
		if !s.skipValue() {
			return nil, false
		}
		if string(name) == pdfKeyName(key) {
			return s.data[valueStart:s.pos], true
		}
	}
}

// pdfDictInsert returns a dictionary with a key added, or with the value of the
// key replaced when it already holds one. The value is written as it is given.
func pdfDictInsert(dict []byte, key, value string) []byte {
	key = "/" + pdfKeyName(key)
	if _, ok := pdfDictValue(dict, key); ok {
		dict = pdfDictRemove(dict, key)
	}
	end := bytes.LastIndex(dict, []byte(">>"))
	if end < 0 {
		return dict
	}
	var out bytes.Buffer
	out.Write(dict[:end])
	if !bytes.HasSuffix(bytes.TrimRight(dict[:end], " \t\r\n"), []byte("<")) {
		out.WriteString(" ")
	}
	out.WriteString(key)
	out.WriteString(" ")
	out.WriteString(value)
	out.WriteString(" ")
	out.Write(dict[end:])
	return out.Bytes()
}

// pdfDictRemove returns a dictionary without a key.
func pdfDictRemove(dict []byte, key string) []byte {
	s := &pdfScanner{data: dict}
	s.skipSpace()
	if s.pos+1 >= len(s.data) || s.data[s.pos] != '<' || s.data[s.pos+1] != '<' {
		return dict
	}
	body := s.pos + 2

	var out bytes.Buffer
	out.Write(dict[:body])
	for {
		s.skipSpace()
		if s.pos >= len(s.data) {
			break
		}
		if s.pos+1 < len(s.data) && s.data[s.pos] == '>' && s.data[s.pos+1] == '>' {
			break
		}
		entryStart := s.pos
		if s.data[s.pos] != '/' {
			s.pos++
			continue
		}
		nameStart := s.pos + 1
		s.skipName()
		name := s.data[nameStart:s.pos]
		s.skipSpace()
		if !s.skipValue() {
			break
		}
		if string(name) == pdfKeyName(key) {
			out.Write(dict[body:entryStart])
			body = s.pos
		}
	}
	out.Write(dict[body:])
	return out.Bytes()
}

// pdfReference returns the raw reference of a dictionary value, such as
// "12 0 R", if it holds one.
func pdfReference(value []byte) (string, bool) {
	fields := strings.Fields(string(value))
	if len(fields) != 3 || fields[2] != "R" {
		return "", false
	}
	if !isPDFInteger([]byte(fields[0])) || !isPDFInteger([]byte(fields[1])) {
		return "", false
	}
	return strings.Join(fields, " "), true
}
