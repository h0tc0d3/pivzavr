//go:build !windows

package pcsc

// readerNames returns the names of the readers that are held in the
// NUL-terminated multi-string a reader list call returned. The smart card
// service of the Unix systems reports a reader name as a byte string.
func readerNames(buf []byte) []string {
	return splitReaderNames(buf)
}
