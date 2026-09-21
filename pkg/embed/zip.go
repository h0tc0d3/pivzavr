package embed

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"time"

	"github.com/pkg/errors"
)

// zipEntry is a part of a container that is held in memory.
type zipEntry struct {
	// Name is the name of the entry as it is stored.
	Name string
	// Data holds the bytes of the entry.
	Data []byte
	// Modified is the modification time of the entry.
	Modified time.Time
	// Mode is the permission of the entry.
	Mode os.FileMode
	// Store keeps the entry uncompressed, as some entry names require.
	Store bool
}

// readZip returns the entries of a ZIP archive in the order they are stored.
func readZip(data []byte) ([]zipEntry, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errors.Wrap(err, "Read ZIP container")
	}

	entries := make([]zipEntry, 0, len(reader.File))
	for _, file := range reader.File {
		entry := zipEntry{
			Name:     file.Name,
			Modified: file.Modified,
			Mode:     file.Mode(),
			Store:    file.Method == zip.Store,
		}
		if file.FileInfo().IsDir() {
			entries = append(entries, entry)
			continue
		}

		reader, err := file.Open()
		if err != nil {
			return nil, errors.Wrapf(err, "Read %q", file.Name)
		}
		content, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil {
			return nil, errors.Wrapf(err, "Read %q", file.Name)
		}
		entry.Data = content
		entries = append(entries, entry)
	}
	return entries, nil
}

// writeZip writes the entries to a ZIP archive.
func writeZip(entries []zipEntry) ([]byte, error) {
	buf := new(bytes.Buffer)
	writer := zip.NewWriter(buf)

	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.Name}
		if entry.Modified.IsZero() {
			header.Modified = time.Now()
		} else {
			header.Modified = entry.Modified
		}
		if entry.Store {
			header.Method = zip.Store
		} else {
			header.Method = zip.Deflate
		}
		if entry.Mode != 0 {
			header.SetMode(entry.Mode)
		}

		part, err := writer.CreateHeader(header)
		if err != nil {
			return nil, errors.Wrapf(err, "Write %q", entry.Name)
		}
		if _, err := part.Write(entry.Data); err != nil {
			return nil, errors.Wrapf(err, "Write %q", entry.Name)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, errors.Wrap(err, "Write ZIP container")
	}
	return buf.Bytes(), nil
}

// zipEntryNamed returns the entry with the given name, or nil when the
// container holds no such entry.
func zipEntryNamed(entries []zipEntry, name string) *zipEntry {
	for i := range entries {
		if entries[i].Name == name {
			return &entries[i]
		}
	}
	return nil
}

// replaceZipEntry adds an entry to a container, replacing the entries with the
// same name, and returns the new list of entries.
func replaceZipEntry(entries []zipEntry, entry zipEntry) []zipEntry {
	result := make([]zipEntry, 0, len(entries)+1)
	for _, existing := range entries {
		if existing.Name == entry.Name {
			continue
		}
		result = append(result, existing)
	}
	return append(result, entry)
}
