package embed

import (
	"strings"

	"github.com/pkg/errors"
)

// The names and namespaces of an OpenDocument package.
const (
	// odfSignaturesPart holds the signatures of a document.
	odfSignaturesPart = "META-INF/documentsignatures.xml"
	// odfManifestPart lists the files of a document.
	odfManifestPart = "META-INF/manifest.xml"

	// odfSignatureNS is the namespace of the document-signatures element.
	odfSignatureNS = "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0"
	// odfManifestNS is the namespace of the manifest of a document.
	odfManifestNS = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
	// odfSignatureMediaType is the media type of the signature part.
	odfSignatureMediaType = "application/vnd.oasis.opendocument.digital-signatures"
)

// odfSignatureWrapper is the element that holds the signatures of a document,
// as the OpenDocument specification requires.
const odfSignatureWrapper = `<document-signatures xmlns="` + odfSignatureNS + `"></document-signatures>`

// odfAddManifestEntry returns the manifest of a document with the entry that
// declares the signature part added.
func odfAddManifestEntry(data []byte) ([]byte, error) {
	roots, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	root, err := rootElement(roots)
	if err != nil {
		return nil, err
	}

	for _, child := range childElements(root) {
		if attrValue(child, "full-path") == odfSignaturesPart {
			return xmlDocument(root)
		}
	}
	entry, err := parseElement(`<manifest:file-entry xmlns:manifest="` + odfManifestNS + `" manifest:full-path="` + odfSignaturesPart + `" manifest:media-type="` + odfSignatureMediaType + `"></manifest:file-entry>`)
	if err != nil {
		return nil, err
	}
	appendChild(root, entry)
	return xmlDocument(root)
}

// odfPartNames returns the parts of a document that a signature covers: every
// part except the signature part itself.
func odfPartNames(entries []zipEntry) map[string][]byte {
	parts := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if entry.Name == "" || strings.HasSuffix(entry.Name, "/") {
			continue
		}
		if strings.EqualFold(entry.Name, odfSignaturesPart) {
			continue
		}
		parts[entry.Name] = entry.Data
	}
	return parts
}

// signODF embeds a signature in an OpenDocument document: the digest of every
// part is written to the manifest of an XML signature, the manifest is signed
// with the key of the smart card, and the signature is stored in the package
// part the specification reserves for it.
func signODF(data []byte, signer *Signer) ([]byte, error) {
	entries, err := readZip(data)
	if err != nil {
		return nil, err
	}

	manifest := zipEntryNamed(entries, odfManifestPart)
	if manifest == nil {
		return nil, errors.Errorf("the document has no %s part", odfManifestPart)
	}
	updatedManifest, err := odfAddManifestEntry(manifest.Data)
	if err != nil {
		return nil, errors.Wrap(err, "Update the manifest")
	}
	entries = replaceZipEntry(entries, zipEntry{Name: odfManifestPart, Data: updatedManifest})

	signature, err := signXMLParts(odfPartNames(entries), signer, odfSignatureWrapper)
	if err != nil {
		return nil, err
	}

	entries = removeEntriesNamed(entries, odfSignaturesPart)
	entries = replaceZipEntry(entries, zipEntry{Name: odfSignaturesPart, Data: signature})
	return writeZip(entries)
}

// verifyODF verifies the signature of an OpenDocument document.
func verifyODF(data []byte) (*Signature, error) {
	entries, err := readZip(data)
	if err != nil {
		return nil, err
	}

	var signaturePart *zipEntry
	for i := range entries {
		if strings.EqualFold(entries[i].Name, odfSignaturesPart) {
			signaturePart = &entries[i]
			break
		}
	}
	if signaturePart == nil {
		return nil, errors.New("the document carries no signature part")
	}

	return verifyXMLParts(signaturePart.Data, odfPartNames(entries), ODT)
}

// removeEntriesNamed removes every entry with the given name.
func removeEntriesNamed(entries []zipEntry, name string) []zipEntry {
	result := make([]zipEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Name == name {
			continue
		}
		result = append(result, entry)
	}
	return result
}
