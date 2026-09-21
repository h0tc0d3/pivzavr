package embed

import (
	"strings"

	"github.com/pkg/errors"
)

// The names, namespaces and content types of an Office Open XML package.
const (
	// opcContentTypes is the part that declares the content type of every
	// other part.
	opcContentTypes = "[Content_Types].xml"
	// opcRelationships is the part that holds the relationships of the package.
	opcRelationships = "_rels/.rels"
	// opcSignatureDirectory holds the signature parts of a package.
	opcSignatureDirectory = "_xmlsignatures/"
	// opcOriginPart is the part a signature belongs to.
	opcOriginPart = opcSignatureDirectory + "origin.sigs"
	// opcSignaturePart holds one XML signature of the package.
	opcSignaturePart = opcSignatureDirectory + "sig1.xml"
	// opcOriginRelationships holds the relationships of the origin part.
	opcOriginRelationships = opcSignatureDirectory + "_rels/origin.sigs.rels"

	// opcContentTypesNS is the namespace of the content types part.
	opcContentTypesNS = "http://schemas.openxmlformats.org/package/2006/content-types"
	// opcRelationshipsNS is the namespace of a relationships part.
	opcRelationshipsNS = "http://schemas.openxmlformats.org/package/2006/relationships"
	// opcDigitalSignatureNS is the namespace of the origin part.
	opcDigitalSignatureNS = "http://schemas.openxmlformats.org/package/2006/digital-signature"

	// opcOriginContentType is the content type of the signature origin part.
	opcOriginContentType = "application/vnd.openxmlformats-package.digital-signature-origin"
	// opcSignatureContentType is the content type of a signature part.
	opcSignatureContentType = "application/vnd.openxmlformats-officedocument.digital-signature-xmlsignature+xml"
	// opcOriginRelationshipType relates a package to its signature origin.
	opcOriginRelationshipType = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin"
	// opcSignatureRelationshipType relates an origin to a signature.
	opcSignatureRelationshipType = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature"
)

// opcPartNames returns the parts of a package that a signature covers: every
// part except the signature parts themselves.
func opcPartNames(entries []zipEntry) map[string][]byte {
	parts := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if entry.Name == "" || strings.HasSuffix(entry.Name, "/") {
			continue
		}
		if strings.HasPrefix(entry.Name, opcSignatureDirectory) {
			continue
		}
		parts[entry.Name] = entry.Data
	}
	return parts
}

// opcAddContentTypes returns the content types part with the content type of
// the signature origin and of the signature part declared, so that a package
// consumer can find the signature.
func opcAddContentTypes(data []byte) ([]byte, error) {
	roots, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	root, err := rootElement(roots)
	if err != nil {
		return nil, err
	}

	if !opcDeclaresContentType(root, "Extension", "sigs") {
		declaration, err := parseElement(`<Default xmlns="` + opcContentTypesNS + `" Extension="sigs" ContentType="` + opcOriginContentType + `"></Default>`)
		if err != nil {
			return nil, err
		}
		// The declarations of the extensions come before the overrides of the
		// parts they cover.
		insertChildBefore(root, "Override", declaration)
	}
	if !opcDeclaresContentType(root, "PartName", "/"+opcSignaturePart) {
		registration, err := parseElement(`<Override xmlns="` + opcContentTypesNS + `" PartName="/` + opcSignaturePart + `" ContentType="` + opcSignatureContentType + `"></Override>`)
		if err != nil {
			return nil, err
		}
		appendChild(root, registration)
	}

	return xmlDocument(root)
}

// opcDeclaresContentType reports whether the content types part already
// declares an extension or a part name.
func opcDeclaresContentType(root *element, attribute, value string) bool {
	for _, child := range childElements(root) {
		if attrValue(child, attribute) == value {
			return true
		}
	}
	return false
}

// opcAddOriginRelationship returns the relationships of the package with the
// relationship to the signature origin added, so that a package consumer
// discovers the signature.
func opcAddOriginRelationship(data []byte) ([]byte, error) {
	roots, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	root, err := rootElement(roots)
	if err != nil {
		return nil, err
	}

	for _, child := range childElements(root) {
		if attrValue(child, "Type") == opcOriginRelationshipType {
			return xmlDocument(root)
		}
	}
	relationship, err := parseElement(`<Relationship xmlns="` + opcRelationshipsNS + `" Id="pivzavrSignatureOrigin" Type="` + opcOriginRelationshipType + `" Target="` + opcSignatureDirectory + `origin.sigs"></Relationship>`)
	if err != nil {
		return nil, err
	}
	appendChild(root, relationship)
	return xmlDocument(root)
}

// opcSignatureOrigin returns the bytes of the origin part the signatures of a
// package belong to.
func opcSignatureOrigin() []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" +
		`<SignatureOrigin xmlns="` + opcDigitalSignatureNS + `"></SignatureOrigin>` + "\n")
}

// opcOriginRelationshipsXML returns the bytes of the relationships of the origin
// part, which point to the signature part.
func opcOriginRelationshipsXML() []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" +
		`<Relationships xmlns="` + opcRelationshipsNS + `">` +
		`<Relationship Id="pivzavrSignature1" Type="` + opcSignatureRelationshipType + `" Target="sig1.xml"></Relationship>` +
		`</Relationships>` + "\n")
}

// removeEntriesWithPrefix removes every entry whose name starts with prefix.
func removeEntriesWithPrefix(entries []zipEntry, prefix string) []zipEntry {
	result := make([]zipEntry, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name, prefix) {
			continue
		}
		result = append(result, entry)
	}
	return result
}

// signOPC embeds a signature in an Office Open XML package: the digest of every
// part is written to the manifest of an XML signature, the manifest is signed
// with the key of the smart card, and the signature is stored in the package
// part the specification reserves for it.
func signOPC(_ Format, data []byte, signer *Signer) ([]byte, error) {
	entries, err := readZip(data)
	if err != nil {
		return nil, err
	}

	contentTypes := zipEntryNamed(entries, opcContentTypes)
	if contentTypes == nil {
		return nil, errors.Errorf("the package has no %s part", opcContentTypes)
	}
	relationships := zipEntryNamed(entries, opcRelationships)
	if relationships == nil {
		return nil, errors.Errorf("the package has no %s part", opcRelationships)
	}

	updatedContentTypes, err := opcAddContentTypes(contentTypes.Data)
	if err != nil {
		return nil, errors.Wrap(err, "Update the content types")
	}
	updatedRelationships, err := opcAddOriginRelationship(relationships.Data)
	if err != nil {
		return nil, errors.Wrap(err, "Update the package relationships")
	}

	entries = replaceZipEntry(entries, zipEntry{Name: opcContentTypes, Data: updatedContentTypes})
	entries = replaceZipEntry(entries, zipEntry{Name: opcRelationships, Data: updatedRelationships})
	parts := opcPartNames(entries)

	signature, err := signXMLParts(parts, signer, "")
	if err != nil {
		return nil, err
	}

	entries = removeEntriesWithPrefix(entries, opcSignatureDirectory)
	entries = replaceZipEntry(entries, zipEntry{Name: opcOriginPart, Data: opcSignatureOrigin()})
	entries = replaceZipEntry(entries, zipEntry{Name: opcOriginRelationships, Data: opcOriginRelationshipsXML()})
	entries = replaceZipEntry(entries, zipEntry{Name: opcSignaturePart, Data: signature})
	return writeZip(entries)
}

// verifyOPC verifies the signature of an Office Open XML package.
func verifyOPC(format Format, data []byte) (*Signature, error) {
	entries, err := readZip(data)
	if err != nil {
		return nil, err
	}

	signaturePart := findOPCSignaturePart(entries)
	if signaturePart == nil {
		return nil, errors.New("the package carries no signature part")
	}

	contentTypes := zipEntryNamed(entries, opcContentTypes)
	if contentTypes == nil {
		return nil, errors.Errorf("the package has no %s part", opcContentTypes)
	}
	contentTypesRoot, err := parseElement(string(contentTypes.Data))
	if err != nil {
		return nil, errors.Wrap(err, "Parse the content types")
	}
	if !opcDeclaresContentType(contentTypesRoot, "Extension", "sigs") {
		return nil, errors.New("the content types do not declare the signature origin part")
	}

	return verifyXMLParts(signaturePart.Data, opcPartNames(entries), format)
}

// findOPCSignaturePart returns the part that holds the signature of a package:
// the part the specification names, or the first XML part of the
// _xmlsignatures directory.
func findOPCSignaturePart(entries []zipEntry) *zipEntry {
	if named := zipEntryNamed(entries, opcSignaturePart); named != nil {
		return named
	}
	for i := range entries {
		name := strings.ToLower(entries[i].Name)
		if !strings.HasPrefix(name, opcSignatureDirectory) {
			continue
		}
		if strings.HasSuffix(name, ".xml") && !strings.Contains(name, "_rels/") {
			return &entries[i]
		}
	}
	return nil
}
