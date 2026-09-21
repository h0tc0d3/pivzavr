package embed

import (
	"sort"

	"github.com/pkg/errors"
)

// signXMLParts signs the parts of a container. The digest of every part is
// written to the manifest of a new XML signature, the manifest is signed with
// the key of the smart card, and the signature document is returned. wrapper is
// the XML of the element that holds the signature when the format requires the
// signature to be nested, such as the document-signatures element of
// OpenDocument; it is empty when the signature is the root of the document.
func signXMLParts(parts map[string][]byte, signer *Signer, wrapper string) ([]byte, error) {
	algorithm, err := algorithmFor(signer.Certificate)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(parts))
	for name := range parts {
		names = append(names, name)
	}
	sort.Strings(names)
	digests := make([]xmlPart, 0, len(names))
	for _, name := range names {
		digests = append(digests, xmlPart{Name: name, Digest: hashBytes(algorithm.Hash, parts[name])})
	}

	signature, err := newXMLSignature(algorithm, signer.Certificate, signer.SigningTime, xmlReference{
		ID:         contentRefID,
		URI:        "#" + manifestID,
		Transforms: []string{excC14N},
	}, digests)
	if err != nil {
		return nil, err
	}

	root := signature
	if wrapper != "" {
		if root, err = parseElement(wrapper); err != nil {
			return nil, err
		}
		appendChild(root, signature)
	}

	manifest := elementByID(root, manifestID)
	if manifest == nil {
		return nil, errors.New("the XML signature has no manifest")
	}
	manifestDigest := hashBytes(algorithm.Hash, canonicalizeElement(manifest, scopeAt(root, manifest)))
	if err := finalizeXMLSignature(signature, root, algorithm, manifestDigest, signer); err != nil {
		return nil, err
	}
	return xmlDocument(root)
}

// verifyXMLParts verifies the signature document of a container. parts holds
// the bytes of the parts the manifest digests, keyed by part name.
func verifyXMLParts(data []byte, parts map[string][]byte, format Format) (*Signature, error) {
	result, err := verifyXMLSignatureDocument(data, parts)
	if err != nil {
		return nil, err
	}
	result.Format = format
	return result, nil
}
