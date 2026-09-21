package embed

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"sort"
	"strings"

	"github.com/h0tc0d3/pivzavr/pkg/cms"
	"github.com/pkg/errors"
)

// hashForKey returns the digest algorithm that is used with a public key. The
// key of a smart card is an RSA or an ECDSA key, so the size of the key selects
// the algorithm.
func hashForKey(key crypto.PublicKey) crypto.Hash {
	switch public := key.(type) {
	case *ecdsa.PublicKey:
		if public.Curve != nil {
			switch public.Curve.Params().BitSize {
			case 384:
				return crypto.SHA384
			case 521:
				return crypto.SHA512
			}
		}
	case ed25519.PublicKey:
		return crypto.SHA512
	}
	return crypto.SHA256
}

// jarDigestAttribute returns the name of the manifest attribute that holds the
// digest of a hash, such as "SHA-256-Digest".
func jarDigestAttribute(hash crypto.Hash) string {
	switch hash {
	case crypto.SHA384:
		return "SHA-384-Digest"
	case crypto.SHA512:
		return "SHA-512-Digest"
	}
	return "SHA-256-Digest"
}

// hashForAttribute returns the hash of a manifest digest attribute name.
func hashForAttribute(name string) (crypto.Hash, bool) {
	switch name {
	case "SHA-256-Digest", "SHA256-Digest":
		return crypto.SHA256, true
	case "SHA-384-Digest", "SHA384-Digest":
		return crypto.SHA384, true
	case "SHA-512-Digest", "SHA512-Digest":
		return crypto.SHA512, true
	}
	return 0, false
}

// appendManifestLine appends a "name: value" attribute line to a manifest,
// wrapped as the JAR file format requires: at most 72 bytes per line, with a
// single space that starts each continuation line. The blank line that
// terminates a manifest section is written by the caller.
func appendManifestLine(buf *bytes.Buffer, name, value string) {
	line := name + ": " + value
	for first := true; len(line) > 0; first = false {
		limit := 72
		if !first {
			limit = 71
			buf.WriteByte(' ')
		}
		if len(line) <= limit {
			buf.WriteString(line)
			break
		}
		// The line is broken at a character boundary, so that a character that
		// is several bytes wide is not split between two lines.
		breakAt := limit
		for breakAt > 0 && line[breakAt]&0xC0 == 0x80 {
			breakAt--
		}
		buf.WriteString(line[:breakAt])
		buf.WriteString("\r\n")
		line = line[breakAt:]
	}
	buf.WriteString("\r\n")
}

// manifestSectionTerminator ends a section of a manifest.
const manifestSectionTerminator = "\r\n"

// buildManifest returns the bytes of the MANIFEST.MF file, the bytes of its
// main section and the bytes of the section of every entry it lists.
func buildManifest(entries []zipEntry, hash crypto.Hash) ([]byte, []byte, map[string][]byte) {
	attribute := jarDigestAttribute(hash)

	var main bytes.Buffer
	appendManifestLine(&main, "Manifest-Version", "1.0")
	appendManifestLine(&main, "Created-By", "pivzavr")
	main.WriteString(manifestSectionTerminator)

	var manifest bytes.Buffer
	manifest.Write(main.Bytes())

	sections := make(map[string][]byte)
	for _, entry := range entries {
		if entry.Name == "" || strings.HasSuffix(entry.Name, "/") || isMetaInf(entry.Name) {
			continue
		}
		var section bytes.Buffer
		appendManifestLine(&section, "Name", entry.Name)
		appendManifestLine(&section, attribute, base64.StdEncoding.EncodeToString(hashBytes(hash, entry.Data)))
		section.WriteString(manifestSectionTerminator)
		sections[entry.Name] = section.Bytes()
		manifest.Write(section.Bytes())
	}
	return manifest.Bytes(), main.Bytes(), sections
}

// isMetaInf reports whether an entry lies in the META-INF directory, whose
// entries a manifest does not list.
func isMetaInf(name string) bool {
	return len(name) >= 8 && strings.EqualFold(name[:8], "META-INF") && (name[8] == '/' || name[8] == '\\')
}

// jarSignatureName returns the base name and the extension of the manifest
// signature files of a format.
func jarSignatureName(format Format, key crypto.PublicKey) (string, string) {
	base := "PIVZAVR"
	if format == APK {
		base = "CERT"
	}
	switch key.(type) {
	case *ecdsa.PublicKey:
		return base, "EC"
	case ed25519.PublicKey:
		return base, "SIG"
	}
	return base, "RSA"
}

// signJAR signs a JAR archive or an APK package with the JAR signing scheme:
// the digest of every entry is written to MANIFEST.MF, the digest of the
// manifest is written to the .SF file, and the .SF file is signed with a
// detached CMS signature.
func signJAR(format Format, data []byte, signer *Signer) ([]byte, error) {
	entries, err := readZip(data)
	if err != nil {
		return nil, err
	}

	hash := hashForKey(signer.Certificate.PublicKey)
	manifest, mainSection, sections := buildManifest(entries, hash)
	signatureFile := buildSignatureFile(manifest, mainSection, sections, hash)

	sd, err := cms.NewSignedData(signatureFile)
	if err != nil {
		return nil, errors.Wrap(err, "Create signed data")
	}
	if err := sd.Sign([]*x509.Certificate{signer.Certificate}, signer.Signer); err != nil {
		return nil, errors.Wrap(err, "Sign manifest")
	}
	sd.Detached()
	if err := sd.SetCertificates([]*x509.Certificate{signer.Certificate}); err != nil {
		return nil, errors.Wrap(err, "Set certificates in signature")
	}
	block, err := sd.ToDER()
	if err != nil {
		return nil, errors.Wrap(err, "Serialize signature")
	}

	base, extension := jarSignatureName(format, signer.Certificate.PublicKey)
	entries = removeJARSignatures(entries)
	entries = replaceZipEntry(entries, zipEntry{Name: "META-INF/MANIFEST.MF", Data: manifest})
	entries = replaceZipEntry(entries, zipEntry{Name: "META-INF/" + base + ".SF", Data: signatureFile})
	entries = replaceZipEntry(entries, zipEntry{Name: "META-INF/" + base + "." + extension, Data: block})

	return writeZip(entries)
}

// removeJARSignatures removes the signature files a previous signature left in
// the archive.
func removeJARSignatures(entries []zipEntry) []zipEntry {
	result := make([]zipEntry, 0, len(entries))
	for _, entry := range entries {
		if isMetaInf(entry.Name) && isJARSignaturePart(entry.Name) {
			continue
		}
		result = append(result, entry)
	}
	return result
}

// isJARSignaturePart reports whether an entry in META-INF is part of a
// signature rather than content.
func isJARSignaturePart(name string) bool {
	lower := strings.ToLower(name)
	switch {
	case lower == "meta-inf/manifest.mf":
		return true
	case strings.HasSuffix(lower, ".sf"):
		return true
	case strings.HasSuffix(lower, ".rsa"), strings.HasSuffix(lower, ".dsa"), strings.HasSuffix(lower, ".ec"), strings.HasSuffix(lower, ".sig"):
		return true
	}
	return false
}

// buildSignatureFile returns the bytes of the .SF file that signs the manifest.
// It holds the digest of the whole manifest and the digest of the section of
// every entry, so that an entry that was added, removed or changed is detected
// even when it is not listed in the manifest.
func buildSignatureFile(manifest, mainSection []byte, sections map[string][]byte, hash crypto.Hash) []byte {
	attribute := jarDigestAttribute(hash)

	var out bytes.Buffer
	appendManifestLine(&out, "Signature-Version", "1.0")
	appendManifestLine(&out, "Created-By", "pivzavr")
	appendManifestLine(&out, attribute+"-Manifest", base64.StdEncoding.EncodeToString(hashBytes(hash, manifest)))
	appendManifestLine(&out, attribute+"-Manifest-Main-Attributes", base64.StdEncoding.EncodeToString(hashBytes(hash, mainSection)))
	out.WriteString(manifestSectionTerminator)

	names := make([]string, 0, len(sections))
	for name := range sections {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		appendManifestLine(&out, "Name", name)
		appendManifestLine(&out, attribute, base64.StdEncoding.EncodeToString(hashBytes(hash, sections[name])))
		out.WriteString(manifestSectionTerminator)
	}
	return out.Bytes()
}

// splitManifestSections returns the raw bytes of every section of a manifest
// file, including the blank line that terminates a section.
func splitManifestSections(data []byte) [][]byte {
	var sections [][]byte
	for len(data) > 0 {
		end := bytes.Index(data, []byte("\r\n\r\n"))
		if end < 0 {
			if len(bytes.TrimRight(data, "\r\n")) > 0 {
				sections = append(sections, data)
			}
			break
		}
		end += 4
		sections = append(sections, data[:end])
		data = data[end:]
	}
	return sections
}

// manifestAttributes returns the attributes of a manifest section. A line that
// continues a value is joined with the value it continues.
func manifestAttributes(section []byte) map[string]string {
	attributes := map[string]string{}
	var name, value string
	flush := func() {
		if name != "" {
			attributes[name] = value
		}
		name, value = "", ""
	}

	for _, raw := range bytes.Split(section, []byte("\r\n")) {
		line := string(raw)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, " "):
			value += line[1:]
			continue
		}
		flush()
		key, val, found := strings.Cut(line, ": ")
		if !found {
			continue
		}
		name, value = key, val
	}
	flush()
	return attributes
}

// manifestSectionsOf returns the main section of a manifest and the section of
// every entry it lists.
func manifestSectionsOf(data []byte) ([]byte, map[string][]byte, error) {
	sections := splitManifestSections(data)
	if len(sections) == 0 {
		return nil, nil, errors.New("the manifest is empty")
	}
	byName := make(map[string][]byte, len(sections))
	for _, section := range sections[1:] {
		name := manifestAttributes(section)["Name"]
		if name == "" {
			continue
		}
		byName[name] = section
	}
	return sections[0], byName, nil
}

// checkDigest compares the digest of content with the base64 encoded digest an
// attribute carries.
func checkDigest(hash crypto.Hash, content []byte, expected, what string) error {
	decoded, err := base64.StdEncoding.DecodeString(expected)
	if err != nil {
		return errors.Wrapf(err, "Decode the digest of %s", what)
	}
	if !bytes.Equal(hashBytes(hash, content), decoded) {
		return errors.Errorf("the digest of %s does not match", what)
	}
	return nil
}

// checkSignatureFile checks the digests the .SF file carries against the
// manifest.
func checkSignatureFile(signatureFile, manifest, mainSection []byte, sections map[string][]byte) error {
	for _, section := range splitManifestSections(signatureFile) {
		attributes := manifestAttributes(section)
		name := attributes["Name"]
		for key, value := range attributes {
			switch {
			case strings.HasSuffix(key, "-Digest-Manifest-Main-Attributes"):
				hash, ok := hashForAttribute(strings.TrimSuffix(key, "-Manifest-Main-Attributes"))
				if !ok {
					continue
				}
				if err := checkDigest(hash, mainSection, value, "the main attributes of the manifest"); err != nil {
					return err
				}
			case strings.HasSuffix(key, "-Digest-Manifest"):
				hash, ok := hashForAttribute(strings.TrimSuffix(key, "-Manifest"))
				if !ok {
					continue
				}
				if err := checkDigest(hash, manifest, value, "the manifest"); err != nil {
					return err
				}
			case strings.HasSuffix(key, "-Digest") && name != "":
				hash, ok := hashForAttribute(key)
				if !ok {
					continue
				}
				manifestSection, ok := sections[name]
				if !ok {
					return errors.Errorf("the manifest has no section for %q", name)
				}
				if err := checkDigest(hash, manifestSection, value, "the manifest section of "+name); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// checkEntries checks every entry the manifest lists against its digest and
// rejects an entry that the signature does not cover.
func checkEntries(entries []zipEntry, sections map[string][]byte) error {
	for name, section := range sections {
		entry := zipEntryNamed(entries, name)
		if entry == nil {
			return errors.Errorf("the entry %q that the manifest lists is missing", name)
		}
		for key, value := range manifestAttributes(section) {
			if key == "Name" {
				continue
			}
			hash, ok := hashForAttribute(key)
			if !ok {
				continue
			}
			if err := checkDigest(hash, entry.Data, value, "the entry "+name); err != nil {
				return err
			}
		}
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name, "/") {
			continue
		}
		if _, listed := sections[entry.Name]; listed {
			continue
		}
		// The manifest does not list the files of META-INF, which carry
		// signature metadata rather than the content of the archive.
		if isMetaInf(entry.Name) {
			continue
		}
		return errors.Errorf("the entry %q is not covered by the signature", entry.Name)
	}
	return nil
}

// jarSignatureEntries returns the manifest signature file and the signature
// block of an archive.
func jarSignatureEntries(entries []zipEntry) (*zipEntry, *zipEntry, error) {
	var signatureFile, block *zipEntry
	for i := range entries {
		name := entries[i].Name
		if !isMetaInf(name) {
			continue
		}
		lower := strings.ToLower(name)
		switch {
		case lower != "meta-inf/manifest.mf" && strings.HasSuffix(lower, ".sf"):
			if signatureFile == nil {
				signatureFile = &entries[i]
			}
		case strings.HasSuffix(lower, ".rsa"), strings.HasSuffix(lower, ".dsa"), strings.HasSuffix(lower, ".ec"), strings.HasSuffix(lower, ".sig"):
			if block == nil {
				block = &entries[i]
			}
		}
	}
	if signatureFile == nil {
		return nil, nil, errors.New("the archive has no manifest signature file")
	}
	if block == nil {
		return nil, nil, errors.New("the archive has no signature block")
	}
	return signatureFile, block, nil
}

// verifyJAR verifies the JAR signature of an archive: the signature block over
// the .SF file, the digests of the .SF file over the manifest, and the digests
// of the manifest over every entry.
func verifyJAR(format Format, data []byte) (*Signature, error) {
	entries, err := readZip(data)
	if err != nil {
		return nil, err
	}

	manifest := zipEntryNamed(entries, "META-INF/MANIFEST.MF")
	if manifest == nil {
		manifest = zipEntryNamed(entries, "meta-inf/manifest.mf")
	}
	if manifest == nil {
		return nil, errors.New("the archive has no META-INF/MANIFEST.MF")
	}
	signatureFile, block, err := jarSignatureEntries(entries)
	if err != nil {
		return nil, err
	}

	certificate, certificates, details, err := verifyDetachedCMS(block.Data, signatureFile.Data)
	if err != nil {
		return nil, errors.Wrap(err, "Verify signature block")
	}

	mainSection, sections, err := manifestSectionsOf(manifest.Data)
	if err != nil {
		return nil, err
	}
	if err := checkSignatureFile(signatureFile.Data, manifest.Data, mainSection, sections); err != nil {
		return nil, err
	}
	if err := checkEntries(entries, sections); err != nil {
		return nil, err
	}

	return &Signature{
		Format:             format,
		Certificate:        certificate,
		Certificates:       certificates,
		SigningTime:        details.SigningTime,
		SignatureAlgorithm: details.SignatureAlgorithm,
	}, nil
}
