package embed

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/h0tc0d3/pivzavr/pkg/testcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSigner returns the material an embedded signature is made with.
func testSigner(t *testing.T) *Signer {
	t.Helper()
	certificate, signer := testcert.Identity(t)
	return &Signer{Certificate: certificate, Signer: signer, SigningTime: time.Now().UTC().Truncate(time.Second)}
}

// testArchive returns a ZIP archive that holds the given entries in the order
// they are listed.
func testArchive(t *testing.T, names []string, content map[string]string) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	writer := zip.NewWriter(buf)
	for _, name := range names {
		part, err := writer.Create(name)
		require.NoError(t, err)
		_, err = part.Write([]byte(content[name]))
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	return buf.Bytes()
}

const testXMLDocument = `<?xml version="1.0" encoding="UTF-8"?>
<invoice xmlns:ex="urn:example">
  <ex:number>42</ex:number>
  <total currency="EUR">100 &amp; 20</total>
</invoice>
`

const testContentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`

const testPackageRelationships = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`

const testDocument = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<document xmlns="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><body><p><r><t>Hello</t></r></p></body></document>`

const testOdfManifest = `<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2"><manifest:file-entry manifest:full-path="/" manifest:version="1.2" manifest:media-type="application/vnd.oasis.opendocument.text"/><manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/></manifest:manifest>`

const testOdfContent = `<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" office:version="1.2"><office:body><office:text><text:p xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">Hello</text:p></office:text></office:body></office:document-content>`

func docxFixture(t *testing.T) []byte {
	t.Helper()
	return testArchive(t, []string{
		"[Content_Types].xml",
		"_rels/.rels",
		"word/document.xml",
	}, map[string]string{
		"[Content_Types].xml": testContentTypes,
		"_rels/.rels":         testPackageRelationships,
		"word/document.xml":   testDocument,
	})
}

func odfFixture(t *testing.T) []byte {
	t.Helper()
	return testArchive(t, []string{
		"mimetype",
		"META-INF/manifest.xml",
		"content.xml",
	}, map[string]string{
		"mimetype":              "application/vnd.oasis.opendocument.text",
		"META-INF/manifest.xml": testOdfManifest,
		"content.xml":           testOdfContent,
	})
}

func jarFixture(t *testing.T) []byte {
	t.Helper()
	return testArchive(t, []string{
		"META-INF/MANIFEST.MF",
		"META-INF/services/com.example.Service",
		"com/example/Main.class",
		"com/example/data.txt",
	}, map[string]string{
		"META-INF/MANIFEST.MF":                  "Manifest-Version: 1.0\r\n\r\n",
		"META-INF/services/com.example.Service": "com.example.Implementation",
		"com/example/Main.class":                "not really a class",
		"com/example/data.txt":                  "hello jar",
	})
}

func TestSignAndVerify(t *testing.T) {
	signer := testSigner(t)

	testCases := []struct {
		name   string
		format Format
		data   []byte
	}{
		{"xml", XML, []byte(testXMLDocument)},
		{"docx", DOCX, docxFixture(t)},
		{"xlsx", XLSX, docxFixture(t)},
		{"odt", ODT, odfFixture(t)},
		{"jar", JAR, jarFixture(t)},
		{"apk", APK, jarFixture(t)},
		{"pdf", PDF, minimalPDF(t)},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			signed, err := Sign(test.format, test.data, signer)
			require.NoError(t, err)
			require.NotEqual(t, test.data, signed)

			signature, err := Verify(test.format, signed)
			require.NoError(t, err)
			assert.Equal(t, test.format, signature.Format)
			assert.True(t, signer.Certificate.Equal(signature.Certificate))
			assert.NotEmpty(t, signature.Certificates)
			assert.NotEqual(t, x509.UnknownSignatureAlgorithm, signature.SignatureAlgorithm)
			assert.WithinDuration(t, signer.SigningTime, signature.SigningTime, 2*time.Second)
		})
	}
}

func TestVerifyRejectsTamperedXML(t *testing.T) {
	signer := testSigner(t)
	signed, err := Sign(XML, []byte(testXMLDocument), signer)
	require.NoError(t, err)

	tampered := bytes.Replace(signed, []byte("<ex:number>42</ex:number>"), []byte("<ex:number>43</ex:number>"), 1)
	_, err = Verify(XML, tampered)
	assert.Error(t, err)
}

func TestVerifyRejectsTamperedDOCX(t *testing.T) {
	signer := testSigner(t)
	signed, err := Sign(DOCX, docxFixture(t), signer)
	require.NoError(t, err)

	tampered := tamperZipEntry(t, signed, "word/document.xml", "<t>Hello</t>", "<t>Bonjour</t>")
	_, err = Verify(DOCX, tampered)
	assert.ErrorContains(t, err, "does not match its digest")
}

func TestVerifyRejectsTamperedODT(t *testing.T) {
	signer := testSigner(t)
	signed, err := Sign(ODT, odfFixture(t), signer)
	require.NoError(t, err)

	tampered := tamperZipEntry(t, signed, "content.xml", "Hello", "Goodbye")
	_, err = Verify(ODT, tampered)
	assert.Error(t, err)
}

func TestVerifyRejectsTamperedJAR(t *testing.T) {
	signer := testSigner(t)
	signed, err := Sign(JAR, jarFixture(t), signer)
	require.NoError(t, err)

	tampered := tamperZipEntry(t, signed, "com/example/data.txt", "hello jar", "hello jar!")
	_, err = Verify(JAR, tampered)
	assert.ErrorContains(t, err, "does not match")
}

func TestVerifyRejectsUnsignedJAREntry(t *testing.T) {
	signer := testSigner(t)
	signed, err := Sign(JAR, jarFixture(t), signer)
	require.NoError(t, err)

	entries, err := readZip(signed)
	require.NoError(t, err)
	entries = append(entries, zipEntry{Name: "com/example/extra.txt", Data: []byte("extra")})
	withExtra, err := writeZip(entries)
	require.NoError(t, err)

	_, err = Verify(JAR, withExtra)
	assert.ErrorContains(t, err, "not covered by the signature")
}

func TestVerifyRejectsTamperedPDF(t *testing.T) {
	signer := testSigner(t)
	signed, err := Sign(PDF, minimalPDF(t), signer)
	require.NoError(t, err)

	tampered := bytes.Replace(signed, []byte("/MediaBox"), []byte("/MediABox"), 1)
	_, err = Verify(PDF, tampered)
	assert.Error(t, err)
}

func TestVerifyWithoutSignature(t *testing.T) {
	testCases := []struct {
		name   string
		format Format
		data   []byte
	}{
		{"xml", XML, []byte(testXMLDocument)},
		{"docx", DOCX, docxFixture(t)},
		{"odt", ODT, odfFixture(t)},
		{"jar", JAR, jarFixture(t)},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			_, err := Verify(test.format, test.data)
			assert.Error(t, err)
		})
	}
}

func TestDetect(t *testing.T) {
	assert.Equal(t, XML, Detect("invoice.xml"))
	assert.Equal(t, DOCX, Detect("report.DOCX"))
	assert.Equal(t, XLSX, Detect("/tmp/book.xlsx"))
	assert.Equal(t, ODT, Detect("notes.odt"))
	assert.Equal(t, JAR, Detect("library.jar"))
	assert.Equal(t, APK, Detect("app.apk"))
	assert.Equal(t, PDF, Detect("contract.pdf"))
	assert.Equal(t, Unknown, Detect("README.md"))
	assert.Equal(t, Unknown, Detect("noextension"))
}

func TestSupportedExtensions(t *testing.T) {
	assert.Equal(t, []string{".apk", ".docx", ".jar", ".odt", ".pdf", ".xlsx", ".xml"}, SupportedExtensions())
}

func TestFormatString(t *testing.T) {
	assert.Equal(t, "PDF", PDF.String())
	assert.Equal(t, "DOCX", DOCX.String())
	assert.Equal(t, "unknown", Unknown.String())
}

// tamperZipEntry replaces a piece of a ZIP entry and returns the rewritten
// archive.
func tamperZipEntry(t *testing.T, data []byte, name, old, replacement string) []byte {
	t.Helper()
	entries, err := readZip(data)
	require.NoError(t, err)

	entry := zipEntryNamed(entries, name)
	require.NotNil(t, entry)
	require.Contains(t, string(entry.Data), old)
	entry.Data = []byte(strings.Replace(string(entry.Data), old, replacement, 1))

	rewritten, err := writeZip(entries)
	require.NoError(t, err)
	return rewritten
}

// minimalPDF returns a small PDF document with a cross reference table.
func minimalPDF(t *testing.T) []byte {
	t.Helper()

	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for i, body := range objects {
		offsets[i+1] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}

	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", len(objects)+1)
	buf.WriteString("0000000000 65535 f \n")
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return buf.Bytes()
}

func TestCanonicalizeExclusive(t *testing.T) {
	// A namespace that the element does not use is left out, an empty element
	// is closed with an end tag, and character data is escaped. The namespace
	// the child uses is declared on the child, because the element that
	// declares it does not use it itself.
	roots, err := parseXML([]byte(`<a xmlns:x="urn:x" xmlns:unused="urn:unused"><x:b/>text&amp;more</a>`))
	require.NoError(t, err)
	assert.Equal(t, `<a><x:b xmlns:x="urn:x"></x:b>text&amp;more</a>`, string(canonicalize(roots)))
}

func TestCanonicalizeAttributesAreSorted(t *testing.T) {
	roots, err := parseXML([]byte(`<a xmlns:x="urn:x" z="1" x:b="2" a="3"></a>`))
	require.NoError(t, err)
	// Attributes without a namespace come first, sorted by local name; the
	// namespaced attribute follows.
	assert.Equal(t, `<a xmlns:x="urn:x" a="3" z="1" x:b="2"></a>`, string(canonicalize(roots)))
}

func TestPDFDictInsertAndValue(t *testing.T) {
	dict := []byte("<< /Type /Catalog /Pages 2 0 R >>")
	value, ok := pdfDictValue(dict, "Pages")
	require.True(t, ok)
	assert.Equal(t, "2 0 R", string(value))

	extended := pdfDictInsert(dict, "/AcroForm", "5 0 R")
	assert.Contains(t, string(extended), "/AcroForm 5 0 R")

	replaced := pdfDictInsert(dict, "/Type", "/Other")
	assert.Contains(t, string(replaced), "/Type /Other")
	assert.NotContains(t, string(replaced), "/Catalog")
}
