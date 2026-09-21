package embed

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/h0tc0d3/pivzavr/pkg/cms"
	"github.com/pkg/errors"
)

// pdfObject is an object of the incremental update that carries a signature.
type pdfObject struct {
	number int
	body   []byte
}

// pdfByteRangePlaceholder is the placeholder the byte range of a signature is
// written in, with a fixed width so that it can be filled in once the offsets
// of the file are known.
const pdfByteRangePlaceholder = "0000000000 0000000000 0000000000 0000000000"

// pdfSignaturePlaceholderLength is the number of bytes a signature may occupy
// in a document.
const pdfSignaturePlaceholderLength = 8192

// pdfTrailerInfo describes the trailer of a PDF document.
type pdfTrailerInfo struct {
	// Root is the raw reference to the catalog of the document.
	Root string
	// RootNumber and RootGeneration identify the catalog object.
	RootNumber     int
	RootGeneration int
	// Size is the number of objects the document declares.
	Size int
	// StartXRef is the offset of the cross reference table or stream.
	StartXRef int
	// Dict holds the raw bytes of the trailer dictionary.
	Dict []byte
}

// pdfLastStartXRef returns the offset in the cross reference entry of the last
// update of a document.
func pdfLastStartXRef(data []byte) (int, error) {
	index := bytes.LastIndex(data, []byte("startxref"))
	if index < 0 {
		return 0, errors.New("the PDF has no startxref entry")
	}
	scanner := &pdfScanner{data: data, pos: index + len("startxref")}
	start, end, ok := scanner.token()
	if !ok {
		return 0, errors.New("the PDF has no offset for its cross reference table")
	}
	offset := pdfIntOf(data[start:end])
	if offset <= 0 || offset >= len(data) {
		return 0, errors.Errorf("the PDF cross reference offset %d is outside the file", offset)
	}
	return offset, nil
}

// pdfTrailerDict returns the trailer dictionary of a document, from either a
// cross reference table or a cross reference stream.
func pdfTrailerDict(data []byte, startXRef int) ([]byte, error) {
	if bytes.HasPrefix(data[startXRef:], []byte("xref")) {
		index := bytes.Index(data[startXRef:], []byte("trailer"))
		if index < 0 {
			return nil, errors.New("the PDF has no trailer")
		}
		scanner := &pdfScanner{data: data, pos: startXRef + index + len("trailer")}
		scanner.skipSpace()
		start := scanner.pos
		scanner.skipDict()
		if scanner.pos <= start {
			return nil, errors.New("the trailer of the PDF is not a dictionary")
		}
		return data[start:scanner.pos], nil
	}

	// The document ends with a cross reference stream, whose dictionary is the
	// trailer of the document.
	body, ok := pdfObjectBodyAt(data, startXRef)
	if !ok {
		return nil, errors.New("the cross reference stream of the PDF was not found")
	}
	dict, ok := pdfDictOf(body)
	if !ok {
		return nil, errors.New("the cross reference stream of the PDF has no dictionary")
	}
	return dict, nil
}

// pdfObjectBodyAt returns the body of the object that starts at offset, without
// any stream it holds.
func pdfObjectBodyAt(data []byte, offset int) ([]byte, bool) {
	scanner := &pdfScanner{data: data, pos: offset}
	if _, _, ok := scanner.token(); !ok {
		return nil, false
	}
	if _, _, ok := scanner.token(); !ok {
		return nil, false
	}
	start, end, ok := scanner.token()
	if !ok || !bytes.Equal(data[start:end], []byte("obj")) {
		return nil, false
	}

	bodyStart := scanner.pos
	bodyEnd := bytes.Index(data[bodyStart:], []byte("endobj"))
	if bodyEnd < 0 {
		return nil, false
	}
	body := data[bodyStart : bodyStart+bodyEnd]
	if stream := bytes.Index(body, []byte("stream")); stream >= 0 {
		body = body[:stream]
	}
	return body, true
}

// pdfObjectBody returns the body of the object with the given number and
// generation, taking its last definition in the file.
func pdfObjectBody(data []byte, number, generation int) ([]byte, bool) {
	pattern := []byte(fmt.Sprintf("%d %d obj", number, generation))
	last := -1
	for from := 0; from < len(data); {
		index := bytes.Index(data[from:], pattern)
		if index < 0 {
			break
		}
		index += from
		// The number must start a token, so that an object number is not
		// matched inside a number or a name.
		if index == 0 || pdfWhitespace(data[index-1]) || pdfDelimiter(data[index-1]) {
			last = index
		}
		from = index + len(pattern)
	}
	if last < 0 {
		return nil, false
	}
	return pdfObjectBodyAt(data, last)
}

// pdfTrailerOf returns what a signature needs to know about the trailer of a
// document.
func pdfTrailerOf(data []byte) (*pdfTrailerInfo, error) {
	startXRef, err := pdfLastStartXRef(data)
	if err != nil {
		return nil, err
	}
	dict, err := pdfTrailerDict(data, startXRef)
	if err != nil {
		return nil, err
	}

	rootValue, ok := pdfDictValue(dict, "Root")
	if !ok {
		return nil, errors.New("the trailer of the PDF has no catalog")
	}
	root, ok := pdfReference(rootValue)
	if !ok {
		return nil, errors.New("the trailer of the PDF has no reference to its catalog")
	}
	fields := strings.Fields(root)

	info := &pdfTrailerInfo{
		Root:           root,
		RootNumber:     pdfIntOf([]byte(fields[0])),
		RootGeneration: pdfIntOf([]byte(fields[1])),
		StartXRef:      startXRef,
		Dict:           dict,
	}
	if size, ok := pdfDictValue(dict, "Size"); ok {
		info.Size = pdfIntOf(size)
	}
	if info.Size <= info.RootNumber {
		info.Size = info.RootNumber + 1
	}
	return info, nil
}

// signPDF appends a CMS signature to a PDF document as an incremental update: a
// signature field is added to the form of the document, and the signature
// dictionary it holds carries the signature over the whole file, except the
// bytes the signature itself occupies.
func signPDF(data []byte, signer *Signer) ([]byte, error) {
	trailer, err := pdfTrailerOf(data)
	if err != nil {
		return nil, err
	}
	catalogBody, ok := pdfObjectBody(data, trailer.RootNumber, trailer.RootGeneration)
	if !ok {
		return nil, errors.Errorf("the catalog object %s of the PDF was not found; a catalog that is stored in an object stream cannot be extended", trailer.Root)
	}
	catalog, ok := pdfDictOf(catalogBody)
	if !ok {
		return nil, errors.New("the catalog of the PDF is not a dictionary")
	}

	catalogObject := trailer.Size
	formObject := catalogObject + 1
	fieldObject := catalogObject + 2
	signatureObject := catalogObject + 3

	// The catalog of the update carries the form the signature field belongs
	// to. Every other entry of the catalog is kept as it is.
	newCatalog := pdfDictInsert(catalog, "/AcroForm", fmt.Sprintf("%d 0 R", formObject))

	placeholder := strings.Repeat("0", 2*pdfSignaturePlaceholderLength)
	signatureDict := fmt.Sprintf(
		"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /Contents <%s> /ByteRange [%s] /M (D:%s+00'00') >>",
		placeholder, pdfByteRangePlaceholder, time.Now().UTC().Format("20060102150405"))

	objects := []pdfObject{
		{number: catalogObject, body: newCatalog},
		{number: formObject, body: []byte(fmt.Sprintf("<< /Fields [ %d 0 R ] /SigFlags 3 >>", fieldObject))},
		{number: fieldObject, body: []byte(fmt.Sprintf("<< /FT /Sig /T (Signature1) /V %d 0 R >>", signatureObject))},
		{number: signatureObject, body: []byte(signatureDict)},
	}

	doc := new(bytes.Buffer)
	doc.Write(data)
	if !bytes.HasSuffix(data, []byte("\n")) {
		doc.WriteString("\n")
	}

	offsets := make([]int, len(objects))
	for i, object := range objects {
		offsets[i] = doc.Len()
		fmt.Fprintf(doc, "%d 0 obj\n", object.number)
		doc.Write(object.body)
		doc.WriteString("\nendobj\n")
	}

	xrefOffset := doc.Len()
	fmt.Fprintf(doc, "xref\n%d %d\n", catalogObject, len(objects))
	for _, offset := range offsets {
		fmt.Fprintf(doc, "%010d %05d n\r\n", offset, 0)
	}
	doc.WriteString("trailer\n<< ")
	fmt.Fprintf(doc, "/Size %d /Root %d 0 R /Prev %d ", signatureObject+1, catalogObject, trailer.StartXRef)
	if info, ok := pdfDictValue(trailer.Dict, "Info"); ok {
		fmt.Fprintf(doc, "/Info %s ", info)
	}
	if id, ok := pdfDictValue(trailer.Dict, "ID"); ok {
		fmt.Fprintf(doc, "/ID %s ", id)
	}
	doc.WriteString(">>\nstartxref\n")
	fmt.Fprintf(doc, "%d\n", xrefOffset)
	doc.WriteString("%%EOF\n")

	out := doc.Bytes()
	marker := []byte("/Contents <" + placeholder + ">")
	index := bytes.Index(out, marker)
	if index < 0 {
		return nil, errors.New("the signature placeholder was lost while the document was written")
	}
	contentStart := index + len("/Contents <")
	contentEnd := contentStart + len(placeholder)

	rangeIndex := bytes.Index(out, []byte(pdfByteRangePlaceholder))
	if rangeIndex < 0 {
		return nil, errors.New("the byte range placeholder was lost while the document was written")
	}
	bounds := [4]int{0, contentStart, contentEnd, len(out) - contentEnd}
	byteRange := fmt.Sprintf("%010d %010d %010d %010d", bounds[0], bounds[1], bounds[2], bounds[3])
	if len(byteRange) != len(pdfByteRangePlaceholder) {
		return nil, errors.New("the byte range of the signature does not fit the placeholder")
	}
	copy(out[rangeIndex:], byteRange)

	message := make([]byte, 0, bounds[1]+bounds[3])
	message = append(message, out[bounds[0]:bounds[0]+bounds[1]]...)
	message = append(message, out[bounds[2]:bounds[2]+bounds[3]]...)

	der, err := cmsDetached(message, signer)
	if err != nil {
		return nil, err
	}
	if len(der)*2 > len(placeholder) {
		return nil, errors.Errorf("the %d byte signature does not fit in the %d byte placeholder of the document", len(der), pdfSignaturePlaceholderLength)
	}
	hex.Encode(out[contentStart:], der)
	return out, nil
}

// verifyPDF verifies the signature of a PDF document.
func verifyPDF(data []byte) (*Signature, error) {
	message, contents, err := pdfSignatureContent(data)
	if err != nil {
		return nil, err
	}
	certificate, certificates, details, err := verifyDetachedCMS(contents, message)
	if err != nil {
		return nil, errors.Wrap(err, "Verify PDF signature")
	}
	return &Signature{
		Format:             PDF,
		Certificate:        certificate,
		Certificates:       certificates,
		SigningTime:        details.SigningTime,
		SignatureAlgorithm: details.SignatureAlgorithm,
	}, nil
}

// pdfSignatureContent returns the bytes the signature of a document covers and
// the CMS signature itself.
func pdfSignatureContent(data []byte) ([]byte, []byte, error) {
	rangeIndex := bytes.LastIndex(data, []byte("/ByteRange"))
	if rangeIndex < 0 {
		return nil, nil, errors.New("the PDF carries no signature")
	}
	rangeStart := rangeIndex + len("/ByteRange")
	relativeEnd := bytes.Index(data[rangeStart:], []byte("]"))
	if relativeEnd < 0 {
		return nil, nil, errors.New("the byte range of the PDF signature is not terminated")
	}
	fields := strings.Fields(strings.TrimPrefix(string(data[rangeStart:rangeStart+relativeEnd]), "["))
	if len(fields) != 4 {
		return nil, nil, errors.New("the byte range of the PDF signature does not hold four numbers")
	}
	bounds := [4]int{}
	for i, field := range fields {
		bounds[i] = pdfIntOf([]byte(field))
	}
	if bounds[0] != 0 || bounds[1] <= 0 || bounds[3] <= 0 {
		return nil, nil, errors.New("the byte range of the PDF signature is invalid")
	}
	if bounds[1] > len(data) || bounds[2] > len(data) || bounds[2]+bounds[3] > len(data) {
		return nil, nil, errors.New("the byte range of the PDF signature reaches past the end of the file")
	}

	// The contents are the string that follows the last /Contents of the
	// signature dictionary, which is the one that follows the last /Type of the
	// file.
	searchStart := bytes.LastIndex(data[:rangeIndex], []byte("/Type"))
	if searchStart < 0 {
		searchStart = 0
	}
	contentsIndex := -1
	if found := bytes.LastIndex(data[searchStart:rangeIndex], []byte("/Contents")); found >= 0 {
		contentsIndex = searchStart + found
	} else if found := bytes.LastIndex(data[:rangeIndex], []byte("/Contents")); found >= 0 {
		contentsIndex = found
	}
	if contentsIndex < 0 {
		return nil, nil, errors.New("the signature dictionary of the PDF has no contents")
	}
	open := bytes.IndexByte(data[contentsIndex:rangeIndex], '<')
	if open < 0 {
		return nil, nil, errors.New("the contents of the PDF signature are not a string")
	}
	open += contentsIndex + 1
	closeIndex := bytes.IndexByte(data[open:], '>')
	if closeIndex < 0 {
		return nil, nil, errors.New("the contents of the PDF signature are not terminated")
	}
	if bounds[1] < open-1 || bounds[2] > open+closeIndex+1 {
		return nil, nil, errors.New("the byte range of the PDF signature does not exclude the signature itself")
	}

	contents := make([]byte, hex.DecodedLen(closeIndex))
	decoded, err := hex.Decode(contents, data[open:open+closeIndex])
	if err != nil {
		return nil, nil, errors.Wrap(err, "Decode the signature of the PDF")
	}
	contents = contents[:decoded]

	message := make([]byte, 0, bounds[1]+bounds[3])
	message = append(message, data[bounds[0]:bounds[0]+bounds[1]]...)
	message = append(message, data[bounds[2]:bounds[2]+bounds[3]]...)
	return message, contents, nil
}

// cmsDetached returns a detached CMS signature over content, made with the key
// of the smart card.
func cmsDetached(content []byte, signer *Signer) ([]byte, error) {
	sd, err := cms.NewSignedData(content)
	if err != nil {
		return nil, errors.Wrap(err, "Create signed data")
	}
	if err := sd.Sign([]*x509.Certificate{signer.Certificate}, signer.Signer); err != nil {
		return nil, errors.Wrap(err, "Sign content")
	}
	sd.Detached()
	if err := sd.SetCertificates([]*x509.Certificate{signer.Certificate}); err != nil {
		return nil, errors.Wrap(err, "Set certificates in signature")
	}
	return sd.ToDER()
}
