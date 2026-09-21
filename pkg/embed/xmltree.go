package embed

import (
	"bytes"
	"encoding/xml"
	"io"
	"sort"
	"strings"

	"github.com/pkg/errors"
)

// xmlName is the qualified name of an element or attribute, as it is written.
// Space holds the namespace prefix (not the namespace URI), which is what the
// canonical form needs; it is empty for a name without a prefix.
type xmlName struct {
	Space string
	Local string
}

// qualified returns the name with its prefix, as it is written.
func (n xmlName) qualified() string {
	if n.Space == "" {
		return n.Local
	}
	return n.Space + ":" + n.Local
}

// nsDecl is a namespace declaration, an xmlns or xmlns:prefix attribute.
type nsDecl struct {
	Prefix string
	URI    string
}

// attr is an attribute that is not a namespace declaration.
type attr struct {
	Name  xmlName
	Value string
}

// element is an element of a parsed XML document.
type element struct {
	Name     xmlName
	NS       []nsDecl
	Attrs    []attr
	Children []any
}

// chardata is the character data of an element.
type chardata string

// procInst is a processing instruction.
type procInst struct {
	Target string
	Inst   string
}

// xmlNS is the namespace of the reserved xml prefix, which is always bound and
// never rendered as a declaration.
const xmlNS = "http://www.w3.org/XML/1998/namespace"

// parseXML parses a document into a list of top-level nodes.
func parseXML(data []byte) ([]any, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true

	var (
		roots []any
		stack []*element
	)
	for {
		token, err := decoder.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "Parse XML")
		}

		switch t := token.(type) {
		case xml.StartElement:
			child := &element{Name: xmlName{Space: t.Name.Space, Local: t.Name.Local}}
			for _, a := range t.Attr {
				decl, isDecl := namespaceDeclaration(a)
				if isDecl {
					if decl.Prefix == "xml" || decl.Prefix == "xmlns" {
						continue
					}
					child.NS = append(child.NS, decl)
					continue
				}
				child.Attrs = append(child.Attrs, attr{Name: xmlName{Space: a.Name.Space, Local: a.Name.Local}, Value: a.Value})
			}
			if len(stack) == 0 {
				roots = append(roots, child)
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, child)
			}
			stack = append(stack, child)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("unexpected end element in XML document")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			parent := stack[len(stack)-1]
			parent.Children = append(parent.Children, chardata(string(t)))
		case xml.ProcInst:
			// The XML declaration is not a processing instruction node, so it
			// is left out of the document that is canonicalized; it is written
			// again when the document is serialized.
			if t.Target == "xml" {
				continue
			}
			if len(stack) == 0 {
				roots = append(roots, procInst{Target: t.Target, Inst: string(t.Inst)})
			}
		}
	}
	if len(stack) != 0 {
		return nil, errors.New("unclosed element in XML document")
	}
	if len(roots) == 0 {
		return nil, errors.New("the XML document has no root element")
	}
	return roots, nil
}

// namespaceDeclaration reports whether a is a namespace declaration and returns
// it. An xmlns attribute declares the default namespace, an xmlns:prefix
// attribute declares the namespace of prefix.
func namespaceDeclaration(a xml.Attr) (nsDecl, bool) {
	switch {
	case a.Name.Space == "" && a.Name.Local == "xmlns":
		return nsDecl{URI: a.Value}, true
	case a.Name.Space == "xmlns":
		return nsDecl{Prefix: a.Name.Local, URI: a.Value}, true
	}
	return nsDecl{}, false
}

// rootElement returns the single root element of a document, or an error when
// the document has several roots.
func rootElement(roots []any) (*element, error) {
	var root *element
	for _, node := range roots {
		e, ok := node.(*element)
		if !ok {
			continue
		}
		if root != nil {
			return nil, errors.New("the XML document has more than one root element")
		}
		root = e
	}
	if root == nil {
		return nil, errors.New("the XML document has no root element")
	}
	return root, nil
}

// childElements returns the element children of e, in document order.
func childElements(e *element) []*element {
	var children []*element
	for _, child := range e.Children {
		if c, ok := child.(*element); ok {
			children = append(children, c)
		}
	}
	return children
}

// firstChild returns the first element child of e with the given local name, or
// nil when e has no such child.
func firstChild(e *element, local string) *element {
	for _, child := range childElements(e) {
		if child.Name.Local == local {
			return child
		}
	}
	return nil
}

// descendants returns e and every element below it, in document order.
func descendants(e *element) []*element {
	result := []*element{e}
	for _, child := range childElements(e) {
		result = append(result, descendants(child)...)
	}
	return result
}

// elementByID returns the element of the document whose Id or ID attribute is
// id, or nil when the document holds no such element.
func elementByID(root *element, id string) *element {
	for _, e := range descendants(root) {
		for _, a := range e.Attrs {
			if (a.Name.Local == "Id" || a.Name.Local == "ID") && a.Value == id {
				return e
			}
		}
	}
	return nil
}

// setText replaces the children of e with a single piece of character data.
func setText(e *element, text string) {
	e.Children = []any{chardata(text)}
}

// text returns the character data of e with the surrounding whitespace
// removed.
func text(e *element) string {
	var builder strings.Builder
	for _, child := range e.Children {
		if data, ok := child.(chardata); ok {
			builder.WriteString(string(data))
		}
	}
	return strings.TrimSpace(builder.String())
}

// appendChild appends an element to the children of parent.
func appendChild(parent, child *element) {
	parent.Children = append(parent.Children, child)
}

// insertChildBefore inserts child before the first element child of parent with
// the given local name, or appends it when parent has no such child.
func insertChildBefore(parent *element, name string, child *element) {
	for i, node := range parent.Children {
		if e, ok := node.(*element); ok && e.Name.Local == name {
			parent.Children = append(parent.Children, nil)
			copy(parent.Children[i+1:], parent.Children[i:])
			parent.Children[i] = child
			return
		}
	}
	appendChild(parent, child)
}

// removeChild removes the first element child of parent that is child and
// reports whether it was found.
func removeChild(parent, child *element) bool {
	for i, node := range parent.Children {
		if e, ok := node.(*element); ok && e == child {
			parent.Children = append(parent.Children[:i], parent.Children[i+1:]...)
			return true
		}
	}
	return false
}

// cloneXML returns a deep copy of an element, so that a document can be
// canonicalized without the signature it is about to receive.
func cloneXML(e *element) *element {
	clone := &element{Name: e.Name, NS: append([]nsDecl(nil), e.NS...), Attrs: append([]attr(nil), e.Attrs...)}
	for _, child := range e.Children {
		switch c := child.(type) {
		case *element:
			clone.Children = append(clone.Children, cloneXML(c))
		case chardata:
			clone.Children = append(clone.Children, c)
		case procInst:
			clone.Children = append(clone.Children, c)
		}
	}
	return clone
}

// cloneDocument returns a deep copy of a document.
func cloneDocument(roots []any) []any {
	clone := make([]any, 0, len(roots))
	for _, node := range roots {
		switch n := node.(type) {
		case *element:
			clone = append(clone, cloneXML(n))
		default:
			clone = append(clone, node)
		}
	}
	return clone
}

// canonicalize returns the exclusive canonical XML form (xml-exc-c14n) of a
// document.
func canonicalize(roots []any) []byte {
	buf := new(bytes.Buffer)
	inScope := map[string]string{"xml": xmlNS}
	for _, node := range roots {
		if e, ok := node.(*element); ok {
			inScope = scopeOf(e, inScope)
		}
		writeCanonicalNode(buf, node, inScope, map[string]string{})
	}
	return buf.Bytes()
}

// canonicalizeElement returns the exclusive canonical form of a single element
// and its descendants. inherited holds the namespace bindings that are visible
// at the element, including the ones it declares. The element is the root of
// the node-set, so a binding it utilizes is declared on it in the result even
// when it was declared on an ancestor.
func canonicalizeElement(e *element, inherited map[string]string) []byte {
	buf := new(bytes.Buffer)
	inScope := scopeOf(e, cloneScope(inherited))
	writeCanonicalNode(buf, e, inScope, map[string]string{})
	return buf.Bytes()
}

// scopeOf returns the bindings that are visible inside e, which are the ones it
// declares on top of the ones that are already in scope.
func scopeOf(e *element, inScope map[string]string) map[string]string {
	scope := cloneScope(inScope)
	for _, decl := range e.NS {
		scope[decl.Prefix] = decl.URI
	}
	return scope
}

// cloneScope copies a namespace binding map.
func cloneScope(scope map[string]string) map[string]string {
	clone := make(map[string]string, len(scope))
	for prefix, uri := range scope {
		clone[prefix] = uri
	}
	return clone
}

func writeCanonicalNode(buf *bytes.Buffer, node any, inScope, rendered map[string]string) {
	switch n := node.(type) {
	case chardata:
		writeEscapedText(buf, string(n))
	case procInst:
		buf.WriteString("<?")
		buf.WriteString(n.Target)
		if n.Inst != "" {
			buf.WriteByte(' ')
			buf.WriteString(n.Inst)
		}
		buf.WriteString("?>")
	case *element:
		writeCanonicalElement(buf, n, inScope, rendered)
	}
}

// writeCanonicalElement writes the exclusive canonical form of an element. Only
// the namespace bindings that the element visibly utilizes, or declares itself,
// are written, and a binding that an output ancestor already wrote with the
// same value is left out.
func writeCanonicalElement(buf *bytes.Buffer, e *element, inScope, rendered map[string]string) {
	// A prefix is visibly utilized when the qualified name of the element or of
	// one of its attributes carries it. An attribute without a prefix is in no
	// namespace, so it does not utilize the default namespace.
	utilized := map[string]bool{}
	if e.Name.Space == "" {
		utilized[""] = true
	} else {
		utilized[e.Name.Space] = true
	}
	for _, a := range e.Attrs {
		if a.Name.Space != "" {
			utilized[a.Name.Space] = true
		}
	}

	var toRender []nsDecl
	for prefix, uri := range inScope {
		if prefix == "xml" {
			continue
		}
		// Exclusive canonicalization renders a namespace declaration only when
		// the element actually uses the prefix, so a declaration that an
		// ancestor made for a descendant, or one that is not used at all, is
		// left out.
		if !utilized[prefix] {
			continue
		}
		if previous, ok := rendered[prefix]; ok && previous == uri {
			continue
		}
		toRender = append(toRender, nsDecl{Prefix: prefix, URI: uri})
	}
	sort.SliceStable(toRender, func(i, j int) bool {
		if (toRender[i].Prefix == "") != (toRender[j].Prefix == "") {
			return toRender[i].Prefix == ""
		}
		return toRender[i].Prefix < toRender[j].Prefix
	})

	buf.WriteByte('<')
	buf.WriteString(e.Name.qualified())
	for _, decl := range toRender {
		if decl.Prefix == "" {
			buf.WriteString(` xmlns="`)
		} else {
			buf.WriteString(` xmlns:` + decl.Prefix + `="`)
		}
		buf.WriteString(escapeAttribute(decl.URI))
		buf.WriteByte('"')
	}

	for _, a := range attributesInCanonicalOrder(e, inScope) {
		buf.WriteByte(' ')
		buf.WriteString(a.Name.qualified())
		buf.WriteString(`="`)
		buf.WriteString(escapeAttribute(a.Value))
		buf.WriteByte('"')
	}
	buf.WriteByte('>')

	childRendered := cloneScope(rendered)
	for _, decl := range toRender {
		childRendered[decl.Prefix] = decl.URI
	}
	for _, child := range e.Children {
		writeCanonicalNode(buf, child, inScope, childRendered)
	}

	buf.WriteString("</")
	buf.WriteString(e.Name.qualified())
	buf.WriteByte('>')
}

// attributesInCanonicalOrder returns the attributes of an element sorted by
// namespace URI and then by local name, as the canonical form requires. The
// namespace URI of an attribute is the one its prefix is bound to in scope.
func attributesInCanonicalOrder(e *element, inScope map[string]string) []attr {
	attrs := append([]attr(nil), e.Attrs...)
	namespaceOf := func(a attr) string {
		if a.Name.Space == "" {
			return ""
		}
		if a.Name.Space == "xml" {
			return xmlNS
		}
		return inScope[a.Name.Space]
	}
	sort.SliceStable(attrs, func(i, j int) bool {
		left, right := namespaceOf(attrs[i]), namespaceOf(attrs[j])
		if left != right {
			return left < right
		}
		return attrs[i].Name.Local < attrs[j].Name.Local
	})
	return attrs
}

// writeEscapedText writes character data with the escapes the canonical form
// requires.
func writeEscapedText(buf *bytes.Buffer, text string) {
	for _, r := range text {
		switch r {
		case '&':
			buf.WriteString("&amp;")
		case '<':
			buf.WriteString("&lt;")
		case '\r':
			buf.WriteString("&#xD;")
		default:
			buf.WriteRune(r)
		}
	}
}

// escapeAttribute returns an attribute value with the escapes the canonical
// form requires.
func escapeAttribute(value string) string {
	var buf bytes.Buffer
	for _, r := range value {
		switch r {
		case '&':
			buf.WriteString("&amp;")
		case '<':
			buf.WriteString("&lt;")
		case '"':
			buf.WriteString("&quot;")
		case '\t':
			buf.WriteString("&#x9;")
		case '\n':
			buf.WriteString("&#xA;")
		case '\r':
			buf.WriteString("&#xD;")
		default:
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

// serialize writes the nodes back as XML. Prefixes and namespace declarations
// are kept as they were parsed, so that the document is not rearranged when it
// is written back with its signature.
func serialize(w io.Writer, nodes []any) error {
	for _, node := range nodes {
		if err := serializeNode(w, node); err != nil {
			return err
		}
	}
	return nil
}

func serializeNode(w io.Writer, node any) error {
	switch n := node.(type) {
	case chardata:
		_, err := io.WriteString(w, escapeText(string(n)))
		return err
	case procInst:
		if _, err := io.WriteString(w, "<?"+n.Target); err != nil {
			return err
		}
		if n.Inst != "" {
			if _, err := io.WriteString(w, " "+n.Inst); err != nil {
				return err
			}
		}
		_, err := io.WriteString(w, "?>")
		return err
	case *element:
		if _, err := io.WriteString(w, "<"+n.Name.qualified()); err != nil {
			return err
		}
		for _, decl := range n.NS {
			name := "xmlns"
			if decl.Prefix != "" {
				name = "xmlns:" + decl.Prefix
			}
			if _, err := io.WriteString(w, " "+name+`="`+escapeAttribute(decl.URI)+`"`); err != nil {
				return err
			}
		}
		for _, a := range n.Attrs {
			if _, err := io.WriteString(w, " "+a.Name.qualified()+`="`+escapeAttribute(a.Value)+`"`); err != nil {
				return err
			}
		}
		if len(n.Children) == 0 {
			_, err := io.WriteString(w, "></"+n.Name.qualified()+">")
			return err
		}
		if _, err := io.WriteString(w, ">"); err != nil {
			return err
		}
		for _, child := range n.Children {
			if err := serializeNode(w, child); err != nil {
				return err
			}
		}
		_, err := io.WriteString(w, "</"+n.Name.qualified()+">")
		return err
	}
	return nil
}

// escapeText escapes the characters that may not appear literally in character
// data.
func escapeText(text string) string {
	var buf bytes.Buffer
	for _, r := range text {
		switch r {
		case '&':
			buf.WriteString("&amp;")
		case '<':
			buf.WriteString("&lt;")
		default:
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

// parseElement parses a single element from XML text.
func parseElement(xmlText string) (*element, error) {
	roots, err := parseXML([]byte(xmlText))
	if err != nil {
		return nil, err
	}
	return rootElement(roots)
}

// xmlDocument returns the bytes of an XML document that holds an XML
// declaration followed by the given root element.
func xmlDocument(root *element) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n")
	if err := serialize(buf, []any{root}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
