package pivzavr

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// FormatCertificate returns a human-readable view of the certificate described
// by output: the slot, fingerprint, subject, issuer, serial number and validity
// period, followed by the PEM-encoded certificate.
func FormatCertificate(output *CertificateOutput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Slot:          %s (%s)\n", output.Slot, output.Slot.Description())
	fmt.Fprintf(&b, "Fingerprint:   %s\n", output.Fingerprint)
	if output.Certificate != nil {
		cert := output.Certificate
		fmt.Fprintf(&b, "Serial Number: %x\n", cert.SerialNumber)
		fmt.Fprintf(&b, "Key Type:      %s\n", CertKeyType(cert))
		fmt.Fprintf(&b, "Not Before:    %s\n", formatTime(cert.NotBefore))
		fmt.Fprintf(&b, "Not After:     %s\n", formatTime(cert.NotAfter))
		fmt.Fprintf(&b, "Subject DN:    %s\n", formatName(cert.Subject))
		fmt.Fprintf(&b, "Issuer DN:     %s\n\n", formatName(cert.Issuer))
	}
	b.WriteString(output.CertificatePem)
	b.WriteString("\n")
	return b.String()
}

// CertKeyType returns a human-readable description of the certificate's key
// type (e.g. "RSA 2048", "ECDSA NIST P-256", "Ed25519").
func CertKeyType(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		if pub.Curve != nil {
			if curve := ecdsaCurveName(pub.Curve); curve != "" {
				return fmt.Sprintf("ECDSA %s", curve)
			}
		}
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	}

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.DSA:
		return "DSA"
	case x509.Ed25519:
		return "Ed25519"
	}

	return "Unknown"
}

// ecdsaCurveName returns a human-readable name for an ECDSA curve, prefixed
// with the standard that defines it. NIST curves from FIPS 186 are rendered
// as "NIST P-256", SECG curves from SEC 2 as "SECG secp256r1", and Brainpool
// curves from RFC 5639 as "Brainpool brainpoolP256r1". Curves that do not
// match a known family keep their reported name unchanged.
func ecdsaCurveName(curve elliptic.Curve) string {
	params := curve.Params()
	if params == nil {
		return ""
	}

	switch params.Name {
	case "P-224", "P-256", "P-384", "P-521":
		return "NIST " + params.Name
	}

	if strings.HasPrefix(params.Name, "secp") || strings.HasPrefix(params.Name, "sect") {
		return "SECG " + params.Name
	}
	if strings.HasPrefix(params.Name, "brainpool") {
		return "Brainpool " + params.Name
	}
	return params.Name
}

// oidNames maps distinguished-name attribute OIDs to their conventional
// short names. Attributes without an entry here are rendered using the
// dotted-decimal OID.
var oidNames = map[string]string{
	// X.520 / RFC 4519 attribute types.
	"2.5.4.3":  "CN",
	"2.5.4.4":  "SN",
	"2.5.4.5":  "SERIALNUMBER",
	"2.5.4.6":  "C",
	"2.5.4.7":  "L",
	"2.5.4.8":  "ST",
	"2.5.4.9":  "STREET",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.12": "T",
	"2.5.4.13": "DESCRIPTION",
	"2.5.4.14": "SEARCHGUIDE",
	"2.5.4.15": "BUSINESSCATEGORY",
	"2.5.4.16": "POSTALADDRESS",
	"2.5.4.17": "POSTALCODE",
	"2.5.4.18": "POSTOFFICEBOX",
	"2.5.4.20": "TELEPHONENUMBER",
	"2.5.4.41": "NAME",
	"2.5.4.42": "GN",
	"2.5.4.43": "INITIALS",
	"2.5.4.44": "GENERATIONQUALIFIER",
	"2.5.4.45": "X500UNIQUEIDENTIFIER",
	"2.5.4.46": "DNQUALIFIER",
	"2.5.4.65": "PSEUDONYM",
	"2.5.4.72": "ROLE",
	// PKCS#9 email address.
	"1.2.840.113549.1.9.1": "emailAddress",
	// RFC 4519 friendly names.
	"0.9.2342.19200300.100.1.1":  "UID",
	"0.9.2342.19200300.100.1.3":  "mail",
	"0.9.2342.19200300.100.1.25": "DC",
}

// formatName returns a human-readable rendering of a distinguished name.
// pkix.Name.String renders attributes with unrecognized OIDs as hex-encoded
// DER values; formatName instead resolves OIDs to their conventional names and
// prints decoded attribute values.
func formatName(name pkix.Name) string {
	rdns := nameRDNSequence(name)
	var b strings.Builder
	for i := 0; i < len(rdns); i++ {
		rdn := rdns[len(rdns)-1-i]
		if i > 0 {
			b.WriteByte(',')
		}
		for j, atv := range rdn {
			if j > 0 {
				b.WriteByte('+')
			}
			b.WriteString(oidName(atv.Type))
			b.WriteByte('=')
			b.WriteString(escapeNameValue(attributeValue(atv.Value)))
		}
	}
	return b.String()
}

// nameRDNSequence returns the RDN sequence represented by name, including
// attributes that only appear in name.Names. pkix.Name.ToRDNSequence drops
// attributes that were not parsed into one of the named fields.
func nameRDNSequence(name pkix.Name) pkix.RDNSequence {
	var rdns pkix.RDNSequence
	if name.ExtraNames == nil {
		for _, atv := range name.Names {
			t := atv.Type
			if len(t) == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
				switch t[3] {
				case 3, 5, 6, 7, 8, 9, 10, 11, 17:
					continue
				}
			}
			rdns = append(rdns, []pkix.AttributeTypeAndValue{atv})
		}
	}
	rdns = append(rdns, name.ToRDNSequence()...)
	return rdns
}

func oidName(oid asn1.ObjectIdentifier) string {
	if name, ok := oidNames[oid.String()]; ok {
		return name
	}
	return oid.String()
}

// attributeValue returns a printable representation of an RDN attribute value.
// Parsed names store string values, but manually constructed names may use raw
// bytes that need decoding before they can be displayed.
func attributeValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		if utf8.Valid(v) {
			return string(v)
		}
		return "#" + hex.EncodeToString(v)
	default:
		return fmt.Sprint(value)
	}
}

// escapeNameValue escapes characters that have special meaning in an
// RFC 4514-style distinguished name string.
func escapeNameValue(value string) string {
	escaped := make([]rune, 0, len(value))
	for i, c := range value {
		escape := false
		switch c {
		case ',', '+', '"', '\\', '<', '>', ';':
			escape = true
		case ' ':
			escape = i == 0 || i == len(value)-1
		case '#':
			escape = i == 0
		}
		if escape {
			escaped = append(escaped, '\\', c)
		} else {
			escaped = append(escaped, c)
		}
	}
	return string(escaped)
}

// formatTime renders a certificate validity timestamp in UTC.
func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05 MST")
}

// unavailableIfEmpty returns value, or a placeholder when value is empty.
func unavailableIfEmpty(value string) string {
	if value == "" {
		return "(unavailable)"
	}
	return value
}

// formatRetries renders a retry count, or a placeholder when the count is
// unknown.
func formatRetries(retries int) string {
	if retries < 0 {
		return "(unavailable)"
	}
	return strconv.Itoa(retries)
}

// FormatDeviceInfo returns a human-readable view of a smart card: its name,
// firmware version, serial number, PIV data objects and the certificates
// stored in its active slots.
func FormatDeviceInfo(info *DeviceInfo) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Name:        %s\n", info.Name)
	fmt.Fprintf(&b, "Firmware:    %s\n", info.FirmwareVersion)
	fmt.Fprintf(&b, "Serial:      %s\n", info.SerialNumber)
	fmt.Fprintf(&b, "CHUID:       %s\n", unavailableIfEmpty(info.CHUID))
	fmt.Fprintf(&b, "CCC:         %s\n", unavailableIfEmpty(info.CCC))
	fmt.Fprintf(&b, "PIN Retries: %s\n", formatRetries(info.PinRetries))
	fmt.Fprintf(&b, "PUK Retries: %s\n", formatRetries(info.PukRetries))

	if len(info.Slots) == 0 {
		return b.String()
	}
	b.WriteString("\n")
	for _, s := range info.Slots {
		b.WriteString(FormatSlot(s.Slot, s.Certificate))
	}
	return b.String()
}

// FormatSlot returns a human-readable view of the certificate stored in slot:
// the slot description, the certificate fingerprint, key type, subject and
// issuer distinguished names and its validity period.
func FormatSlot(slot Slot, cert *x509.Certificate) string {
	return fmt.Sprintf(
		"Slot: %s (%s)\n  Fingerprint: %s\n  Key Type: %s\n"+
			"  Subject DN: %s\n  Issuer DN: %s\n  Not Before: %s\n  Not After: %s\n\n",
		slot,
		slot.Description(),
		CertHexFingerprint(cert),
		CertKeyType(cert),
		formatName(cert.Subject),
		formatName(cert.Issuer),
		formatTime(cert.NotBefore),
		formatTime(cert.NotAfter),
	)
}
