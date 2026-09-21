// Package cms implements the subset of the Cryptographic Message Syntax
// (RFC 5652) and of the RFC 3161 timestamping protocol that pivzavr needs to
// create and verify S/MIME signatures.
//
// The implementation is intentionally small: it supports the SignedData
// content type of type id-data, issuerAndSerialNumber and subjectKeyIdentifier
// signer identifiers, the mandatory signed attributes, and the SHA-2 family of
// digest algorithms. It does not implement encryption, countersignatures or
// revocation checking.
package cms
