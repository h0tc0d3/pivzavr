package pcsc

import (
	"errors"
	"fmt"
)

// Error is a status code returned by the PC/SC smart card service. The values
// are the ones defined by the PC/SC specification, so they can be compared
// against the exported codes of this package.
type Error uint32

// PC/SC status codes. ErrSuccess is not an error and is never returned as one;
// it is kept so that the whole set of codes of a PC/SC implementation is
// available to callers.
const (
	ErrSuccess                Error = 0x00000000
	ErrInternalError          Error = 0x80100001
	ErrCancelled              Error = 0x80100002
	ErrInvalidHandle          Error = 0x80100003
	ErrInvalidParameter       Error = 0x80100004
	ErrInvalidTarget          Error = 0x80100005
	ErrNoMemory               Error = 0x80100006
	ErrWaitedTooLong          Error = 0x80100007
	ErrInsufficientBuffer     Error = 0x80100008
	ErrUnknownReader          Error = 0x80100009
	ErrTimeout                Error = 0x8010000A
	ErrSharingViolation       Error = 0x8010000B
	ErrNoSmartcard            Error = 0x8010000C
	ErrUnknownCard            Error = 0x8010000D
	ErrCantDispose            Error = 0x8010000E
	ErrProtoMismatch          Error = 0x8010000F
	ErrNotReady               Error = 0x80100010
	ErrInvalidValue           Error = 0x80100011
	ErrSystemCancelled        Error = 0x80100012
	ErrCommError              Error = 0x80100013
	ErrUnknownError           Error = 0x80100014
	ErrInvalidAtr             Error = 0x80100015
	ErrNotTransacted          Error = 0x80100016
	ErrReaderUnavailable      Error = 0x80100017
	ErrShutdown               Error = 0x80100018
	ErrPciTooSmall            Error = 0x80100019
	ErrReaderUnsupported      Error = 0x8010001A
	ErrDuplicateReader        Error = 0x8010001B
	ErrCardUnsupported        Error = 0x8010001C
	ErrNoService              Error = 0x8010001D
	ErrServiceStopped         Error = 0x8010001E
	ErrUnexpected             Error = 0x8010001F
	ErrIccInstallation        Error = 0x80100020
	ErrIccCreateOrder         Error = 0x80100021
	ErrFileNotFound           Error = 0x80100024
	ErrNoDir                  Error = 0x80100025
	ErrNoFile                 Error = 0x80100026
	ErrNoAccess               Error = 0x80100027
	ErrWriteTooMany           Error = 0x80100028
	ErrBadSeek                Error = 0x80100029
	ErrInvalidChv             Error = 0x8010002A
	ErrUnknownResMng          Error = 0x8010002B
	ErrNoSuchCertificate      Error = 0x8010002C
	ErrCertificateUnavailable Error = 0x8010002D
	ErrNoReadersAvailable     Error = 0x8010002E
	ErrCommDataLost           Error = 0x8010002F
	ErrNoKeyContainer         Error = 0x80100030
	ErrServerTooBusy          Error = 0x80100031
	ErrUnsupportedCard        Error = 0x80100065
	ErrUnresponsiveCard       Error = 0x80100066
	ErrUnpoweredCard          Error = 0x80100067
	ErrResetCard              Error = 0x80100068
	ErrRemovedCard            Error = 0x80100069
	ErrSecurityViolation      Error = 0x8010006A
	ErrWrongChv               Error = 0x8010006B
	ErrChvBlocked             Error = 0x8010006C
	ErrEOF                    Error = 0x8010006D
	ErrCancelledByUser        Error = 0x8010006E
	ErrCardNotAuthenticated   Error = 0x8010006F
)

// errorNames maps the error codes to their PC/SC names, which is what the
// string form of an Error reports.
var errorNames = map[Error]string{
	ErrSuccess:                "SCARD_S_SUCCESS",
	ErrInternalError:          "SCARD_F_INTERNAL_ERROR",
	ErrCancelled:              "SCARD_E_CANCELLED",
	ErrInvalidHandle:          "SCARD_E_INVALID_HANDLE",
	ErrInvalidParameter:       "SCARD_E_INVALID_PARAMETER",
	ErrInvalidTarget:          "SCARD_E_INVALID_TARGET",
	ErrNoMemory:               "SCARD_E_NO_MEMORY",
	ErrWaitedTooLong:          "SCARD_F_WAITED_TOO_LONG",
	ErrInsufficientBuffer:     "SCARD_E_INSUFFICIENT_BUFFER",
	ErrUnknownReader:          "SCARD_E_UNKNOWN_READER",
	ErrTimeout:                "SCARD_E_TIMEOUT",
	ErrSharingViolation:       "SCARD_E_SHARING_VIOLATION",
	ErrNoSmartcard:            "SCARD_E_NO_SMARTCARD",
	ErrUnknownCard:            "SCARD_E_UNKNOWN_CARD",
	ErrCantDispose:            "SCARD_E_CANT_DISPOSE",
	ErrProtoMismatch:          "SCARD_E_PROTO_MISMATCH",
	ErrNotReady:               "SCARD_E_NOT_READY",
	ErrInvalidValue:           "SCARD_E_INVALID_VALUE",
	ErrSystemCancelled:        "SCARD_E_SYSTEM_CANCELLED",
	ErrCommError:              "SCARD_F_COMM_ERROR",
	ErrUnknownError:           "SCARD_F_UNKNOWN_ERROR",
	ErrInvalidAtr:             "SCARD_E_INVALID_ATR",
	ErrNotTransacted:          "SCARD_E_NOT_TRANSACTED",
	ErrReaderUnavailable:      "SCARD_E_READER_UNAVAILABLE",
	ErrShutdown:               "SCARD_P_SHUTDOWN",
	ErrPciTooSmall:            "SCARD_E_PCI_TOO_SMALL",
	ErrReaderUnsupported:      "SCARD_E_READER_UNSUPPORTED",
	ErrDuplicateReader:        "SCARD_E_DUPLICATE_READER",
	ErrCardUnsupported:        "SCARD_E_CARD_UNSUPPORTED",
	ErrNoService:              "SCARD_E_NO_SERVICE",
	ErrServiceStopped:         "SCARD_E_SERVICE_STOPPED",
	ErrUnexpected:             "SCARD_E_UNEXPECTED",
	ErrIccInstallation:        "SCARD_E_ICC_INSTALLATION",
	ErrIccCreateOrder:         "SCARD_E_ICC_CREATEORDER",
	ErrFileNotFound:           "SCARD_E_FILE_NOT_FOUND",
	ErrNoDir:                  "SCARD_E_NO_DIR",
	ErrNoFile:                 "SCARD_E_NO_FILE",
	ErrNoAccess:               "SCARD_E_NO_ACCESS",
	ErrWriteTooMany:           "SCARD_E_WRITE_TOO_MANY",
	ErrBadSeek:                "SCARD_E_BAD_SEEK",
	ErrInvalidChv:             "SCARD_E_INVALID_CHV",
	ErrUnknownResMng:          "SCARD_E_UNKNOWN_RES_MNG",
	ErrNoSuchCertificate:      "SCARD_E_NO_SUCH_CERTIFICATE",
	ErrCertificateUnavailable: "SCARD_E_CERTIFICATE_UNAVAILABLE",
	ErrNoReadersAvailable:     "SCARD_E_NO_READERS_AVAILABLE",
	ErrCommDataLost:           "SCARD_E_COMM_DATA_LOST",
	ErrNoKeyContainer:         "SCARD_E_NO_KEY_CONTAINER",
	ErrServerTooBusy:          "SCARD_E_SERVER_TOO_BUSY",
	ErrUnsupportedCard:        "SCARD_W_UNSUPPORTED_CARD",
	ErrUnresponsiveCard:       "SCARD_W_UNRESPONSIVE_CARD",
	ErrUnpoweredCard:          "SCARD_W_UNPOWERED_CARD",
	ErrResetCard:              "SCARD_W_RESET_CARD",
	ErrRemovedCard:            "SCARD_W_REMOVED_CARD",
	ErrSecurityViolation:      "SCARD_W_SECURITY_VIOLATION",
	ErrWrongChv:               "SCARD_W_WRONG_CHV",
	ErrChvBlocked:             "SCARD_W_CHV_BLOCKED",
	ErrEOF:                    "SCARD_W_EOF",
	ErrCancelledByUser:        "SCARD_W_CANCELLED_BY_USER",

	ErrCardNotAuthenticated: "SCARD_W_CARD_NOT_AUTHENTICATED",
}

// Name returns the PC/SC name of the error, or an empty string when the code
// is not one that this package knows.
func (e Error) Name() string {
	return errorNames[e]
}

// Error implements error. The message names the status code, which is what the
// string forms of the PC/SC implementations report, so that a failure can be
// looked up in the specification.
func (e Error) Error() string {
	if name := errorNames[e]; name != "" {
		return "pcsc: " + name
	}
	return fmt.Sprintf("pcsc: unknown error 0x%08X", uint32(e))
}

// isNoReader reports whether err says that no smart card reader is present. A
// system that has no reader at all answers a reader list call with this code
// instead of an empty list, so it is treated as one.
func isNoReader(err error) bool {
	var code Error
	return errors.As(err, &code) && code == ErrNoReadersAvailable
}

// scardError converts the status code a PC/SC call returned to an error. A
// successful call reports nil, so callers can return it unchanged.
func scardError(code int32) error {
	if code == 0 {
		return nil
	}
	// The error codes of PC/SC are 32-bit values that are larger than the
	// largest int32, so they arrive here as negative numbers and take their
	// meaning back from the widening to uint32.
	return Error(uint32(code)) // #nosec G115 -- the code is a 32-bit PC/SC status word.
}
