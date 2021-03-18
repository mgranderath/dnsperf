package terr

type ErrorCode uint64

const (
	UnexpectedMessage    ErrorCode = 10
	BadRecordMac         ErrorCode = 20
	DecryptionFailed     ErrorCode = 21
	RecordOverflow       ErrorCode = 22
	DecompressionFail    ErrorCode = 30
	HandshakeFailure     ErrorCode = 40
	BadCertificate       ErrorCode = 42
	UnsupportedCert      ErrorCode = 43
	CertificateRevoked   ErrorCode = 44
	CertificateExpired   ErrorCode = 45
	CertificateUnknown   ErrorCode = 46
	UnknownCA            ErrorCode = 48
	AccessDenied         ErrorCode = 49
	DecodeError          ErrorCode = 50
	DecryptError         ErrorCode = 51
	ExportRestriction    ErrorCode = 60
	ProtocolVersion      ErrorCode = 70
	InsufficientSecurity ErrorCode = 71
	InternalError        ErrorCode = 80
	UserCancelled        ErrorCode = 90
	NoRenogiation        ErrorCode = 100
	UnsupportedExt       ErrorCode = 110
)
