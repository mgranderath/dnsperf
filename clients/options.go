package clients

import (
	"github.com/lucas-clemente/quic-go"
	"net"
	"time"
)

type TLSOptions struct {
	// MinVersion the minimum TLS version to use
	MinVersion uint16

	// MaxVersion the maximum TLS version to use
	MaxVersion uint16

	// InsecureSkipVerify - if true, do not verify the server certificate
	InsecureSkipVerify bool

	// SkipCommonName - if true, do not verify the server hostname, has to be used in combination with InsecureSkipVerify false
	SkipCommonName bool
}

type QuicOptions struct {
	AllowedVersions *[]DoQVersion
	TokenStore quic.TokenStore
}

type Options struct {
	// Timeout is the default upstream timeout. Also, it is used as a timeout for bootstrap DNS requests.
	// timeout=0 means infinite timeout.
	Timeout time.Duration

	// List of IP addresses of upstream DNS server
	// Bootstrap DNS servers won't be used at all
	ServerIPAddrs []net.IP

	// TLSOptions can be used to specify the TLS versions to be allowed
	TLSOptions *TLSOptions

	// QuicOptions can be used to specify the QUIC versions to be allowed
	QuicOptions *QuicOptions
}
