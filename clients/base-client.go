package clients

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"dnsperf/metrics"
	"dnsperf/util"
	"errors"
	"fmt"
	"github.com/joomcode/errorx"
	"golang.org/x/net/http2"
	"log"
	"net"
	"net/url"
	"time"
)

// RootCAs is the CertPool that must be used by all upstreams
// Redefining RootCAs makes sense on iOS to overcome the 15MB memory limit of the NEPacketTunnelProvider
// nolint
var RootCAs *x509.CertPool

// CipherSuites - custom list of TLSv1.2 ciphers
// nolint
var CipherSuites []uint16

type baseClient struct {
	URL               *url.URL
	resolvedConfig    *tls.Config
	resolvedAddresses []string

	options Options
}

func newBaseClient(upsURL *url.URL, options Options) (*baseClient, error) {
	host, port, err := net.SplitHostPort(upsURL.Host)
	if err != nil {
		return nil, fmt.Errorf("baseClient requires port in address %s", upsURL.String())
	}

	var resolverAddresses []string
	if len(options.ServerIPAddrs) != 0 {
		for _, ip := range options.ServerIPAddrs {
			addr := net.JoinHostPort(ip.String(), port)
			resolverAddresses = append(resolverAddresses, addr)
		}
	} else {
		resolverAddresses, err = util.ResolveURLToIP(upsURL)
		if err != nil {
			return nil, err
		}
	}

	c := &baseClient{
		URL:               upsURL,
		options:           options,
		resolvedAddresses: resolverAddresses,
	}

	c.resolvedConfig = c.getTLSConfig(host)

	return c, nil
}

func (c *baseClient) handleTLSError(err error, collector *metrics.Collector) {
	x509error := &x509.CertificateInvalidError{}
	converted := errors.As(err, x509error)
	if converted {
		collector.TLSError(x509error.Reason)
	}
}

func (c *baseClient) getTLSDialContext(collector *metrics.Collector) dialHandler {
	return func(context context.Context, network string, addr string) (net.Conn, error) {
		tlsConfig := c.resolvedConfig
		dialContext := c.getDialContext(collector)

		rawConn, err := dialContext(context, "tcp", "")
		if err != nil {
			return nil, err
		}

		// we want the timeout to cover the whole process: TCP connection and TLS handshake
		// dialTimeout will be used as connection deadLine
		conn := tls.Client(rawConn, tlsConfig)
		err = conn.SetDeadline(time.Now().Add(dialTimeout))
		if err != nil {
			log.Printf("DeadLine is not supported cause: %s", err)
			conn.Close()
			return nil, err
		}

		collector.TLSHandshakeStart()
		err = conn.Handshake()
		collector.TLSHandshakeFinished(conn.ConnectionState().Version)
		if err != nil {
			conn.Close()
			c.handleTLSError(err, collector)
			return nil, err
		}

		return conn, nil
	}
}

// dialHandler specifies the dial function for creating unencrypted TCP connections.
type dialHandler func(ctx context.Context, network, addr string) (net.Conn, error)

func (c *baseClient) getDialContext(collector *metrics.Collector) (dialContext dialHandler) {
	dialer := &net.Dialer{
		Timeout: c.options.Timeout,
	}

	start := func(network string) {
		if collector == nil {
			return
		}
		switch network {
		case "tcp":
			collector.TCPHandshakeStart()
		case "udp":
			collector.UDPSocketSetupStart()
		}
	}

	stop := func(network string) {
		if collector == nil {
			return
		}
		switch network {
		case "tcp":
			collector.TCPHandshakeFinished()
		case "udp":
			collector.UDPSocketSetupFinished()
		}
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		errs := []error{}

		// Return first connection without error
		// Note that we're using bootstrapped resolverAddress instead of what's passed to the function
		for _, resolverAddress := range c.resolvedAddresses {
			start(network)
			con, err := dialer.DialContext(ctx, network, resolverAddress)
			if err == nil {
				stop(network)
				return con, err
			}
			errs = append(errs, err)
		}

		if len(errs) == 0 {
			return nil, fmt.Errorf("all dialers failed to initialize connection")
		}
		return nil, errorx.DecorateMany("all dialers failed to initialize connection: ", errs...)
	}
}

func (c *baseClient) skipHostnameVerification(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return fmt.Errorf("tls: failed to parse server certificate error: %s", err.Error())
		}
		certs[i] = cert
	}

	if c.resolvedConfig.RootCAs == nil {
		return nil
	}

	// Verify certs if they exist but skip ServerName validation
	opts := x509.VerifyOptions{
		Roots:         c.resolvedConfig.RootCAs,
		CurrentTime:   time.Now(),
		DNSName:       "", // skip hostname verification
		Intermediates: x509.NewCertPool(),
	}

	for i, cert := range certs {
		if i == 0 {
			continue
		}
		opts.Intermediates.AddCert(cert)
	}
	_, err := certs[0].Verify(opts)
	return err
}

func (c *baseClient) getTLSConfig(host string) *tls.Config {
	tlsConfig := &tls.Config{
		ServerName:   host,
		RootCAs:      RootCAs,
		CipherSuites: CipherSuites,
	}

	if c.options.TLSOptions != nil {
		tlsConfig.MinVersion = c.options.TLSOptions.MinVersion
		tlsConfig.MaxVersion = c.options.TLSOptions.MaxVersion
		tlsConfig.InsecureSkipVerify = c.options.TLSOptions.InsecureSkipVerify

		if c.options.TLSOptions.SkipCommonName {
			tlsConfig.VerifyPeerCertificate = c.skipHostnameVerification
		}
	}

	// The supported application level protocols should be specified only
	// for DNS-over-HTTPS and DNS-over-QUIC connections.
	//
	// See https://github.com/AdguardTeam/AdGuardHome/issues/2681.
	if c.URL.Scheme == "https" {
		tlsConfig.NextProtos = []string{
			"http/1.1", http2.NextProtoTLS,
		}
	} else if c.URL.Scheme == "quic" {
		if c.options.QuicOptions != nil {
			tlsConfig.NextProtos = append(c.options.QuicOptions.AllowedVersions, []string{"http/1.1", http2.NextProtoTLS}...)
		}
	}

	return tlsConfig
}
