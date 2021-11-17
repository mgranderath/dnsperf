package clients

import (
	"context"
	"errors"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
	"github.com/Lucapaulo/dnsperf/metrics"
	"github.com/Lucapaulo/dnsperf/qerr"
	"github.com/miekg/dns"
	"io"
	"net"
	"reflect"
	"sync"
	"time"
)

type DoQVersion string

const (
	VersionDoQ00 DoQVersion = "doq-i00"
	VersionDoQ01 DoQVersion = "doq-i01"
	VersionDoQ02 DoQVersion = "doq-i02"
	VersionDoQ03 DoQVersion = "doq-i03"
	VersionDoQ04 DoQVersion = "doq-i04"
	VersionDoQ05 DoQVersion = "doq-i05"
	VersionDoQ06 DoQVersion = "doq-i06"
)

var defaultDoQVersions = []DoQVersion{VersionDoQ06, VersionDoQ05, VersionDoQ04, VersionDoQ03, VersionDoQ02, VersionDoQ01, VersionDoQ00}

const handshakeTimeout = time.Second * 2

type DoQClient struct {
	baseClient *baseClient
}

type qLogWriter struct {
	collector *metrics.Collector
}

func (w qLogWriter) Write(p []byte) (n int, err error) {
	if string(p[:]) == "\n" {
		return 0, nil
	}
	w.collector.QLogMessage(p)
	return len(p), nil
}

func (w qLogWriter) Close() error {
	return nil
}

func newWriterCloser(collector *metrics.Collector) io.WriteCloser {
	return &qLogWriter{collector: collector}
}

func (c *DoQClient) getSession(collector *metrics.Collector) (quic.Session, error) {
	tlsConfig := c.baseClient.resolvedConfig
	dialContext := c.baseClient.getDialContext(nil)
	tokenStore := c.baseClient.options.QuicOptions.TokenStore

	// we're using bootstrapped address instead of what's passed to the function
	// it does not create an actual connection, but it helps us determine
	// what IP is actually reachable (when there're v4/v6 addresses)
	rawConn, err := dialContext(context.TODO(), "udp", "")
	if err != nil {
		return nil, err
	}
	// It's never actually used
	_ = rawConn.Close()

	udpConn, ok := rawConn.(*net.UDPConn)
	if !ok {
		return nil, err
	}

	addr := udpConn.RemoteAddr().String()
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
		Versions: []quic.VersionNumber{
			quic.VersionDraft34,
			quic.VersionDraft32,
			quic.VersionDraft29,
			quic.Version1,
		},
		Tracer: qlog.NewTracer(func(p logging.Perspective, connectionID []byte) io.WriteCloser {
			return newWriterCloser(collector)
		}),
		TokenStore: tokenStore,
	}

	// Moved here because code above is misc
	collector.ExchangeStarted()

	collector.QUICHandshakeStart()
	session, err := quic.DialAddrContext(context.Background(), addr, tlsConfig, quicConfig)
	if err != nil {
		reflectErr := reflect.ValueOf(err)
		if reflectErr.IsValid() && reflectErr.Elem().Type().String() == "qerr.QuicError" {
			errorCode := reflectErr.Elem().FieldByName("ErrorCode").Uint()
			collector.QUICError(qerr.ErrorCode(errorCode))
		}
		return nil, err
	}
	collector.QUICHandshakeDone()
	collector.TLSVersion(session.ConnectionState().TLS.Version)
	collector.QUICNegotiatedProtocol(session.ConnectionState().TLS.NegotiatedProtocol)
	collector.QUICVersion(reflect.ValueOf(session).Elem().FieldByName("version").Uint())

	return session, nil
}

func (c *DoQClient) openStream(session quic.Session) (quic.Stream, error) {
	ctx := context.Background()

	if c.baseClient.options.Timeout > 0 {
		deadline := time.Now().Add(c.baseClient.options.Timeout)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
		defer cancel() // avoid resource leak
	}

	return session.OpenStreamSync(ctx)
}

func (c *DoQClient) getBytesPool() *sync.Pool {
	return &sync.Pool{
		New: func() interface{} {
			return make([]byte, dns.MaxMsgSize)
		},
	}
}

func (c *DoQClient) Exchange(m *dns.Msg) *metrics.WithResponseOrError {
	collector := &metrics.Collector{}
	session, err := c.getSession(collector)
	if err != nil {
		return collector.WithError(err)
	}

	// If any message sent on a DoQ connection contains an edns-tcp-keepalive EDNS(0) Option,
	// this is a fatal error and the recipient of the defective message MUST forcibly abort
	// the connection immediately.
	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.6.2
	if opt := m.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			// Check for EDNS TCP keepalive option
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				_ = session.CloseWithError(0, "") // Already closing the connection so we don't care about the error
				return collector.WithError(errors.New("EDNS0 TCP keepalive option is set"))
			}
		}
	}

	// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.4
	// When sending queries over a QUIC connection, the DNS Message ID MUST be set to zero.
	id := m.Id
	var reply *dns.Msg
	m.Id = 0
	defer func() {
		// Restore the original ID to not break compatibility with proxies
		m.Id = id
		if reply != nil {
			reply.Id = id
		}
	}()

	stream, err := c.openStream(session)
	if err != nil {
		return collector.WithError(err)
	}

	buf, err := m.Pack()
	if err != nil {
		collector.WithError(err)
	}

	collector.QuerySend()
	_, err = stream.Write(buf)
	if err != nil {
		collector.WithError(err)
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// stream.Close() -- closes the write-direction of the stream.
	_ = stream.Close()

	pool := c.getBytesPool()
	respBuf := pool.Get().([]byte)

	defer pool.Put(respBuf)

	n, err := stream.Read(respBuf)
	collector.QueryReceive()
	if err != nil && n == 0 {
		collector.WithError(err)
	}

	reply = new(dns.Msg)
	err = reply.Unpack(respBuf)
	if err != nil {
		collector.WithError(err)
	}

	collector.ExchangeFinished()

	session.CloseWithError(0, "")

	return collector.WithResponse(reply)
}
