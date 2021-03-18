package clients

import (
	"context"
	"dnsperf/metrics"
	"dnsperf/qerr"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"net"
	"reflect"
	"sync"
	"time"
)

const (
	VersionQuic00 = "doq-i00"
	VersionQuic01 = "doq-i01"
	VersionQuic02 = "doq-i02"
)

const handshakeTimeout = time.Second * 2

type DoQClient struct {
	baseClient *baseClient
}

func (c *DoQClient) getSession(collector *metrics.Collector) (quic.Session, error) {
	tlsConfig := c.baseClient.resolvedConfig
	dialContext := c.baseClient.getDialContext(nil)

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
		return nil, fmt.Errorf("failed to open connection to %s", c.baseClient.URL.String())
	}

	addr := udpConn.RemoteAddr().String()
	quicConfig := &quic.Config{
		HandshakeTimeout: handshakeTimeout,
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
	collector.QUICHandshakeDone(session.ConnectionState().Version, session.ConnectionState().NegotiatedProtocol)

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

	// Linter says that the argument needs to be pointer-like
	// But it's already pointer-like
	// nolint
	defer pool.Put(respBuf)

	n, err := stream.Read(respBuf)
	collector.QueryReceive()
	if err != nil && n == 0 {
		collector.WithError(err)
	}

	reply := new(dns.Msg)
	err = reply.Unpack(respBuf)
	if err != nil {
		collector.WithError(err)
	}

	collector.ExchangeFinished()

	return collector.WithResponse(reply)
}
