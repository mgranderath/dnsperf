package metrics

import (
	"crypto/x509"
	"dnsperf/qerr"
	"github.com/miekg/dns"
	"time"
)

type Collector struct {
	startTime time.Time

	udpSocketSetupStartTime time.Time
	udpSocketSetupDoneTime  time.Time

	tcpHandshakeStartTime time.Time
	tcpHandshakeDoneTime  time.Time

	tlsHandshakeStartTime time.Time
	tlsHandshakeDoneTime  time.Time
	tlsVersion            *uint16
	tlsError              *x509.InvalidReason

	quicHandshakeStartTime time.Time
	quicHandshakeDoneTime  time.Time
	quicVersion            *string
	quicError              *qerr.ErrorCode

	querySendTime    time.Time
	queryReceiveTime time.Time

	endTime time.Time
}

func NewCollector() *Collector {
	return &Collector{}
}

func (c *Collector) WithError(err error) *WithResponseOrError {
	return &WithResponseOrError{
		response:  nil,
		collector: c,
		error:     err,
	}
}

func (c *Collector) WithResponse(response *dns.Msg) *WithResponseOrError {
	return &WithResponseOrError{
		response:  response,
		collector: c,
		error:     nil,
	}
}

func (c *Collector) WithResponseAndError(response *dns.Msg, err error) *WithResponseOrError {
	return &WithResponseOrError{
		response:  response,
		collector: c,
		error:     err,
	}
}

func (c *Collector) ExchangeStarted() {
	c.startTime = time.Now()
}

func (c *Collector) UDPSocketSetupStart() {
	c.udpSocketSetupStartTime = time.Now()
}

func (c *Collector) UDPSocketSetupFinished() {
	c.udpSocketSetupDoneTime = time.Now()
}

func (c *Collector) TCPHandshakeStart() {
	c.tcpHandshakeStartTime = time.Now()
}

func (c *Collector) TCPHandshakeFinished() {
	c.tcpHandshakeDoneTime = time.Now()
}

func (c *Collector) TLSHandshakeStart() {
	c.tlsHandshakeStartTime = time.Now()
}

func (c *Collector) TLSHandshakeFinished(version uint16) {
	c.tlsHandshakeDoneTime = time.Now()
	c.tlsVersion = &version
}

func (c *Collector) TLSError(err x509.InvalidReason) {
	c.tlsError = &err
}

func (c *Collector) QUICError(err qerr.ErrorCode) {
	c.quicError = &err
}

func (c *Collector) QUICHandshakeStart() {
	c.quicHandshakeStartTime = time.Now()
}

func (c *Collector) QUICHandshakeDone(tlsVersion uint16, quicVersion string) {
	c.quicHandshakeDoneTime = time.Now()
	c.tlsVersion = &tlsVersion
	c.quicVersion = &quicVersion
}

func (c *Collector) QuerySend() {
	c.querySendTime = time.Now()
}

func (c *Collector) QueryReceive() {
	c.queryReceiveTime = time.Now()
}

func (c *Collector) ExchangeFinished() {
	c.endTime = time.Now()
}
