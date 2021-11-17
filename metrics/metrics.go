package metrics

import (
	"crypto/x509"
	"encoding/json"
	"github.com/Lucapaulo/dnsperf/qerr"
	"github.com/miekg/dns"
	"log"
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
	quicVersion            *uint64
	quicError              *qerr.ErrorCode
	quicNegotiatedProtocol *string

	querySendTime    time.Time
	queryReceiveTime time.Time

	httpVersion *string

	endTime time.Time

	qLogMessages []map[string]interface{}
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

func (c *Collector) QUICHandshakeDone() {
	c.quicHandshakeDoneTime = time.Now()
}

func (c *Collector) QUICNegotiatedProtocol(negotiatedProtocol string) {
	c.quicNegotiatedProtocol = &negotiatedProtocol
}

func (c *Collector) QUICVersion(version uint64) {
	c.quicVersion = &version
}

func (c *Collector) TLSVersion(tlsVersion uint16) {
	c.tlsVersion = &tlsVersion
}

func (c *Collector) QuerySend() {
	c.querySendTime = time.Now()
}

func (c *Collector) QueryReceive() {
	c.queryReceiveTime = time.Now()
}

func (c *Collector) HTTPVersion(version string) {
	c.httpVersion = &version
}

func (c *Collector) ExchangeFinished() {
	c.endTime = time.Now()
}

func (c *Collector) QLogMessage(message []byte) {
	m := make(map[string]interface{})
	err := json.Unmarshal(message, &m)
	if err != nil {
		log.Panic(err)
	}
	c.qLogMessages = append(c.qLogMessages, m)
}
