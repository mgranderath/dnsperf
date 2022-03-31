package metrics

import (
	"time"
)

type Result struct {
	collector *Collector

	UDPSocketSetupDuration *time.Duration `json:"udp_socket_setup_duration,omitempty"`

	TCPHandshakeDuration *time.Duration `json:"tcp_handshake_duration,omitempty"`

	TLSHandshakeDuration *time.Duration `json:"tls_handshake_duration,omitempty"`
	TLSVersion           *uint16        `json:"tls_version,omitempty"`
	TLSError             *int           `json:"tls_error,omitempty"`

	QUICHandshakeDuration  *time.Duration           `json:"quic_handshake_duration,omitempty"`
	QUICVersion            *uint64                  `json:"quic_version,omitempty"`
	QUICNegotiatedProtocol *string                  `json:"quic_negotiated_protocol,omitempty"`
	QUICUsed0RTT 		bool 			`json:"quic_used0RTT"`
	QUICError              *uint64                  `json:"quic_error,omitempty"`
	QLogMessages           []map[string]interface{} `json:"qlog_messages,omitempty"`

	HTTPVersion *string `json:"http_version,omitempty"`

	QueryTime *time.Duration `json:"query_time,omitempty"`

	TotalTime *time.Duration `json:"total_time,omitempty"`
}

func fromCollector(collector *Collector) *Result {
	result := &Result{
		collector: collector,
	}

	result.transformUDP()
	result.transformTCP()
	result.transformTLS()
	result.transformQUIC()
	result.transformCommon()
	result.transformHTTPS()

	return result
}

func toPointer(duration time.Duration) *time.Duration {
	return &duration
}

func (r *Result) transformUDP() {
	if !r.collector.udpSocketSetupDoneTime.IsZero() {
		r.UDPSocketSetupDuration = toPointer(r.collector.udpSocketSetupDoneTime.Sub(r.collector.udpSocketSetupStartTime))
	}
}

func (r *Result) transformTCP() {
	if !r.collector.tcpHandshakeDoneTime.IsZero() {
		r.TCPHandshakeDuration = toPointer(r.collector.tcpHandshakeDoneTime.Sub(r.collector.tcpHandshakeStartTime))
	}
}

func (r *Result) transformTLS() {
	if !r.collector.tlsHandshakeDoneTime.IsZero() {
		r.TLSHandshakeDuration = toPointer(r.collector.tlsHandshakeDoneTime.Sub(r.collector.tlsHandshakeStartTime))
	}
	r.TLSVersion = r.collector.tlsVersion
	r.TLSError = (*int)(r.collector.tlsError)
}

func (r *Result) transformQUIC() {
	if !r.collector.quicHandshakeDoneTime.IsZero() {
		r.QUICHandshakeDuration = toPointer(r.collector.quicHandshakeDoneTime.Sub(r.collector.quicHandshakeStartTime))
	}
	r.QUICVersion = r.collector.quicVersion
	r.QUICError = (*uint64)(r.collector.quicError)
	r.QUICNegotiatedProtocol = r.collector.quicNegotiatedProtocol
	r.QUICUsed0RTT = r.collector.quicUsed0RTT

	if len(r.collector.qLogMessages) != 0 {
		for _, message := range r.collector.qLogMessages {
			r.QLogMessages = append(r.QLogMessages, message)
		}
	}
}

func (r *Result) transformCommon() {
	if !r.collector.endTime.IsZero() {
		r.TotalTime = toPointer(r.collector.endTime.Sub(r.collector.startTime))
	}
	if !r.collector.queryReceiveTime.IsZero() {
		r.QueryTime = toPointer(r.collector.queryReceiveTime.Sub(r.collector.querySendTime))
	}
}

func (r *Result) transformHTTPS() {
	r.HTTPVersion = r.collector.httpVersion
}
