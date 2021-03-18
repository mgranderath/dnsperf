package metrics

import "time"

type Result struct {
	collector *Collector

	UDPSocketSetupDuration *time.Duration `json:"udpSocketSetupDuration,omitempty"`

	TCPHandshakeDuration *time.Duration `json:"tcpHandshakeDuration,omitempty"`

	TLSHandshakeDuration *time.Duration `json:"tlsHandshakeDuration,omitempty"`
	TLSVersion           *uint16        `json:"tlsVersion,omitempty"`
	TLSError             *int           `json:"tlsError,omitempty"`

	QUICHandshakeDuration *time.Duration `json:"quicHandshakeDuration,omitempty"`
	QUICVersion           *string        `json:"quicVersion,omitempty"`
	QUICError             *uint64        `json:"quicError,omitempty"`

	QueryTime *time.Duration `json:"queryTime,omitempty"`

	TotalTime *time.Duration `json:"totalTime,omitempty"`
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
}

func (r *Result) transformCommon() {
	if !r.collector.endTime.IsZero() {
		r.TotalTime = toPointer(r.collector.endTime.Sub(r.collector.startTime))
	}
	if !r.collector.queryReceiveTime.IsZero() {
		r.QueryTime = toPointer(r.collector.queryReceiveTime.Sub(r.collector.querySendTime))
	}
}
