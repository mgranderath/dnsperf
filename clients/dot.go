package clients

import (
	"context"
	"github.com/Lucapaulo/dnsperf/metrics"
	"github.com/miekg/dns"
	"time"
)

const dialTimeout = 10 * time.Second

type DoTClient struct {
	baseClient *baseClient
}

func (c *DoTClient) Exchange(m *dns.Msg) *metrics.WithResponseOrError {
	collector := metrics.NewCollector()
	collector.ExchangeStarted()
	rawCon, err := c.baseClient.getTLSDialContext(collector)(context.TODO(), "tcp", "")
	if err != nil {
		return collector.WithError(err)
	}

	cn := dns.Conn{Conn: rawCon}
	_ = cn.SetDeadline(time.Now().Add(c.baseClient.options.Timeout))

	collector.QuerySend()
	err = cn.WriteMsg(m)
	if err != nil {
		rawCon.Close()
		return collector.WithError(err)
	}

	reply, err := cn.ReadMsg()
	collector.QueryReceive()
	if err != nil {
		rawCon.Close()
		return collector.WithError(err)
	}
	if reply.Id != m.Id {
		err = dns.ErrId
	}

	collector.ExchangeFinished()
	return collector.WithResponseAndError(reply, err)
}
