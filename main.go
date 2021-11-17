package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/Lucapaulo/dnsperf/clients"
	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"log"
	"strings"

	"time"
)

func main() {
	tokenStore := quic.NewLRUTokenStore(5, 50)

	rrType := dns.TypeA
	timeout := 10

	opts := clients.Options{
		Timeout: time.Duration(timeout) * time.Second,
		TLSOptions: &clients.TLSOptions{
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		},
		QuicOptions: &clients.QuicOptions{
			TokenStore: tokenStore,
			QuicVersions: []quic.VersionNumber{quic.VersionDraft34, quic.VersionDraft32, quic.VersionDraft29, quic.Version1},

		},
	}

	u, err := clients.AddressToClient("quic://94.140.15.15:8853", opts)
	if err != nil {
		log.Fatalf("Cannot create an upstream: %s", err)
	}

	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "test.com" + ".", Qtype: rrType, Qclass: dns.ClassINET},
	}

	response := ""

	for i := 1;  i<=3; i++ {
		reply := u.Exchange(&req)
		if reply.GetError() != nil {
			log.Printf("Cannot make the DNS request: %s\n", reply.GetError())
		}

		b, err := json.MarshalIndent(reply.GetMetrics(), "", "  ")
		if err != nil {
			log.Fatalf("Cannot marshal json: %s", err)
		}

		//os.Stdout.WriteString(string(b) + "\n")

		c, err := json.MarshalIndent(reply.GetResponse(), "", "  ")
		if err != nil {
			log.Fatalf("Cannot marshal json: %s", err)
		}

		//os.Stdout.WriteString(string(c) + "\n")
		response = response + string(b) + "\n" + string(c) + "\n"
		req.Id = dns.Id()
		time.Sleep(time.Second * 1)
	}
	fmt.Println("Retry count: ", strings.Count(response, "\"retry\""))
}
