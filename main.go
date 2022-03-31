package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/mgranderath/dnsperf/clients"
	"github.com/miekg/dns"
	"log"
	"net"
	"strconv"
	"strings"

	"time"
	"os"
)

func main() {
	tokenStore := quic.NewLRUTokenStore(5, 50)
	clientSessionCache := tls.NewLRUClientSessionCache(100)

	rrType := dns.TypeA
	timeout := 10
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	_, portString, _ := net.SplitHostPort(udpConn.LocalAddr().String())
	udpConn.Close()
	port, _ := strconv.Atoi(portString)

	opts := clients.Options{
		Timeout: time.Duration(timeout) * time.Second,
		TLSOptions: &clients.TLSOptions{
			MinVersion: tls.VersionTLS10,
			MaxVersion: tls.VersionTLS13,
			ClientSessionCache: clientSessionCache,
			SkipCommonName: true,
			InsecureSkipVerify: true,
		},
		QuicOptions: &clients.QuicOptions{
			TokenStore:   tokenStore,
			QuicVersions: []quic.VersionNumber{quic.Version1},
			LocalPort:    port,
		},
	}

	//u, err := clients.AddressToClient("quic://94.140.15.15:8853", opts)
	u, err := clients.AddressToClient("quic://127.0.0.1:8853", opts)
	//u, err := clients.AddressToClient("quic://145.100.185.18:8853", opts)
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

	for i := 1; i <= 3; i++ {
		reply := u.Exchange(&req)
		if reply.GetError() != nil {
			log.Printf("Cannot make the DNS request: %s\n", reply.GetError())
		}

		b, err := json.MarshalIndent(reply.GetMetrics(), "", "  ")
		if err != nil {
			log.Fatalf("Cannot marshal json: %s", err)
		}

		os.Stdout.WriteString(string(b) + "\n")

		c, err := json.MarshalIndent(reply.GetResponse(), "", "  ")
		if err != nil {
			log.Fatalf("Cannot marshal json: %s", err)
		}

		os.Stdout.WriteString(string(c) + "\n")
		response = response + string(b) + "\n" + string(c) + "\n"
		req.Id = dns.Id()
		time.Sleep(time.Second * 1)
	}
	fmt.Println("Retry count: ", strings.Count(response, "\"retry\""))
}
