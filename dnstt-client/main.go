package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
)

const (
	idleTimeout = 10 * time.Minute
)

// A base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

func dnsResponsePayload(resp *dns.Message, domain dns.Name) []byte {
	if resp.Flags&0x8000 != 0x8000 {
		// QR != 1, this is not a response.
		return nil
	}
	if resp.Flags&0x000f != dns.RcodeNoError {
		return nil
	}

	if len(resp.Answer) != 1 {
		return nil
	}
	answer := resp.Answer[0]

	_, ok := answer.Name.TrimSuffix(domain)
	if !ok {
		// Not the name we are expecting.
		return nil
	}

	if answer.Type != dns.RRTypeTXT {
		// We only support TYPE == TXT.
		return nil
	}
	payload, err := dns.DecodeRDataTXT(answer.Data)
	if err != nil {
		return nil
	}

	return payload
}

type DNSPacketConn struct {
	shortClientID [4]byte
	domain        dns.Name
	net.PacketConn
}

func (c *DNSPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		var buf [4096]byte
		n, addr, err := c.PacketConn.ReadFrom(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return n, addr, err
		}
		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			continue
		}
		payload := dnsResponsePayload(&resp, c.domain)
		if payload == nil {
			continue
		}
		return copy(p, payload), addr, nil
	}
}

func (c *DNSPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	payload := bytes.Join([][]byte{c.shortClientID[:], p}, nil)
	encoded := make([]byte, base32Encoding.EncodedLen(len(payload)))
	base32Encoding.Encode(encoded, payload)
	labels := chunks(encoded, 63)
	labels = append(labels, c.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return 0, err
	}

	var id uint16
	binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100, // QR = 0, RD = 1
		Question: []dns.Question{
			{
				Name:  name,
				Type:  dns.RRTypeTXT,
				Class: dns.ClassIN,
			},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(buf, addr)
}

func handle(local *net.TCPConn, sess *smux.Session) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err != nil {
			fmt.Fprintf(os.Stderr, "copy stream←local: %v\n", err)
		}
		stream.Close()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err != nil {
			fmt.Fprintf(os.Stderr, "copy local←stream: %v\n", err)
		}
		local.Close()
	}()
	wg.Wait()

	return err
}

func run(domain dns.Name, localAddr, udpAddr string) error {
	var sess *smux.Session

	if udpAddr != "" {
		addr, err := net.ResolveUDPAddr("udp", udpAddr)
		if err != nil {
			return err
		}
		dnsConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return fmt.Errorf("opening UDP conn: %v", err)
		}
		defer dnsConn.Close()

		// Start up the virtual PacketConn for turbotunnel.
		var shortClientID [4]byte
		rand.Read(shortClientID[:])
		pconn := &DNSPacketConn{shortClientID, domain, dnsConn}

		// Open a KCP conn on the PacketConn.
		conn, err := kcp.NewConn2(addr, nil, 0, 0, pconn)
		if err != nil {
			return fmt.Errorf("opening KCP conn: %v", err)
		}
		defer conn.Close()
		// Permit coalescing the payloads of consecutive sends.
		conn.SetStreamMode(true)
		// Disable the dynamic congestion window (limit only by the
		// maximum of local and remote static windows).
		conn.SetNoDelay(
			0, // default nodelay
			0, // default interval
			0, // default resend
			1, // nc=1 => congestion window off
		)
		conn.SetMtu(100) // TODO: MTU appropriate for length of domain

		// Start a smux session on the KCP conn.
		smuxConfig := smux.DefaultConfig()
		smuxConfig.Version = 2
		smuxConfig.KeepAliveTimeout = idleTimeout
		sess, err = smux.Client(conn, smuxConfig)
		if err != nil {
			return fmt.Errorf("opening smux session: %v", err)
		}
		defer sess.Close()
	} else {
		return fmt.Errorf("need a UDP address")
	}

	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}

	for {
		local, err := ln.Accept()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		go func() {
			defer local.Close()
			err := handle(local.(*net.TCPConn), sess)
			if err != nil {
				fmt.Fprintf(os.Stderr, "handle: %v\n", err)
			}
		}()
	}
}

func main() {
	var udpAddr string

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s -udp ADDR DOMAIN LOCALADDR\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&udpAddr, "udp", "", "UDP port of DNS server")
	flag.Parse()

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}
	domain, err := dns.ParseName(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}
	localAddr := flag.Arg(1)

	err = run(domain, localAddr, udpAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
