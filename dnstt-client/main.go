package main

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	idleTimeout         = 10 * time.Minute
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0
	// How many bytes of random padding to insert into queries.
	numPadding = 3
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

func nextPacket(r *bytes.Reader) ([]byte, error) {
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	for {
		var n uint16
		err := binary.Read(r, binary.BigEndian, &n)
		if err != nil {
			return nil, err
		}
		p := make([]byte, n)
		_, err = io.ReadFull(r, p)
		return p, eof(err)
	}
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

func handle(local *net.TCPConn, sess *smux.Session) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("opening stream: %v", err)
	}
	log.Printf("begin stream %v", stream.ID())
	defer func() {
		log.Printf("end stream %v", stream.ID())
		stream.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err != nil {
			log.Printf("copy stream←local: %v\n", err)
		}
		stream.Close()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err != nil {
			log.Printf("copy local←stream: %v\n", err)
		}
		local.Close()
	}()
	wg.Wait()

	return err
}

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name.
func dnsNameCapacity(domain dns.Name) int {
	// https://tools.ietf.org/html/rfc1035#section-2.3.4
	// Names must be 255 octets or shorter in total length.
	capacity := 255
	// Subtract the length of the null terminator.
	capacity -= 1
	for _, label := range domain {
		// Subtract the length of the label and the length octet.
		capacity -= len(label) + 1
	}
	// Each label may be up to 63 bytes long and requires 64
	capacity = capacity * 63 / 64
	// Base32 expands every 5 bytes to 8.
	capacity = capacity * 5 / 8
	return capacity
}

func run(pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn) error {
	defer pconn.Close()

	// Open a KCP conn on the PacketConn.
	conn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
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
	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1 // clientid + padding length prefix + padding + data length prefix
	if mtu < 80 {
		return fmt.Errorf("domain %s leaves only %d bytes for payload", domain, mtu)
	}
	log.Printf("MTU %d\n", mtu)
	if rc := conn.SetMtu(mtu); !rc {
		panic(rc)
	}

	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewClient(conn, pubkey)
	if err != nil {
		return err
	}

	// Start a smux session on the Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		return fmt.Errorf("opening smux session: %v", err)
	}
	defer sess.Close()

	ln, err := net.ListenTCP("tcp", localAddr)
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
				log.Printf("handle: %v\n", err)
			}
		}()
	}
}

func main() {
	var dohURL string
	var dotAddr string
	var udpAddr string

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [-doh URL|-dot ADDR|-udp ADDR] PUBKEY DOMAIN LOCALADDR\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&dohURL, "doh", "", "URL of DoH resolver")
	flag.StringVar(&dotAddr, "dot", "", "address of DoT resolver")
	flag.StringVar(&udpAddr, "udp", "", "address of UDP DNS resolver")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if flag.NArg() != 3 {
		flag.Usage()
		os.Exit(1)
	}
	pubkey, err := hex.DecodeString(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid pubkey %+q: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}
	domain, err := dns.ParseName(flag.Arg(1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", flag.Arg(1), err)
		os.Exit(1)
	}
	localAddr, err := net.ResolveTCPAddr("tcp", flag.Arg(2))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Iterate over the remote resolver address options and select one and
	// only one.
	var remoteAddr net.Addr
	var pconn net.PacketConn
	for _, opt := range []struct {
		s string
		f func(string) (net.Addr, net.PacketConn, error)
	}{
		// -doh
		{dohURL, func(s string) (net.Addr, net.PacketConn, error) {
			addr := turbotunnel.DummyAddr{}
			pconn, err := NewHTTPPacketConn(dohURL, 32)
			return addr, pconn, err
		}},
		// -dot
		{dotAddr, func(s string) (net.Addr, net.PacketConn, error) {
			addr := turbotunnel.DummyAddr{}
			pconn, err := NewTLSPacketConn(dotAddr)
			return addr, pconn, err
		}},
		// -udp
		{udpAddr, func(s string) (net.Addr, net.PacketConn, error) {
			addr, err := net.ResolveUDPAddr("udp", s)
			if err != nil {
				return nil, nil, err
			}
			pconn, err := net.ListenUDP("udp", nil)
			return addr, pconn, err
		}},
	} {
		if opt.s == "" {
			continue
		}
		if pconn != nil {
			fmt.Fprintf(os.Stderr, "only one of -doh, -dot, and -udp may be given\n")
			os.Exit(1)
		}
		var err error
		remoteAddr, pconn, err = opt.f(opt.s)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if pconn == nil {
		fmt.Fprintf(os.Stderr, "one of -doh, -dot, or -udp is required\n")
		os.Exit(1)
	}

	pconn = NewDNSPacketConn(pconn, remoteAddr, domain)
	err = run(pubkey, domain, localAddr, remoteAddr, pconn)
	if err != nil {
		log.Fatal(err)
	}
}
