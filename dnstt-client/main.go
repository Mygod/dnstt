package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
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
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	idleTimeout         = 10 * time.Minute
	initPollDelay       = 100 * time.Millisecond
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

type DNSPacketConn struct {
	clientID turbotunnel.ClientID
	domain   dns.Name
	pollChan chan struct{}
	*turbotunnel.QueuePacketConn
}

func NewDNSPacketConn(udpConn net.PacketConn, addr net.Addr, domain dns.Name) *DNSPacketConn {
	// Generate a new random ClientID.
	var clientID turbotunnel.ClientID
	rand.Read(clientID[:])
	c := &DNSPacketConn{
		clientID:        clientID,
		domain:          domain,
		pollChan:        make(chan struct{}),
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, idleTimeout),
	}
	go func() {
		err := c.recvLoop(udpConn)
		if err != nil {
			log.Printf("recvLoop: %v", err)
		}
	}()
	go func() {
		err := c.sendLoop(udpConn, addr)
		if err != nil {
			log.Printf("sendLoop: %v", err)
		}
	}()
	return c
}

func (c *DNSPacketConn) recvLoop(udpConn net.PacketConn) error {
	for {
		var buf [4096]byte
		n, addr, err := udpConn.ReadFrom(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("ReadFrom temporary error: %v", err)
				continue
			}
			return err
		}

		// Got a UDP packet. Try to parse it as a DNS message.
		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("MessageFromWireFormat: %v", err)
			continue
		}

		payload := dnsResponsePayload(&resp, c.domain)
		// Reading anything gives sendLoop license to poll immediately.
		if len(payload) > 0 {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}

		// Pull out the packets contained in the payload.
		r := bytes.NewReader(payload)
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			c.QueuePacketConn.QueueIncoming(p, addr)
		}
	}
}

// send sends a single packet in a DNS query.
func (c *DNSPacketConn) send(udpConn net.PacketConn, p []byte, addr net.Addr) error {
	var decoded []byte
	{
		if len(p) >= 224 {
			return fmt.Errorf("too long")
		}
		var buf bytes.Buffer
		// ClientID
		buf.Write(c.clientID[:])
		// Padding / cache inhibition
		buf.WriteByte(224 + numPadding)
		io.CopyN(&buf, rand.Reader, numPadding)
		// Packet contents
		if len(p) > 0 {
			buf.WriteByte(byte(len(p)))
			buf.Write(p)
		}
		decoded = buf.Bytes()
	}

	encoded := make([]byte, base32Encoding.EncodedLen(len(decoded)))
	base32Encoding.Encode(encoded, decoded)
	labels := chunks(encoded, 63)
	labels = append(labels, c.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
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
		// EDNS(0)
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: 4096, // requestor's UDP payload size
				TTL:   0,    // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return err
	}

	_, err = udpConn.WriteTo(buf, addr)
	return err
}

func (c *DNSPacketConn) sendLoop(udpConn net.PacketConn, addr net.Addr) error {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	for {
		var p []byte
		select {
		case <-c.pollChan:
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			p = nil
		case p = <-c.QueuePacketConn.OutgoingQueue(addr):
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = initPollDelay
		case <-pollTimer.C:
			p = nil
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		}
		pollTimer.Reset(pollDelay)
		err := c.send(udpConn, p, addr)
		if err != nil {
			log.Printf("send: %v", err)
			continue
		}
	}
}

func handle(local *net.TCPConn, sess *smux.Session) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return err
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

func run(domain dns.Name, localAddr, udpAddr string) error {
	var sess *smux.Session

	if udpAddr != "" {
		addr, err := net.ResolveUDPAddr("udp", udpAddr)
		if err != nil {
			return err
		}
		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return fmt.Errorf("opening UDP conn: %v", err)
		}
		defer udpConn.Close()

		// Start up the virtual PacketConn for turbotunnel.
		pconn := NewDNSPacketConn(udpConn, addr, domain)

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
		mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1 // clientid + padding length prefix + padding + data length prefix
		if mtu < 80 {
			return fmt.Errorf("domain %s leaves only %d bytes for payload", domain, mtu)
		}
		log.Printf("MTU %d\n", mtu)
		if rc := conn.SetMtu(mtu); !rc {
			panic(rc)
		}

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
				log.Printf("handle: %v\n", err)
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

	log.SetFlags(log.LstdFlags | log.LUTC)

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}
	domain, err := dns.ParseName(flag.Arg(0))
	if err != nil {
		log.Printf("invalid domain %+q: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}
	localAddr := flag.Arg(1)

	err = run(domain, localAddr, udpAddr)
	if err != nil {
		log.Fatal(err)
	}
}
