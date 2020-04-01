package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

type DoHPacketConn struct {
	clientID  turbotunnel.ClientID
	domain    dns.Name
	urlString string
	pollChan  chan struct{}
	sendChan  chan []byte
	*turbotunnel.QueuePacketConn
}

func NewDoHPacketConn(urlString string, domain dns.Name) (*DoHPacketConn, error) {
	u, err := url.Parse(urlString)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("bad URL scheme %+q", u.Scheme)
	}
	// Generate a new random ClientID.
	var clientID turbotunnel.ClientID
	rand.Read(clientID[:])
	c := &DoHPacketConn{
		clientID:        clientID,
		domain:          domain,
		urlString:       urlString,
		pollChan:        make(chan struct{}),
		sendChan:        make(chan []byte, 32),
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, idleTimeout),
	}
	go func() {
		err := c.sendLoop()
		if err != nil {
			log.Printf("sendLoop: %v", err)
		}
	}()
	for i := 0; i < 10; i++ {
		go func() {
			for p := range c.sendChan {
				err := c.send(p)
				if err != nil {
					log.Printf("sender thread: %v", err)
				}
			}
		}()
	}
	return c, nil
}

// send sends a single packet in an HTTP request.
func (c *DoHPacketConn) send(p []byte) error {
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

	req, err := http.NewRequest("POST", c.urlString, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/dns-message" {
		return fmt.Errorf("unexpected response")
	}
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 64000))
	if err != nil {
		// Don't report an error if we at least managed to send.
		return nil
	}
	// Got a response. Try to parse it as a DNS message.
	dnsResp, err := dns.MessageFromWireFormat(body)
	if err != nil {
		log.Printf("MessageFromWireFormat: %v", err)
		return nil
	}
	payload := dnsResponsePayload(&dnsResp, c.domain)
	// Reading anything gives sendLoop license to poll immediately.
	if len(payload) > 0 {
		select {
		case c.pollChan <- struct{}{}:
		default:
		}
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
		c.QueuePacketConn.QueueIncoming(p, dummyAddr{})
	}
	return nil
}

func (c *DoHPacketConn) sendLoop() error {
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
		case p = <-c.QueuePacketConn.OutgoingQueue(dummyAddr{}):
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
		select {
		case c.sendChan <- p:
		default:
		}
	}
}

func (c *DoHPacketConn) Close() error {
	close(c.sendChan) // TODO
	return c.QueuePacketConn.Close()
}
