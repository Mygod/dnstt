package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

type DNSPacketConn struct {
	clientID turbotunnel.ClientID
	domain   dns.Name
	pollChan chan struct{}
	*turbotunnel.QueuePacketConn
}

func NewDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name) *DNSPacketConn {
	// Generate a new random ClientID.
	var clientID turbotunnel.ClientID
	rand.Read(clientID[:])
	c := &DNSPacketConn{
		clientID:        clientID,
		domain:          domain,
		pollChan:        make(chan struct{}),
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0),
	}
	go func() {
		err := c.recvLoop(transport)
		if err != nil {
			log.Printf("recvLoop: %v", err)
		}
	}()
	go func() {
		err := c.sendLoop(transport, addr)
		if err != nil {
			log.Printf("sendLoop: %v", err)
		}
	}()
	return c
}

func (c *DNSPacketConn) recvLoop(transport net.PacketConn) error {
	for {
		var buf [4096]byte
		n, addr, err := transport.ReadFrom(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("ReadFrom temporary error: %v", err)
				continue
			}
			return err
		}

		// Got a response. Try to parse it as a DNS message.
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
func (c *DNSPacketConn) send(transport net.PacketConn, p []byte, addr net.Addr) error {
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

	_, err = transport.WriteTo(buf, addr)
	return err
}

func (c *DNSPacketConn) sendLoop(transport net.PacketConn, addr net.Addr) error {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	for {
		var p []byte
		outgoingQueue := c.QueuePacketConn.OutgoingQueue(addr)
		pollTimerExpired := false
		select {
		// Give priority to sending an actual data packet from
		// OutgoingQueue. Only when that is empty, consider a poll.
		case p = <-outgoingQueue:
		default:
			select {
			case p = <-outgoingQueue:
			case <-c.pollChan:
				p = nil
			case <-pollTimer.C:
				p = nil
				pollTimerExpired = true
			}
		}

		if len(p) > 0 {
			// We have an actual data-carrying packet, so discard a
			// pending poll opportunity, if any.
			select {
			case <-c.pollChan:
			default:
			}
		}

		if pollTimerExpired {
			// We're polling because it's been a while since we last
			// polled. Increase the poll delay.
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			// We're sending an actual data packet, or we're polling
			// in response to a received packet. Reset the poll
			// delay to initial.
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)

		err := c.send(transport, p, addr)
		if err != nil {
			log.Printf("send: %v", err)
			continue
		}
	}
}
