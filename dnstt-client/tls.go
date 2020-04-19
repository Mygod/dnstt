package main

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// TLSPacketConn is a TLS- and TCP-based transport for DNS messages, used for
// DNS over TLS (DoT). Its WriteTo and ReadFrom methods exchange DNS messages
// over a TLS channel, prefixing each message with a two-octet length field as
// in DNS over TCP.
//
// TLSPacketConn deals only with alreaday formatted DNS messages. It does not
// handle encoding information into the messages. That is rather the
// responsibility of DNSPacketConn.
//
// https://tools.ietf.org/html/rfc7858
type TLSPacketConn struct {
	// QueuePacketConn is the direct receiver of ReadFrom and WriteTo calls.
	// recvLoop and sendLoop take the messages out of the receive and send
	// queues and actually put them on the network.
	*turbotunnel.QueuePacketConn
}

// NewTLSPacketConn creates a new TLSPacketConn configured to use the TLS
// server at addr as a DNS over TLS resolver. It maintains a TLS connection to
// the resolver, reconnecting as necessary. It closes the connection if any
// reconnection attempt fails.
func NewTLSPacketConn(addr string) (*TLSPacketConn, error) {
	c := &TLSPacketConn{
		QueuePacketConn: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0),
	}
	// We maintain one TLS connection at a time, redialing it whenever it
	// becomes disconnected. We do the first dial here, outside the
	// goroutine, so that any immediate and permanent connection errors are
	// reported directly to the caller of NewTLSPacketConn.
	tlsConfig := &tls.Config{}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	go func() {
		defer c.Close()
		for {
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				err := c.recvLoop(conn)
				if err != nil {
					log.Printf("recvLoop: %v", err)
				}
				wg.Done()
			}()
			go func() {
				err := c.sendLoop(conn)
				if err != nil {
					log.Printf("recvLoop: %v", err)
				}
				wg.Done()
			}()
			wg.Wait()
			conn.Close()

			// Whenever the TLS connection dies, redial a new one.
			conn, err = tls.Dial("tcp", addr, tlsConfig)
			if err != nil {
				log.Printf("tls.Dial: %v", err)
				break
			}
		}
	}()
	return c, nil
}

// recvLoop reads length-prefixed messages from conn and passes them to the
// incoming queue.
func (c *TLSPacketConn) recvLoop(conn net.Conn) error {
	for {
		var length uint16
		err := binary.Read(conn, binary.BigEndian, &length)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return err
		}
		p := make([]byte, int(length))
		_, err = io.ReadFull(conn, p)
		if err != nil {
			return err
		}
		c.QueuePacketConn.QueueIncoming(p, turbotunnel.DummyAddr{})
	}
}

// sendLoop reads messages from the outgoing queue and writes them,
// length-prefixed, to conn.
func (c *TLSPacketConn) sendLoop(conn net.Conn) error {
	for p := range c.QueuePacketConn.OutgoingQueue(turbotunnel.DummyAddr{}) {
		length := uint16(len(p))
		if int(length) != len(p) {
			panic(len(p))
		}
		err := binary.Write(conn, binary.BigEndian, &length)
		if err != nil {
			return err
		}
		conn.Write(p)
		if err != nil {
			return err
		}
	}
	return nil
}
