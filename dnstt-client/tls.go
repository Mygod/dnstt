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

type TLSPacketConn struct {
	*turbotunnel.QueuePacketConn
}

func NewTLSPacketConn(addr string) (*TLSPacketConn, error) {
	c := &TLSPacketConn{
		QueuePacketConn: turbotunnel.NewQueuePacketConn(dummyAddr{}, 0),
	}
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

			conn, err = tls.Dial("tcp", addr, tlsConfig)
			if err != nil {
				log.Printf("tls.Dial: %v", err)
				break
			}
		}
	}()
	return c, nil
}

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
		c.QueuePacketConn.QueueIncoming(p, dummyAddr{})
	}
}

func (c *TLSPacketConn) sendLoop(conn net.Conn) error {
	for p := range c.QueuePacketConn.OutgoingQueue(dummyAddr{}) {
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

func (c *TLSPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	// Ignore addr.
	return c.QueuePacketConn.WriteTo(p, dummyAddr{})
}
