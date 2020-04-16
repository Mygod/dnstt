package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

type HTTPPacketConn struct {
	urlString string
	sendChan  chan []byte
	*turbotunnel.QueuePacketConn
}

func NewHTTPPacketConn(urlString string, numSenders int) (*HTTPPacketConn, error) {
	c := &HTTPPacketConn{
		urlString:       urlString,
		sendChan:        make(chan []byte, 32),
		QueuePacketConn: turbotunnel.NewQueuePacketConn(dummyAddr{}, idleTimeout),
	}
	for i := 0; i < numSenders; i++ {
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
func (c *HTTPPacketConn) send(p []byte) error {
	req, err := http.NewRequest("POST", c.urlString, bytes.NewReader(p))
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
	c.QueuePacketConn.QueueIncoming(body, dummyAddr{})
	return nil
}

func (c *HTTPPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	// Ignore addr.
	select {
	case c.sendChan <- p:
	default:
	}
	return len(p), nil
}

func (c *HTTPPacketConn) Close() error {
	close(c.sendChan) // TODO
	return c.QueuePacketConn.Close()
}
