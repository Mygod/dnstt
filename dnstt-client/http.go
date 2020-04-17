package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

type HTTPPacketConn struct {
	urlString     string
	client        *http.Client
	notBefore     time.Time
	notBeforeLock sync.RWMutex
	*turbotunnel.QueuePacketConn
}

func NewHTTPPacketConn(urlString string, numSenders int) (*HTTPPacketConn, error) {
	c := &HTTPPacketConn{
		urlString: urlString,
		client: &http.Client{
			Timeout: 1 * time.Minute,
		},
		QueuePacketConn: turbotunnel.NewQueuePacketConn(dummyAddr{}, 0),
	}
	for i := 0; i < numSenders; i++ {
		go func() {
			for p := range c.QueuePacketConn.OutgoingQueue(dummyAddr{}) {
				err := c.send(p)
				if err != nil {
					log.Printf("sender thread: %v", err)
				}
			}
		}()
	}
	return c, nil
}

func (c *HTTPPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	// Drop packets while we are rate-limiting ourselves (as a result of a
	// Retry-After response header, for example).
	c.notBeforeLock.RLock()
	notBefore := c.notBefore
	c.notBeforeLock.RUnlock()
	if time.Now().Before(notBefore) {
		return len(p), nil
	}

	// Ignore addr.
	return c.QueuePacketConn.WriteTo(p, dummyAddr{})
}

// send sends a single packet in an HTTP request.
func (c *HTTPPacketConn) send(p []byte) error {
	req, err := http.NewRequest("POST", c.urlString, bytes.NewReader(p))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("User-Agent", "") // Disable default "Go-http-client/1.1".
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
			return fmt.Errorf("unknown HTTP response Content-Type %+q", ct)
		}
		body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 64000))
		if err == nil {
			c.QueuePacketConn.QueueIncoming(body, dummyAddr{})
		}
		// Ignore err != nil; don't report an error if we at least
		// managed to send.
	default:
		// We primarily are thinking of 429 Too Many Requests here, but
		// any other unexpected response codes will also cause us to
		// rate-limit ourself and emit a log message.
		// https://developers.google.com/speed/public-dns/docs/doh/#errors
		now := time.Now()
		var retryAfter time.Time
		if value := resp.Header.Get("Retry-After"); value != "" {
			var err error
			retryAfter, err = parseRetryAfter(value, now)
			if err != nil {
				log.Printf("cannot parse Retry-After value %+q", value)
			}
		}
		if retryAfter.IsZero() {
			// Supply a default.
			retryAfter = now.Add(10 * time.Second)
		}
		c.notBeforeLock.Lock()
		if retryAfter.After(now) && retryAfter.After(c.notBefore) {
			log.Printf("got %+q; ceasing sending for %v", resp.Status, retryAfter.Sub(now))
			c.notBefore = retryAfter
		}
		c.notBeforeLock.Unlock()
	}

	return nil
}

// parseRetryAfter parses the value of a Retry-After header as an absolute
// time.Time.
func parseRetryAfter(value string, now time.Time) (time.Time, error) {
	// May be a date string or an integer number of seconds.
	// https://tools.ietf.org/html/rfc7231#section-7.1.3
	if t, err := http.ParseTime(value); err == nil {
		return t, nil
	}
	i, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return time.Time{}, err
	}
	return now.Add(time.Duration(i) * time.Second), nil
}
