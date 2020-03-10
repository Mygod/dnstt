package main

import (
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
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	idleTimeout = 10 * time.Minute
)

// handleStream bidirectionally connects a client stream with the ORPort.
func handleStream(stream *smux.Stream, upstream *net.TCPAddr) error {
	conn, err := net.DialTCP("tcp", nil, upstream)
	if err != nil {
		return err
	}
	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, conn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "copy stream←upstream: %v\n", err)
		}
		stream.Close()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(conn, stream)
		if err != nil {
			fmt.Fprintf(os.Stderr, "copy upstream←stream: %v\n", err)
		}
		conn.Close()
	}()
	wg.Wait()

	return nil
}

// acceptStreams layers an smux.Session on a KCP connection and awaits streams
// on it. It passes each stream to handleStream.
func acceptStreams(conn *kcp.UDPSession, upstream *net.TCPAddr) error {
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	sess, err := smux.Server(conn, smuxConfig)
	if err != nil {
		return err
	}

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		go func() {
			defer stream.Close()
			err := handleStream(stream, upstream)
			if err != nil {
				fmt.Fprintf(os.Stderr, "handleStream: %v\n", err)
			}
		}()
	}
}

// acceptSessions listens for incoming KCP connections and passes them to
// acceptStreams.
func acceptSessions(ln *kcp.Listener, mtu int, upstream *net.TCPAddr) error {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
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
		// Set the maximum transmission unit.
		conn.SetMtu(mtu)
		go func() {
			defer conn.Close()
			err := acceptStreams(conn, upstream)
			if err != nil {
				fmt.Fprintf(os.Stderr, "acceptStreams: %v\n", err)
			}
		}()
	}
}

func handle(c net.PacketConn, p []byte, addr net.Addr) error {
	fmt.Printf("handle %v %x\n", addr, p)
	message, err := dns.MessageFromWireFormat(p)
	if err != nil {
		return err
	}
	fmt.Printf("%#v\n", message)
	_, err = c.WriteTo([]byte("hello"), addr)
	return err
}

func loop(c net.PacketConn, domain dns.Name) error {
	type taggedPacket struct {
		P    []byte
		Addr net.Addr
	}

	handleChan := make(chan taggedPacket, 64)
	defer close(handleChan)
	go func() {
		for tp := range handleChan {
			p := tp.P
			addr := tp.Addr
			err := handle(c, p, addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "handle from %v: %v\n", addr, err)
			}
		}
	}()

	for {
		// One byte longer than we want, to check for truncation.
		var buf [513]byte
		n, addr, err := c.ReadFrom(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		if n == len(buf) {
			// Truncated packet.
			continue
		}
		// Copy the packet data into its own buffer.
		p := make([]byte, n)
		copy(p, buf[:n])
		select {
		case handleChan <- taggedPacket{p, addr}:
		default:
			// Drop incoming packets if channel is full.
		}
	}
}

type dummyAddr struct{}

func (addr dummyAddr) Network() string { return "dummy" }
func (addr dummyAddr) String() string  { return "dummy" }

func run(domain dns.Name, upstream net.Addr, udpAddr string) error {
	// Start up the virtual PacketConn for turbotunnel.
	pconn := turbotunnel.NewQueuePacketConn(dummyAddr{}, idleTimeout*2)
	ln, err := kcp.ServeConn(nil, 0, 0, pconn)
	if err != nil {
		return fmt.Errorf("opening KCP listener: %v", err)
	}
	defer ln.Close()
	go func() {
		err := acceptSessions(ln, 120, upstream.(*net.TCPAddr)) // TODO: MTU appropriate for length of domain
		if err != nil {
			fmt.Fprintf(os.Stderr, "acceptSessions: %v\n", err)
		}
	}()

	var wg sync.WaitGroup

	if udpAddr != "" {
		c, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("opening UDP listener: %v", err)
		}
		wg.Add(1)
		go func() {
			defer c.Close()
			defer wg.Done()
			err := loop(c, domain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error in UDP loop: %v\n", err)
			}
		}()
	}

	wg.Wait()
	return nil
}

func main() {
	var udpAddr string

	flag.StringVar(&udpAddr, "udp", "", "UDP port to listen on")
	flag.Parse()

	if flag.NArg() != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s -udp ADDR DOMAIN UPSTREAMADDR\n", os.Args[0])
		os.Exit(1)
	}
	domain, err := dns.ParseName(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}
	upstream, err := net.ResolveTCPAddr("tcp", flag.Arg(1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot resolve %+q: %v\n", flag.Arg(1), err)
		os.Exit(1)
	}

	err = run(domain, upstream, udpAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
