// dnstt-client is the client end of a DNS tunnel.
//
// Usage:
//
//	dnstt-client [-doh URL|-dot ADDR|-udp ADDR] (-pubkey PUBKEY|-pubkey-file PUBKEYFILE) DOMAIN LOCALADDR
//
// Examples:
//
//	dnstt-client -doh https://resolver.example/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:7000
//	dnstt-client -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000
//
// The program supports DNS over HTTPS (DoH), DNS over TLS (DoT), and UDP DNS.
// Use one of these options:
//
//	-doh https://resolver.example/dns-query
//	-dot resolver.example:853
//	-udp resolver.example:53
//
// You can give the server's public key as a file or as a hex string. Use
// "dnstt-server -gen-key" to get the public key.
//
//	-pubkey-file server.pub
//	-pubkey 0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// LOCALADDR is the TCP address that will listen for connections and forward
// them over the tunnel.
//
// In -doh and -dot modes, the program's TLS fingerprint is camouflaged with
// uTLS by default. The specific TLS fingerprint is selected randomly from a
// weighted distribution. You can set your own distribution (or specific single
// fingerprint) using the -utls option. The special value "none" disables uTLS.
//
//	-utls '3*Firefox,2*Chrome,1*iOS'
//	-utls Firefox
//	-utls none
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name.
func dnsNameCapacity(domain dns.Name) int {
	// Names must be 255 octets or shorter in total length.
	// https://tools.ietf.org/html/rfc1035#section-2.3.4
	capacity := 255
	// Subtract the length of the null terminator.
	capacity -= 1
	for _, label := range domain {
		// Subtract the length of the label and the length octet.
		capacity -= len(label) + 1
	}
	// Each label may be up to 63 bytes long and requires 64 bytes to
	// encode.
	capacity = capacity * 63 / 64
	// Base32 expands every 5 bytes to 8.
	capacity = capacity * 5 / 8
	return capacity
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// sampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func sampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

// sessionManager manages the KCP connection, Noise channel, and smux session,
// and can recreate them if they become closed.
type smuxSession interface {
	OpenStream() (*smux.Stream, error)
	Close() error
}

type sessionState struct {
	count    int
	draining bool
	conv     uint32
}

type sessionManager struct {
	pubkey     []byte
	domain     dns.Name
	remoteAddr net.Addr
	pconn      net.PacketConn
	mtu        int

	mu       sync.RWMutex
	createMu sync.Mutex
	// createSessionFn overrides session creation in tests.
	createSessionFn func(closeExisting bool) error
	sessions        map[smuxSession]*sessionState
	conn            *kcp.UDPSession
	rw              io.ReadWriteCloser
	sess            smuxSession
	conv            uint32
}

// noClosePacketConn prevents session teardown from closing a shared PacketConn.
type noClosePacketConn struct {
	net.PacketConn
}

func (c *noClosePacketConn) Close() error {
	return nil
}

// newSessionManager creates a new session manager.
func newSessionManager(pubkey []byte, domain dns.Name, remoteAddr net.Addr, pconn net.PacketConn, mtu int) *sessionManager {
	return &sessionManager{
		pubkey:     pubkey,
		domain:     domain,
		remoteAddr: remoteAddr,
		pconn:      &noClosePacketConn{PacketConn: pconn},
		mtu:        mtu,
	}
}

// closeSessionLocked closes the current session if it exists.
// Caller must hold sm.mu write lock.
func (sm *sessionManager) closeSessionLocked() {
	if sm.sess != nil {
		sm.sess.Close()
		if sm.sessions != nil {
			delete(sm.sessions, sm.sess)
		}
		sm.sess = nil
	}
	if sm.rw != nil {
		sm.rw.Close()
		sm.rw = nil
	}
	if sm.conn != nil {
		conv := sm.conv
		log.Printf("end session %08x", conv)
		sm.conn.Close()
		sm.conn = nil
	}
	sm.conv = 0
}

// createSession creates a new KCP connection, Noise channel, and smux session.
// Caller must NOT hold sm.mu lock.
func (sm *sessionManager) createSession() error {
	return sm.createSessionWithClose(true, nil)
}

func (sm *sessionManager) createSessionWithClose(closeExisting bool, expectedSess smuxSession) error {
	if sm.createSessionFn != nil {
		return sm.createSessionFn(closeExisting)
	}

	if closeExisting {
		sm.mu.Lock()
		// Close existing session if any.
		if expectedSess == nil || sm.sess == expectedSess {
			sm.closeSessionLocked()
		}
		sm.mu.Unlock()
	}

	conn, err := kcp.NewConn2(sm.remoteAddr, nil, 0, 0, sm.pconn)
	if err != nil {
		return fmt.Errorf("opening KCP conn: %v", err)
	}
	conv := conn.GetConv()
	log.Printf("begin session %08x", conv)

	// Permit coalescing the payloads of consecutive sends.
	conn.SetStreamMode(true)
	// Disable the dynamic congestion window (limit only by the maximum of
	// local and remote static windows).
	conn.SetNoDelay(
		0, // default nodelay
		0, // default interval
		0, // default resend
		1, // nc=1 => congestion window off
	)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if rc := conn.SetMtu(sm.mtu); !rc {
		conn.Close()
		panic(rc)
	}

	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewClient(conn, sm.pubkey)
	if err != nil {
		conn.Close()
		return err
	}

	// Start a smux session on the Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		rw.Close()
		conn.Close()
		return fmt.Errorf("opening smux session: %v", err)
	}

	// Lock again to update the session
	sm.mu.Lock()
	if sm.sessions == nil {
		sm.sessions = make(map[smuxSession]*sessionState)
	}
	sm.sessions[sess] = &sessionState{conv: conv}
	sm.conn = conn
	sm.rw = rw
	sm.sess = sess
	sm.conv = conv
	sm.mu.Unlock()

	return nil
}

func (sm *sessionManager) ensureSessionStateLocked(sess smuxSession, conv uint32) *sessionState {
	if sm.sessions == nil {
		sm.sessions = make(map[smuxSession]*sessionState)
	}
	state, ok := sm.sessions[sess]
	if !ok {
		state = &sessionState{conv: conv}
		sm.sessions[sess] = state
	} else if state.conv == 0 && conv != 0 {
		state.conv = conv
	}
	return state
}

func (sm *sessionManager) markSessionDraining(sess smuxSession, conv uint32) (smuxSession, uint32) {
	if sess == nil {
		return nil, 0
	}
	var closeSess smuxSession
	var closeConv uint32
	sm.mu.Lock()
	state := sm.ensureSessionStateLocked(sess, conv)
	state.draining = true
	if state.count == 0 {
		delete(sm.sessions, sess)
		closeSess = sess
		closeConv = state.conv
	}
	sm.mu.Unlock()
	return closeSess, closeConv
}

func (sm *sessionManager) trackStream(sess smuxSession, conv uint32) func() {
	sm.mu.Lock()
	state := sm.ensureSessionStateLocked(sess, conv)
	state.count++
	sm.mu.Unlock()
	return func() {
		sm.releaseStream(sess)
	}
}

func (sm *sessionManager) releaseStream(sess smuxSession) {
	var closeSess smuxSession
	var closeConv uint32
	sm.mu.Lock()
	state, ok := sm.sessions[sess]
	if !ok {
		sm.mu.Unlock()
		return
	}
	if state.count > 0 {
		state.count--
	}
	if state.draining && state.count == 0 {
		delete(sm.sessions, sess)
		closeSess = sess
		closeConv = state.conv
	}
	sm.mu.Unlock()
	if closeSess != nil {
		log.Printf("end session %08x", closeConv)
		closeSess.Close()
	}
}

func (sm *sessionManager) recreateSession(sess smuxSession, conv uint32, closeExisting bool) (smuxSession, uint32, error) {
	sm.createMu.Lock()
	defer sm.createMu.Unlock()

	var closeSess smuxSession
	var closeConv uint32
	if !closeExisting {
		closeSess, closeConv = sm.markSessionDraining(sess, conv)
	}

	// Double-check: another goroutine might have already recreated the session.
	sm.mu.RLock()
	if sm.sess != nil && sm.sess != sess {
		sess = sm.sess
		conv = sm.conv
		sm.mu.RUnlock()
		if closeSess != nil {
			log.Printf("end session %08x", closeConv)
			closeSess.Close()
		}
		return sess, conv, nil
	}
	sm.mu.RUnlock()

	err := sm.createSessionWithClose(closeExisting, sess)
	if err != nil {
		if closeSess != nil {
			log.Printf("end session %08x", closeConv)
			closeSess.Close()
		}
		return nil, 0, err
	}

	sm.mu.RLock()
	sess = sm.sess
	conv = sm.conv
	sm.mu.RUnlock()
	if closeSess != nil {
		log.Printf("end session %08x", closeConv)
		closeSess.Close()
	}
	return sess, conv, nil
}

// closeSession closes the current session if it exists.
func (sm *sessionManager) closeSession() {
	sm.mu.Lock()
	sessions := sm.sessions
	fallbackSess := sm.sess
	fallbackConv := sm.conv
	sm.sessions = nil
	sm.conn = nil
	sm.rw = nil
	sm.sess = nil
	sm.conv = 0
	sm.mu.Unlock()

	if sessions == nil && fallbackSess != nil {
		log.Printf("end session %08x", fallbackConv)
		fallbackSess.Close()
		return
	}

	for sess, state := range sessions {
		log.Printf("end session %08x", state.conv)
		sess.Close()
	}
}

// getSession returns the current session, creating one if needed.
func (sm *sessionManager) getSession() (smuxSession, uint32, error) {
	sm.mu.RLock()
	sess := sm.sess
	conv := sm.conv
	sm.mu.RUnlock()

	if sess != nil {
		return sess, conv, nil
	}

	// Serialize session creation attempts.
	sm.createMu.Lock()
	defer sm.createMu.Unlock()

	// Double-check after waiting for the creator.
	sm.mu.RLock()
	sess = sm.sess
	conv = sm.conv
	sm.mu.RUnlock()
	if sess != nil {
		return sess, conv, nil
	}

	// Create new session
	err := sm.createSession()
	if err != nil {
		return nil, 0, err
	}

	sm.mu.RLock()
	sess = sm.sess
	conv = sm.conv
	sm.mu.RUnlock()
	return sess, conv, nil
}

// openStream opens a new stream, recreating the session if necessary.
func (sm *sessionManager) openStream() (*smux.Stream, uint32, func(), error) {
	// Try to get existing session
	sess, conv, err := sm.getSession()
	if err != nil {
		return nil, 0, nil, err
	}

	// Try to open a stream
	stream, err := sess.OpenStream()
	if err == nil {
		release := sm.trackStream(sess, conv)
		return stream, conv, release, nil
	}

	if errors.Is(err, smux.ErrGoAway) {
		log.Printf("session %08x goaway, starting new session for new streams: %v", conv, err)

		sess, conv, err = sm.recreateSession(sess, conv, false)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("recreating session after goaway: %v", err)
		}

		stream, err = sess.OpenStream()
		if err != nil {
			return nil, 0, nil, fmt.Errorf("session %08x opening stream after goaway: %v", conv, err)
		}
		release := sm.trackStream(sess, conv)
		return stream, conv, release, nil
	}

	// If opening stream failed, the session might be closed.
	// Check if it's a closed pipe error or similar.
	isClosedError := errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, os.ErrClosed) ||
		errors.Is(err, io.EOF)
	if !isClosedError {
		// Fallback to string matching for errors that don't wrap the sentinels.
		errStr := err.Error()
		isClosedError = strings.Contains(errStr, "closed pipe") ||
			strings.Contains(errStr, "broken pipe") ||
			strings.Contains(errStr, "use of closed network connection")
	}

	if isClosedError {
		log.Printf("session %08x appears closed, recreating: %v", conv, err)

		sess, conv, err = sm.recreateSession(sess, conv, true)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("recreating session: %v", err)
		}

		// Try again with the (possibly new) session
		stream, err = sess.OpenStream()
		if err != nil {
			return nil, 0, nil, fmt.Errorf("session %08x opening stream after recreate: %v", conv, err)
		}
		release := sm.trackStream(sess, conv)
		return stream, conv, release, nil
	}

	return nil, 0, nil, fmt.Errorf("session %08x opening stream: %v", conv, err)
}

func handle(local *net.TCPConn, sm *sessionManager) error {
	stream, conv, release, err := sm.openStream()
	if err != nil {
		return fmt.Errorf("opening stream: %v", err)
	}
	defer release()
	defer func() {
		log.Printf("end stream %08x:%d", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()

	return err
}

func run(pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn) error {
	defer pconn.Close()

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	defer ln.Close()

	mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1 // clientid + padding length prefix + padding + data length prefix
	if mtu < 80 {
		return fmt.Errorf("domain %s leaves only %d bytes for payload", domain, mtu)
	}
	log.Printf("effective MTU %d", mtu)

	// Create session manager
	sm := newSessionManager(pubkey, domain, remoteAddr, pconn, mtu)
	defer sm.closeSession()

	// Create initial session
	err = sm.createSession()
	if err != nil {
		return err
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
			err := handle(local.(*net.TCPConn), sm)
			if err != nil {
				log.Printf("handle: %v", err)
			}
		}()
	}
}

var dialerControl func(network, address string, c syscall.RawConn) error = nil

func main() {
	// If no command-line arguments are given, try to read options from
	// environment variables, for compatibility with shadowsocks plugins.
	// ss-local -s 0.0.0.1 -p 1 -l 1080 -k password --plugin dnstt-client --plugin-opts 'doh=https://doh.example/dns-query;domain=<domain>;pubkey=<pubkey>'
	if len(os.Args) == 1 {
		pluginOpts := os.Getenv("SS_PLUGIN_OPTIONS")
		if pluginOpts != "" {
			var transportFlag, resolver, pubkey, domainStr string

			// Parse the semicolon-separated list of options.
			options := strings.Split(pluginOpts, ";")
			for _, opt := range options {
				parts := strings.SplitN(opt, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
				switch key {
				case "doh":
					transportFlag = "-doh"
					resolver = value
				case "dot":
					transportFlag = "-dot"
					resolver = value
				case "udp":
					transportFlag = "-udp"
					resolver = value
				case "pubkey":
					pubkey = value
				case "domain":
					domainStr = value
				case "__android_vpn":
					dialerControl = dialerControlVpn
				}
			}

			localHost := os.Getenv("SS_LOCAL_HOST")
			localPort := os.Getenv("SS_LOCAL_PORT")

			// Validate that we have all the required options, mimicking the shell script's checks.
			if transportFlag == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_PLUGIN_OPTIONS must contain one of: doh, dot, or udp")
				os.Exit(1)
			}
			if resolver == "" {
				remoteHost := os.Getenv("SS_REMOTE_HOST")
				remotePort := os.Getenv("SS_REMOTE_PORT")
				if remoteHost == "" || remotePort == "" {
					fmt.Fprintf(os.Stderr, "dnstt-client: SS_PLUGIN_OPTIONS must contain one of: doh, dot, or udp")
					os.Exit(1)
				}
				resolver = net.JoinHostPort(remoteHost, remotePort)
			}
			if transportFlag == "-doh" {
				if !strings.HasPrefix(strings.ToLower(resolver), "https://") {
					resolver = "https://" + resolver + "/dns-query"
				}
			}
			if pubkey == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_PLUGIN_OPTIONS must contain pubkey")
				os.Exit(1)
			}
			if domainStr == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_PLUGIN_OPTIONS must contain domain")
				os.Exit(1)
			}
			if localHost == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_LOCAL_HOST environment variable not set")
				os.Exit(1)
			}
			if localPort == "" {
				fmt.Fprintf(os.Stderr, "dnstt-client: SS_LOCAL_PORT environment variable not set")
				os.Exit(1)
			}

			// Reconstruct os.Args so the existing flag-parsing logic can be used.
			os.Args = []string{
				os.Args[0],
				transportFlag,
				resolver,
				"-pubkey",
				pubkey,
				domainStr,
				net.JoinHostPort(localHost, localPort),
			}
		}
	}

	var dohURL string
	var dotAddr string
	var pubkeyFilename string
	var pubkeyString string
	var udpAddr string
	var utlsDistribution string

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s [-doh URL|-dot ADDR|-udp ADDR] (-pubkey PUBKEY|-pubkey-file PUBKEYFILE) DOMAIN LOCALADDR

Examples:
  %[1]s -doh https://resolver.example/dns-query -pubkey-file server.pub t.example.com 127.0.0.1:7000
  %[1]s -dot resolver.example:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000

`, os.Args[0])
		flag.PrintDefaults()
		labels := make([]string, 0, len(utlsClientHelloIDMap))
		labels = append(labels, "none")
		for _, entry := range utlsClientHelloIDMap {
			labels = append(labels, entry.Label)
		}
		fmt.Fprintf(flag.CommandLine.Output(), `
Known TLS fingerprints for -utls are:
`)
		i := 0
		for i < len(labels) {
			var line strings.Builder
			fmt.Fprintf(&line, "  %s", labels[i])
			w := 2 + len(labels[i])
			i++
			for i < len(labels) && w+1+len(labels[i]) <= 72 {
				fmt.Fprintf(&line, " %s", labels[i])
				w += 1 + len(labels[i])
				i++
			}
			fmt.Fprintln(flag.CommandLine.Output(), line.String())
		}
	}
	flag.StringVar(&dohURL, "doh", "", "URL of DoH resolver")
	flag.StringVar(&dotAddr, "dot", "", "address of DoT resolver")
	flag.StringVar(&pubkeyString, "pubkey", "", fmt.Sprintf("server public key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "read server public key from file")
	flag.StringVar(&udpAddr, "udp", "", "address of UDP DNS resolver")
	flag.StringVar(&utlsDistribution, "utls",
		"4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13",
		"choose TLS fingerprint from weighted distribution")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}
	domain, err := dns.ParseName(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", flag.Arg(0), err)
		os.Exit(1)
	}
	localAddr, err := net.ResolveTCPAddr("tcp", flag.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var pubkey []byte
	if pubkeyFilename != "" && pubkeyString != "" {
		fmt.Fprintf(os.Stderr, "only one of -pubkey and -pubkey-file may be used\n")
		os.Exit(1)
	} else if pubkeyFilename != "" {
		var err error
		pubkey, err = readKeyFromFile(pubkeyFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read pubkey from file: %v\n", err)
			os.Exit(1)
		}
	} else if pubkeyString != "" {
		var err error
		pubkey, err = noise.DecodeKey(pubkeyString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pubkey format error: %v\n", err)
			os.Exit(1)
		}
	}
	if len(pubkey) == 0 {
		fmt.Fprintf(os.Stderr, "the -pubkey or -pubkey-file option is required\n")
		os.Exit(1)
	}

	utlsClientHelloID, err := sampleUTLSDistribution(utlsDistribution)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parsing -utls: %v\n", err)
		os.Exit(1)
	}
	if utlsClientHelloID != nil {
		log.Printf("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
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
			var rt http.RoundTripper
			if utlsClientHelloID == nil {
				transport := http.DefaultTransport.(*http.Transport).Clone()
				// Disable DefaultTransport's default Proxy =
				// ProxyFromEnvironment setting, for conformity
				// with utlsRoundTripper and with DoT mode,
				// which do not take a proxy from the
				// environment.
				transport.Proxy = nil
				rt = transport
			} else {
				rt = NewUTLSRoundTripper(nil, utlsClientHelloID)
			}
			pconn, err := NewHTTPPacketConn(rt, dohURL, 32)
			return addr, pconn, err
		}},
		// -dot
		{dotAddr, func(s string) (net.Addr, net.PacketConn, error) {
			addr := turbotunnel.DummyAddr{}
			var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
			if utlsClientHelloID == nil {
				dialTLSContext = (&tls.Dialer{
					NetDialer: &net.Dialer{
						Control: dialerControl,
					},
				}).DialContext
			} else {
				dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
				}
			}
			pconn, err := NewTLSPacketConn(dotAddr, dialTLSContext)
			return addr, pconn, err
		}},
		// -udp
		{udpAddr, func(s string) (net.Addr, net.PacketConn, error) {
			addr, err := net.ResolveUDPAddr("udp", s)
			if err != nil {
				return nil, nil, err
			}
			lc := net.ListenConfig{
				Control: dialerControl,
			}
			pconn, err := lc.ListenPacket(context.Background(), "udp", ":0")
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
