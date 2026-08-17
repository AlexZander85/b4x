// Command b4-ppe-probe is the controlled-flow emitter used by the PPE
// visibility self-test (src/capture/ppe/selftest_probe.go).
//
// Contract:
//
//	b4-ppe-probe --protocol tcp --family ipv4 --source-port 8443 --flow-id X \
//	             --phase without_exclusion --endpoint host:port --timeout-ms 5000
//
// Output: one JSON line on stdout:
//
//	{"protocol":"b4-ppe-self-test/v1","client_emitted":true,"detail":"..."}
//
// The probe must emit a flow whose *source port* equals --source-port so the
// passive observer (nfq/ppe_observer.go) can correlate it via ClientPort.
//
// Keenetic deployment notes: the router runs the probe locally, so the flow
// would otherwise be a purely local (OUTPUT) one that never traverses the
// forwarded path (B4_PPE_FWD / POSTROUTING) where MediaTek PPE offload acts.
// Local raw packets also bypass the nat hook on this firmware, so plain
// OUTPUT DNAT cannot be used. Instead the probe owns a tun device: packets
// written into the tun appear as ingress traffic and traverse the standard
// forwarded path (PREROUTING -> nat DNAT 32000 -> FORWARD -> POSTROUTING),
// which makes the flow visible in B4_PPE_FWD/POSTROUTING (outgoing) and
// B4_PREROUTING (incoming replies).
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	selfTestProtocol = "b4-ppe-self-test/v1"
	protoTCP         = 6
	protoUDP         = 17
	payload1Len      = 40
	payload2Len      = 32
)

type args struct {
	protocol   string
	family     string
	sourcePort uint16
	flowID     string
	phase      string
	endpoint   string
	timeout    time.Duration
	managedSet string
	tunNet     string
	noDNAT     bool
	debug      bool
}

var debugEnabled bool

func debugf(format string, values ...any) {
	if debugEnabled {
		fmt.Fprintf(os.Stderr, "[ppe-probe] "+format+"\n", values...)
	}
}

func main() {
	os.Exit(run())
}

func run() int {
	a, err := parseArgs(os.Args[1:])
	if err != nil {
		return emit(ProbeResult{Protocol: selfTestProtocol, ClientEmitted: false, Detail: err.Error()})
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	result := ProbeResult{Protocol: selfTestProtocol}
	switch a.protocol {
	case "tcp":
		result = runTCP(ctx, a)
	case "quic", "udp":
		result = runUDP(ctx, a)
	default:
		result = ProbeResult{Protocol: selfTestProtocol, ClientEmitted: false, Detail: fmt.Sprintf("unsupported protocol %q", a.protocol)}
	}
	return emit(result)
}

type ProbeResult struct {
	Protocol      string `json:"protocol"`
	ClientEmitted bool   `json:"client_emitted"`
	Detail        string `json:"detail,omitempty"`
}

func emit(result ProbeResult) int {
	encoded, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode result: %v\n", err)
		return 1
	}
	fmt.Println(string(encoded))
	return 0
}

func parseArgs(argv []string) (args, error) {
	fs := flag.NewFlagSet("b4-ppe-probe", flag.ContinueOnError)
	var (
		protocol   = fs.String("protocol", "tcp", "probe protocol: tcp or quic")
		family     = fs.String("family", "ipv4", "address family: ipv4 or ipv6")
		sourcePort = fs.Uint("source-port", 0, "client source port")
		flowID     = fs.String("flow-id", "", "self-test flow identifier")
		phase      = fs.String("phase", "", "self-test phase")
		endpoint   = fs.String("endpoint", "", "controlled endpoint host:port")
		timeoutMS  = fs.Int("timeout-ms", 5000, "overall probe timeout in milliseconds")
		managedSet = fs.String("managed-set", "", "ipset to register the tun source with (PPE exclusion match)")
		tunNet     = fs.String("tun-net", "10.99.0.1/24", "address/prefix assigned to the tun device (probe source)")
		noDNAT     = fs.Bool("no-dnat", false, "diagnostic: send straight to endpoint port without DNAT")
		debug      = fs.Bool("debug", false, "verbose stderr diagnostics")
	)
	if err := fs.Parse(argv); err != nil {
		return args{}, err
	}
	debugEnabled = *debug
	if *sourcePort == 0 || *sourcePort > 65535 {
		return args{}, errors.New("--source-port is required (1..65535)")
	}
	if strings.TrimSpace(*endpoint) == "" {
		return args{}, errors.New("--endpoint host:port is required")
	}
	timeout := time.Duration(*timeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	return args{
		protocol:   strings.ToLower(*protocol),
		family:     strings.ToLower(*family),
		sourcePort: uint16(*sourcePort),
		flowID:     *flowID,
		phase:      *phase,
		endpoint:   *endpoint,
		timeout:    timeout,
		managedSet: *managedSet,
		tunNet:     *tunNet,
		noDNAT:     *noDNAT,
		debug:      *debug,
	}, nil
}

// endpointAddr splits host:port and resolves the host to an IPv4 address.
// A full http(s) URL (as passed by the b4 self-test controller) is accepted
// as well: the scheme, host and optional port are extracted and any path is
// ignored (the probe emits raw TCP/UDP flows, not HTTP requests).
func endpointAddr(endpoint string) (ip net.IP, port int, err error) {
	endpoint = strings.TrimSpace(endpoint)
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		parsed, parseErr := url.Parse(endpoint)
		if parseErr != nil || parsed.Host == "" {
			return nil, 0, fmt.Errorf("invalid endpoint URL %q", endpoint)
		}
		host := parsed.Hostname()
		port = 443
		if parsed.Scheme == "http" {
			port = 80
		}
		if text := parsed.Port(); text != "" {
			parsedPort, convErr := strconv.Atoi(text)
			if convErr != nil || parsedPort <= 0 || parsedPort > 65535 {
				return nil, 0, fmt.Errorf("invalid endpoint port %q", text)
			}
			port = parsedPort
		}
		ip = net.ParseIP(host)
		if ip == nil {
			addrs, lookupErr := net.LookupIP(host)
			if lookupErr != nil || len(addrs) == 0 {
				return nil, 0, fmt.Errorf("resolve %q: %v", host, lookupErr)
			}
			for _, candidate := range addrs {
				if v4 := candidate.To4(); v4 != nil {
					ip = v4
					break
				}
			}
			if ip == nil {
				return nil, 0, fmt.Errorf("resolve %q: no IPv4 address", host)
			}
		}
		if ip.To4() == nil {
			return nil, 0, fmt.Errorf("endpoint %q is not IPv4", endpoint)
		}
		return ip.To4(), port, nil
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		// allow bare host (defaults to 443)
		host, portText, err = endpoint, "443", nil
	}
	if err != nil {
		return nil, 0, err
	}
	port, err = strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return nil, 0, fmt.Errorf("invalid endpoint port %q", portText)
	}
	ip = net.ParseIP(host)
	if ip == nil {
		addrs, lookupErr := net.LookupIP(host)
		if lookupErr != nil || len(addrs) == 0 {
			return nil, 0, fmt.Errorf("resolve %q: %v", host, lookupErr)
		}
		for _, candidate := range addrs {
			if v4 := candidate.To4(); v4 != nil {
				ip = v4
				break
			}
		}
		if ip == nil {
			return nil, 0, fmt.Errorf("resolve %q: no IPv4 address", host)
		}
	}
	if ip.To4() == nil {
		return nil, 0, fmt.Errorf("endpoint %q is not IPv4", endpoint)
	}
	return ip.To4(), port, nil
}

// --- raw IPv4/TCP helpers -------------------------------------------------

func checksum16(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

func ipv4Header(saddr, daddr net.IP, totalLen int, proto int) []byte {
	header := make([]byte, 20)
	header[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(header[2:4], uint16(totalLen))
	header[8] = 64 // TTL
	header[9] = byte(proto)
	copy(header[12:16], saddr.To4())
	copy(header[16:20], daddr.To4())
	binary.BigEndian.PutUint16(header[10:12], checksum16(header))
	return header
}

func tcpHeader(sport, dport uint16, seq, ack uint32, flags byte, payloadLen int) []byte {
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], sport)
	binary.BigEndian.PutUint16(header[2:4], dport)
	binary.BigEndian.PutUint32(header[4:8], seq)
	binary.BigEndian.PutUint32(header[8:12], ack)
	header[12] = 5 << 4 // data offset 5
	header[13] = flags
	binary.BigEndian.PutUint16(header[14:16], 65535) // window
	// checksum + urgent pointer filled by tcpChecksum wrapper
	binary.BigEndian.PutUint16(header[18:20], 0)
	return header
}

func buildTCPPacket(saddr, daddr net.IP, sport, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	tcp := tcpHeader(sport, dport, seq, ack, flags, len(payload))
	tcp = append(tcp, payload...)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(saddr, daddr, tcp))
	packet := ipv4Header(saddr, daddr, 20+len(tcp), protoTCP)
	return append(packet, tcp...)
}

func tcpChecksum(saddr, daddr net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], saddr.To4())
	copy(pseudo[4:8], daddr.To4())
	pseudo[8] = 0
	pseudo[9] = protoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	combined := append(pseudo, tcp...)
	return checksum16(combined)
}

// --- tun + iptables --------------------------------------------------------

const (
	// tunIface / tunIP are the tun device and address used by the probe.
	// The device must be addressable so replies (which after reverse NAT
	// target the tun IP) are delivered locally to the raw receive socket.
	tunIface = "b4ppe0"
	tunIP    = "10.99.0.1"
	tunNet   = tunIP + "/24"

	iffTun    = 0x0001
	iffNoPI   = 0x1000
	tunSetIFF = 0x400454ca
)

// dnatPort is the local redirection port used to force the probe flow
// through the forwarded path: packets from the tun device to
// <endpoint>:dnatPort are DNATed (PREROUTING) onto the controlled endpoint
// port, so the flow is classified and observed as forwarded traffic
// (B4_PPE_FWD / B4).
const dnatPort = 32000

// tunProbe owns the probe tun device and the NAT rules that steer probe
// traffic through the forwarded path.
type tunProbe struct {
	fd         int
	endpoint   net.IP
	srcIP      net.IP
	tunIP      net.IP
	sourcePort uint16
	cleanups   []func()
}

// setupTunProbe creates the tun device, addresses it, and installs the
// DNAT (PREROUTING) + SNAT (POSTROUTING) rules that make probe packets
// traversable and observable as a forwarded flow. When noDNAT is set the
// flow is sent straight to the endpoint port instead (diagnostic mode).
// The returned probe is torn down by Close.
func setupTunProbe(ctx context.Context, endpointIP net.IP, endpointPort int, sourcePort uint16, managedSet, tunNet string, noDNAT bool) (*tunProbe, error) {
	fd, err := openTun(tunIface)
	if err != nil {
		return nil, fmt.Errorf("open tun device: %w", err)
	}
	probe := &tunProbe{fd: fd, endpoint: endpointIP, sourcePort: sourcePort}
	probe.cleanups = append(probe.cleanups, func() { syscall.Close(fd) })
	run := func(args ...string) error { return runIPTables(ctx, args...) }

	if err := runExec(ctx, "ip", "addr", "add", tunNet, "dev", tunIface); err != nil {
		probe.Close()
		return nil, fmt.Errorf("address tun device: %w", err)
	}
	if err := runExec(ctx, "ip", "link", "set", tunIface, "up"); err != nil {
		probe.Close()
		return nil, fmt.Errorf("bring up tun device: %w", err)
	}
	// A /32 tun address is not in the local table, so replies to the probe
	// source would be unroutable. Pin the source on loopback so inbound
	// SYN-ACKs (dst = tun address) reach the raw receive socket.
	if ip, _, err := net.ParseCIDR(tunNet); err == nil && ip != nil {
		probe.tunIP = ip
		if strings.HasSuffix(tunNet, "/32") {
		if err := runExec(ctx, "ip", "route", "add", tunNet, "dev", "lo"); err != nil {
			probe.Close()
			return nil, fmt.Errorf("route tun source to lo: %w", err)
		}
		probe.cleanups = append(probe.cleanups, func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = runExec(cleanupCtx, "ip", "route", "del", tunNet, "dev", "lo")
		})
		}
	}
	// Packets written into a tun device with a local source address
	// (tunNet) are dropped as martian spoofs by ip_route_input unless
	// accept_local is enabled for the interface (and, as a fallback, for
	// all). Keenetic defaults both to 0, which silently swallowed every
	// probe packet before FORWARD/INPUT. Restore 0 on teardown.
	for _, scope := range []string{
		"net.ipv4.conf." + tunIface + ".accept_local",
		"net.ipv4.conf.all.accept_local",
		// The probe source (/32 on the upstream LAN) is not configured on
		// any Ethernet interface, so the upstream gateway cannot resolve
		// its MAC for replies. proxy_arp answers on its behalf.
		"net.ipv4.conf.all.proxy_arp",
		"net.ipv4.conf." + tunIface + ".proxy_arp",
	} {
		if err := runExec(ctx, "sysctl", "-w", scope+"=1"); err != nil {
			log.Printf("[ppe-probe] warn: enable %s: %v", scope, err)
		}
		probe.cleanups = append(probe.cleanups, func(s string) func() {
			return func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = runExec(cleanupCtx, "sysctl", "-w", s+"=0")
			}
		}(scope))
	}
	srcIP, err := sourceIPFor(endpointIP)
	if err != nil {
		probe.Close()
		return nil, fmt.Errorf("determine egress source address: %w", err)
	}
	probe.srcIP = srcIP

	dnat := []string{
		"-t", "nat", "-I", "PREROUTING", "1",
		"-p", "tcp", "-d", endpointIP.String(),
		"--dport", fmt.Sprintf("%d", dnatPort),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", endpointIP.String(), endpointPort),
	}
	if !noDNAT {
		if err := run(dnat...); err != nil {
			probe.Close()
			return nil, fmt.Errorf("install probe DNAT: %w", err)
		}
		probe.cleanups = append(probe.cleanups, func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			args := append([]string{"-t", "nat", "-D", "PREROUTING"}, dnat[5:]...)
			_ = runIPTables(cleanupCtx, args...)
		})
	}
	snat := []string{
		"-t", "nat", "-I", "POSTROUTING", "1",
		"-p", "tcp", "-s", probe.tunIP.String(), "--sport", fmt.Sprintf("%d", sourcePort),
		"-d", endpointIP.String(), "--dport", fmt.Sprintf("%d", endpointPort),
		"-j", "SNAT", "--to-source", fmt.Sprintf("%s:%d", srcIP.String(), sourcePort),
	}
	if err := run(snat...); err != nil {
		probe.Close()
		return nil, fmt.Errorf("install probe SNAT: %w", err)
	}
	probe.cleanups = append(probe.cleanups, func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		args := append([]string{"-t", "nat", "-D", "POSTROUTING"}, snat[5:]...)
		_ = runIPTables(cleanupCtx, args...)
	})
	// Probe packets are untracked by conntrack on this firmware (no NAT
	// entry, tcp INVALID), so filter FORWARD's state-based accept never
	// matches and the chain's default policy (DROP) swallows the flow.
	// Explicitly accept the probe flow at the top of filter FORWARD.
	forwardAccept := []string{
		"-I", "FORWARD", "1",
		"-p", "tcp", "-s", probe.tunIP.String(), "--sport", fmt.Sprintf("%d", sourcePort),
		"-d", endpointIP.String(), "--dport", fmt.Sprintf("%d", endpointPort),
		"-j", "ACCEPT",
	}
	if err := run(forwardAccept...); err != nil {
		probe.Close()
		return nil, fmt.Errorf("install probe FORWARD accept: %w", err)
	}
	probe.cleanups = append(probe.cleanups, func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		args := append([]string{"-D", "FORWARD"}, forwardAccept[2:]...)
		_ = runIPTables(cleanupCtx, args...)
	})
	if managedSet != "" {
		// Register the tun source with the managed-source set so the PPE
		// exclusion rule matches probe traffic in the FORWARD chain.
		if err := runExec(ctx, "ipset", "add", managedSet, probe.tunIP.String()); err == nil {
			set := managedSet
			probe.cleanups = append(probe.cleanups, func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = runExec(cleanupCtx, "ipset", "del", set, probe.tunIP.String())
			})
		} else {
			debugf("managed set %s not available (%v); PPE exclusion may not match probe flow", managedSet, err)
		}
	}
	return probe, nil
}

func (p *tunProbe) Close() {
	for index := len(p.cleanups) - 1; index >= 0; index-- {
		p.cleanups[index]()
	}
	p.cleanups = nil
}

// openTun creates/attaches the named tun device via TUNSETIFF and returns
// the file descriptor. The device disappears when the fd is closed.
func openTun(name string) (int, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return -1, err
	}
	ifreq := make([]byte, 40)
	copy(ifreq[0:16], name)
	binary.LittleEndian.PutUint16(ifreq[16:18], iffTun|iffNoPI)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&ifreq[0])))
	if errno != 0 {
		syscall.Close(fd)
		return -1, errno
	}
	return fd, nil
}

func runExec(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runIPTables(ctx context.Context, args ...string) error {
	// NOTE: Keenetic ships iptables v1.4.21 without the -w (wait) flag.
	cmd := exec.CommandContext(ctx, "iptables", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

// --- TCP probe -------------------------------------------------------------

const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagACK = 0x10
)
func runTCP(ctx context.Context, a args) ProbeResult {
	result := ProbeResult{Protocol: selfTestProtocol}
	if a.family != "ipv4" {
		result.Detail = "ipv6 TCP probe not implemented"
		return result
	}
	endpointIP, endpointPort, err := endpointAddr(a.endpoint)
	if err != nil {
		result.Detail = err.Error()
		return result
	}
	probe, err := setupTunProbe(ctx, endpointIP, endpointPort, a.sourcePort, a.managedSet, a.tunNet, a.noDNAT)
	if err != nil {
		result.Detail = fmt.Sprintf("setup probe path: %v", err)
		return result
	}
	defer probe.Close()
	probePort := uint16(dnatPort)
	if a.noDNAT {
		probePort = uint16(endpointPort)
	}
	debugf("tun=%s src=%s endpoint=%s:%d probe-port=%d", tunIface, probe.srcIP, endpointIP, endpointPort, probePort)

	recvSock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, protoTCP)
	if err != nil {
		result.Detail = fmt.Sprintf("open raw receive socket (CAP_NET_RAW required): %v", err)
		return result
	}
	defer syscall.Close(recvSock)
	recvTimeout := syscall.Timeval{Sec: 1, Usec: 0}
	if err := syscall.SetsockoptTimeval(recvSock, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &recvTimeout); err != nil {
		result.Detail = fmt.Sprintf("set SO_RCVTIMEO: %v", err)
		return result
	}

	localIP := probe.tunIP
	payload1 := make([]byte, payload1Len)
	payload2 := make([]byte, payload2Len)
	rand.Read(payload1)
	rand.Read(payload2)

	// 1. SYN
	isn := rand.Uint32()
	seq := isn
	if err := sendTun(probe.fd, localIP, endpointIP, a.sourcePort, probePort, seq, 0, flagSYN, nil); err != nil {
		result.Detail = fmt.Sprintf("send SYN: %v", err)
		return result
	}
	// 2. wait for SYN-ACK (deadline capped by overall ctx)
	synackCtx, synackCancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer synackCancel()
	synackSeq, ok := waitForPacket(recvSock, endpointIP, uint16(endpointPort), a.sourcePort, probePort, synackCtx, func(tcp []byte) bool {
		return tcp[13]&flagSYN != 0 && tcp[13]&flagACK != 0 && tcp[13]&flagRST == 0
	})
	if !ok {
		result.Detail = "no SYN-ACK from controlled endpoint (flow not established)"
		return result
	}

	// 3. ACK + first payload
	seq = isn + 1
	ack := synackSeq + 1
	if err := sendTun(probe.fd, localIP, endpointIP, a.sourcePort, probePort, seq, ack, flagACK, payload1); err != nil {
		result.Detail = fmt.Sprintf("send payload1: %v", err)
		return result
	}
	// 4. disjoint second payload
	time.Sleep(120 * time.Millisecond)
	seq += uint32(len(payload1))
	if err := sendTun(probe.fd, localIP, endpointIP, a.sourcePort, probePort, seq, ack, flagACK, payload2); err != nil {
		result.Detail = fmt.Sprintf("send payload2: %v", err)
		return result
	}
	// 5. retransmission of the first payload (same seq/len)
	time.Sleep(120 * time.Millisecond)
	if err := sendTun(probe.fd, localIP, endpointIP, a.sourcePort, probePort, isn+1, ack, flagACK, payload1); err != nil {
		result.Detail = fmt.Sprintf("send retransmission: %v", err)
		return result
	}

	// 6. collect any incoming progress (ACK/RST/data) until the deadline
	incomingSeen := waitForIncoming(recvSock, endpointIP, uint16(endpointPort), a.sourcePort, probePort, ctx)

	// 7. tear the flow down with RST
	sendTun(probe.fd, localIP, endpointIP, a.sourcePort, probePort, seq+uint32(len(payload2)), ack, flagRST|flagACK, nil)

	result.ClientEmitted = true
	result.Detail = fmt.Sprintf("phase=%s flow=%s synack=yes payloads=2 retrans=yes incoming=%v", a.phase, a.flowID, incomingSeen)
	return result
}

func sendTun(fd int, saddr, daddr net.IP, sport, dport uint16, seq, ack uint32, flags byte, payload []byte) error {
	packet := buildTCPPacket(saddr, daddr, sport, dport, seq, ack, flags, payload)
	n, err := syscall.Write(fd, packet)
	debugf("tun-write src=%s sport=%d dport=%d seq=%d ack=%d flags=0x%02x payload=%d n=%d err=%v",
		saddr, sport, dport, seq, ack, flags, len(payload), n, err)
	if err == nil && n != len(packet) {
		err = fmt.Errorf("short write: %d of %d bytes", n, len(packet))
	}
	return err
}

// sourceIPFor returns the source address the kernel would use for packets to
// the given destination. A throwaway UDP connect makes the routing stack pick
// the egress interface address without sending anything.
func sourceIPFor(dst net.IP) (net.IP, error) {
	conn, err := net.Dial("udp4", net.JoinHostPort(dst.String(), "9"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)
	if local == nil || local.IP == nil {
		return nil, errors.New("no local address for destination")
	}
	return local.IP.To4(), nil
}

// waitForPacket receives raw TCP packets until predicate matches or ctx ends.
// The raw socket sees inbound segments after reverse DNAT (nat PREROUTING),
// so in DNAT mode the endpoint's replies arrive with sport == dnatPort rather
// than the endpoint port; both are accepted.
func waitForPacket(sock int, endpointIP net.IP, endpointPort, sourcePort, probePort uint16, ctx context.Context, predicate func(tcp []byte) bool) (uint32, bool) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return 0, false
		default:
		}
		n, _, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				continue
			}
			return 0, false
		}
		if n < 40 {
			continue
		}
		packet := buf[:n]
		if packet[0]>>4 != 4 {
			continue
		}
		ihl := int(packet[0]&0x0f) * 4
		if n < ihl+20 || packet[9] != protoTCP {
			continue
		}
		if !net.IP(packet[12:16]).Equal(endpointIP) {
			continue
		}
		tcp := packet[ihl:n]
		debugf("recv from %s sport=%d dport=%d seq=%d flags=0x%02x",
			net.IP(packet[12:16]), binary.BigEndian.Uint16(tcp[0:2]), binary.BigEndian.Uint16(tcp[2:4]),
			binary.BigEndian.Uint32(tcp[4:8]), tcp[13])
		if (binary.BigEndian.Uint16(tcp[0:2]) != endpointPort && binary.BigEndian.Uint16(tcp[0:2]) != probePort) || binary.BigEndian.Uint16(tcp[2:4]) != sourcePort {
			continue
		}
		if predicate(tcp) {
			return binary.BigEndian.Uint32(tcp[4:8]), true
		}
	}
}

// waitForIncoming reports whether any packet from the endpoint reached the
// probe source port before ctx ended (ACK/RST/data from the server).
// Like waitForPacket, the endpoint source port is matched before or after
// reverse DNAT (endpointPort or dnatPort).
func waitForIncoming(sock int, endpointIP net.IP, endpointPort, sourcePort, probePort uint16, ctx context.Context) bool {
	seen := false
	deadline := time.Now().Add(1500 * time.Millisecond)
	buf := make([]byte, 65536)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return seen
		default:
		}
		remain := deadline.Sub(time.Now())
		if remain <= 0 {
			break
		}
		_ = syscall.SetsockoptTimeval(sock, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 0, Usec: 200000})
		n, _, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			continue
		}
		if n < 40 || buf[0]>>4 != 4 {
			continue
		}
		ihl := int(buf[0]&0x0f) * 4
		if n < ihl+20 || buf[9] != protoTCP {
			continue
		}
		if !net.IP(buf[12:16]).Equal(endpointIP) {
			continue
		}
		tcp := buf[ihl:n]
		if (binary.BigEndian.Uint16(tcp[0:2]) != endpointPort && binary.BigEndian.Uint16(tcp[0:2]) != probePort) || binary.BigEndian.Uint16(tcp[2:4]) != sourcePort {
			continue
		}
		seen = true
		// keep draining so the socket buffer does not fill up
	}
	return seen
}

// --- QUIC/UDP probe --------------------------------------------------------

func runUDP(ctx context.Context, a args) ProbeResult {
	result := ProbeResult{Protocol: selfTestProtocol}
	if a.family != "ipv4" {
		result.Detail = "ipv6 QUIC probe not implemented"
		return result
	}
	endpointIP, endpointPort, err := endpointAddr(a.endpoint)
	if err != nil {
		result.Detail = err.Error()
		return result
	}
	probe, err := setupTunProbe(ctx, endpointIP, endpointPort, a.sourcePort, a.managedSet, a.tunNet, a.noDNAT)
	if err != nil {
		result.Detail = fmt.Sprintf("setup probe path: %v", err)
		return result
	}
	defer probe.Close()

	localIP := probe.tunIP
	probePort := uint16(dnatPort)
	if a.noDNAT {
		probePort = uint16(endpointPort)
	}
	initial := quicInitialDatagram()
	second := make([]byte, 64)
	rand.Read(second)
	for _, payload := range [][]byte{initial, second, initial} {
		if err := sendUDPTun(probe.fd, localIP, endpointIP, a.sourcePort, probePort, payload); err != nil {
			result.Detail = fmt.Sprintf("send datagram: %v", err)
			return result
		}
		time.Sleep(100 * time.Millisecond)
	}
	result.ClientEmitted = true
	result.Detail = fmt.Sprintf("phase=%s flow=%s datagrams=3", a.phase, a.flowID)
	return result
}

func sendUDPTun(fd int, saddr, daddr net.IP, sport, dport uint16, payload []byte) error {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	udp = append(udp, payload...)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(saddr, daddr, udp))
	packet := ipv4Header(saddr, daddr, 20+len(udp), protoUDP)
	packet = append(packet, udp...)
	n, err := syscall.Write(fd, packet)
	debugf("tun-write-udp src=%s sport=%d dport=%d payload=%d n=%d err=%v", saddr, sport, dport, len(payload), n, err)
	if err == nil && n != len(packet) {
		err = fmt.Errorf("short write: %d of %d bytes", n, len(packet))
	}
	return err
}

// quicInitialDatagram builds a payload that quic.LooksLikeQUIC accepts:
// long header, version, DCID/SCID length octets (see src/quic/initial.go).
func quicInitialDatagram() []byte {
	dcidLen, scidLen := 8, 8
	datagram := make([]byte, 0, 1+4+1+dcidLen+1+scidLen+32)
	datagram = append(datagram, 0xC3) // long header + fixed bit + Initial type bits
	version := []byte{0x00, 0x00, 0x00, 0x01}
	datagram = append(datagram, version...)
	datagram = append(datagram, byte(dcidLen))
	dcid := make([]byte, dcidLen)
	rand.Read(dcid)
	datagram = append(datagram, dcid...)
	datagram = append(datagram, byte(scidLen))
	scid := make([]byte, scidLen)
	rand.Read(scid)
	datagram = append(datagram, scid...)
	payload := make([]byte, 32)
	rand.Read(payload)
	datagram = append(datagram, payload...)
	return datagram
}

func udpChecksum(saddr, daddr net.IP, udp []byte) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], saddr.To4())
	copy(pseudo[4:8], daddr.To4())
	pseudo[8] = 0
	pseudo[9] = protoUDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	return checksum16(append(pseudo, udp...))
}