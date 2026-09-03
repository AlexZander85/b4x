package tun

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/engine"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/nfq"
	"github.com/daniellavrushin/b4/routing"
	"github.com/daniellavrushin/b4/sock"
)

const (
	tunBufSize        = 65536
	defaultDeviceName = "b4tun0"
	defaultAddress    = "10.255.0.1/30"
	defaultRouteTable = 9999
)

type Engine struct {
	cfg           atomic.Pointer[config.Config]
	pool          *nfq.Pool
	tunFile       *os.File
	tunName       string
	routes        *routeManager
	sender        *sock.Sender
	clientSender  *sock.Sender
	trigger       chan struct{}
	egressW       *egressWatcher
	wg            sync.WaitGroup
	quit          chan struct{}
	stopOnce      sync.Once
	fwdCount      uint64
	fwdErrCount   uint64
	v6DropCount   uint64
	lastFwdErrLog int64

	decisions     *routing.DecisionStore
	markSenders   map[uint32]*sock.Sender
	markSendersMu sync.Mutex
}

const maxMarkSenders = 16

func NewEngine(cfg *config.Config, pool *nfq.Pool) *Engine {
	e := &Engine{
		pool:        pool,
		quit:        make(chan struct{}),
		markSenders: make(map[uint32]*sock.Sender),
	}
	e.cfg.Store(cfg)
	return e
}

// SetRouteDecisions wires the shared route decision store produced by the
// NFQUEUE authorized route path. The engine only reads decisions to pick a
// per-mark sender; it never consults the fallback manager itself (FB-23).
func (e *Engine) SetRouteDecisions(store *routing.DecisionStore) {
	e.decisions = store
}

func (e *Engine) config() *config.Config {
	return e.cfg.Load()
}

func (e *Engine) UpdateConfig(cfg *config.Config) {
	e.cfg.Store(cfg)
}

func (e *Engine) Start() error {
	cfg := e.config()
	tunCfg := &cfg.Queue.TUN
	deviceName := tunCfg.DeviceName
	if deviceName == "" {
		deviceName = defaultDeviceName
	}
	address := tunCfg.Address
	if address == "" {
		address = defaultAddress
	}
	routeTable := tunCfg.RouteTable
	if routeTable == 0 {
		routeTable = defaultRouteTable
	}

	for _, w := range e.pool.Workers {
		if err := w.InitSender(); err != nil {
			return err
		}
	}

	if tunCfg.OutInterface != "" && deviceName == tunCfg.OutInterface {
		return log.Errorf("TUN: device_name %q must not equal out_interface", deviceName)
	}
	if interfaceExists(deviceName) {
		if !isTunDevice(deviceName) {
			return log.Errorf("TUN: device_name %q is an existing non-TUN interface; refusing to delete it", deviceName)
		}
		log.Infof("TUN: removing pre-existing TUN device %s (stale from a previous run)", deviceName)
		run("ip", "link", "del", deviceName)
	}

	f, name, err := openTUN(deviceName)
	if err != nil {
		return err
	}
	e.tunFile = f
	e.tunName = name
	log.Infof("TUN: opened device %s", name)

	sender, err := sock.NewSenderWithMark(int(capture.ProcessedMarkFor(cfg.Queue.Mark)) | engine.ReinjectMarkBit)
	if err != nil {
		e.tunFile.Close()
		run("ip", "link", "del", name)
		return err
	}
	e.sender = sender

	replyCapture := replyCaptureNeeded(cfg)
	if replyCapture {
		clientSender, err := sock.NewSenderWithMark(defaultClientMark)
		if err != nil {
			sender.Close()
			e.tunFile.Close()
			run("ip", "link", "del", name)
			return err
		}
		e.clientSender = clientSender
		log.Infof("TUN: reply-direction RST capture enabled (experimental; RST protection / escalation). Validate on a real device")
	}

	captureTable := routeTable - 1
	if captureTable <= 0 {
		captureTable = routeTable + 1
	}

	tcpLimit := cfg.Queue.TCPConnBytesLimit
	if tcpLimit <= 0 {
		tcpLimit = 19
	}
	udpLimit := cfg.Queue.UDPConnBytesLimit
	if udpLimit <= 0 {
		udpLimit = 8
	}

	dupV4, _ := cfg.CollectDuplicateIPs()

	e.routes = &routeManager{
		tunName:      name,
		tunAddr:      address,
		tunAddrV6:    tunCfg.AddressV6,
		outIface:     tunCfg.OutInterface,
		outGateway:   tunCfg.OutGateway,
		mark:         cfg.Queue.Mark,
		routeTable:   routeTable,
		skipTables:   cfg.System.Tables.SkipSetup,
		captureTable: captureTable,
		tcpPorts:     normalizePorts(cfg.CollectTCPPorts()),
		udpPorts:     normalizePorts(cfg.CollectUDPPorts()),
		tcpLimit:     tcpLimit,
		udpLimit:     udpLimit,
		dupIPs:       dupV4,
		replyCapture: replyCapture,

		devicesEnabled: cfg.Queue.Devices.Enabled,
		whiteIsBlack:   cfg.Queue.Devices.WhiteIsBlack,
		selectedMACs:   cfg.Queue.Devices.SelectedMACs(),

		followDefault: tunCfg.FollowsDefaultRoute(),
	}
	if err := e.routes.setup(); err != nil {
		e.routes.teardown()
		sender.Close()
		e.tunFile.Close()
		return err
	}

	if !cfg.System.Tables.SkipSetup {
		e.pool.EnableTUNSourceResolver(e.routes.currentSrcIP())
	}

	threads := cfg.Queue.Threads
	if threads < 1 {
		threads = 1
	}
	for i := 0; i < threads; i++ {
		e.wg.Add(1)
		go e.readLoop(i)
	}

	log.Infof("TUN: started %d reader threads", threads)

	e.trigger = make(chan struct{}, 1)
	e.wg.Add(1)
	go e.reconcileLoop()

	e.egressW = newEgressWatcher(e.triggerReconcile)
	if err := e.egressW.Start(); err != nil {
		log.Warnf("TUN: egress netlink watcher disabled (%v); falling back to periodic reconcile poll", err)
		e.egressW = nil
	}

	return nil
}

func (e *Engine) reconcileLoop() {
	defer e.wg.Done()

	interval := time.Duration(e.config().System.Tables.MonitorInterval) * time.Second
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-e.quit:
			return
		case <-e.trigger:
			if e.routes != nil {
				e.routes.reconcile()
				e.pool.UpdateTUNSourceWAN(e.routes.currentSrcIP())
			}
		case <-ticker.C:
			if e.routes != nil {
				e.routes.reconcile()
				e.pool.UpdateTUNSourceWAN(e.routes.currentSrcIP())
			}
		}
	}
}

func (e *Engine) readLoop(workerIdx int) {
	defer e.wg.Done()

	worker := e.pool.Workers[workerIdx%len(e.pool.Workers)]
	buf := make([]byte, tunBufSize)

	for {
		select {
		case <-e.quit:
			return
		default:
		}

		n, err := e.tunFile.Read(buf)
		if err != nil {
			select {
			case <-e.quit:
				return
			default:
			}
			log.Errorf("TUN: read error: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n == 0 {
			continue
		}

		raw := buf[:n]
		if worker.ProcessPacket(raw) == engine.VerdictAccept {
			e.forwardPacket(raw)
		}
	}
}

func (e *Engine) forwardPacket(raw []byte) {
	if len(raw) == 0 {
		return
	}
	switch raw[0] >> 4 {
	case 4:
		if len(raw) < 20 {
			return
		}
		if err := e.senderFor(raw).SendIPv4(raw, raw[16:20]); err != nil {
			e.logForwardError(err, net.IP(raw[12:16]).String(), net.IP(raw[16:20]).String())
			return
		}
	case 6:
		atomic.AddUint64(&e.v6DropCount, 1)
		return
	default:
		return
	}
	atomic.AddUint64(&e.fwdCount, 1)
}

func (e *Engine) senderFor(raw []byte) *sock.Sender {
	if e.clientSender == nil || e.routes == nil {
		return e.sender
	}
	ihl := int(raw[0]&0x0f) * 4
	if ihl < 20 || raw[9] != 6 || len(raw) < ihl+2 {
		return e.sender
	}
	sport := uint16(raw[ihl])<<8 | uint16(raw[ihl+1])
	if portMatches(sport, e.routes.tcpPorts) {
		return e.clientSender
	}
	// FB-23: when the authorized route path decided a non-zero SO_MARK for
	// this client flow (e.g. generic or proxy escape), forward the packet
	// through a sender that carries that mark so the kernel policy routing
	// applies the same rule table the decision described. Missing decisions
	// or sender creation failures keep the default sender (fail-open).
	if e.decisions != nil && len(raw) >= ihl+4 {
		dport := uint16(raw[ihl+2])<<8 | uint16(raw[ihl+3])
		dst := net.IP(raw[16:20])
		dstIP, ok := netip.AddrFromSlice(dst)
		if ok {
			clientIP, ok := netip.AddrFromSlice(net.IP(raw[12:16]))
			if ok {
				decision, found := e.decisions.LookupFlow(clientIP.Unmap(), dstIP.Unmap(), dport, 6)
				if found && decision.SOMark != 0 && decision.Route != routing.RouteNative && decision.Route != routing.RouteDirect {
					if marked := e.senderForMark(decision.SOMark); marked != nil {
						return marked
					}
				}
			}
		}
	}
	return e.sender
}

// senderForMark returns (creating on first use) a bounded set of raw senders
// that carry the given SO_MARK. Sender creation fails are fail-open: a nil
// return keeps the default sender.
func (e *Engine) senderForMark(mark uint32) *sock.Sender {
	e.markSendersMu.Lock()
	defer e.markSendersMu.Unlock()
	if s, ok := e.markSenders[mark]; ok {
		return s
	}
	if len(e.markSenders) >= maxMarkSenders {
		// Bounded state: never grow the raw-socket set without limit. The
		// oldest entry is closed and replaced (FIFO eviction).
		for oldMark, old := range e.markSenders {
			if old != nil {
				old.Close()
			}
			delete(e.markSenders, oldMark)
			break
		}
	}
	s, err := sock.NewSenderWithMark(int(mark))
	if err != nil {
		log.Warnf("TUN: failed to create marked sender for mark %d (%v); using default sender", mark, err)
		return nil
	}
	e.markSenders[mark] = s
	return s
}

func replyCaptureNeeded(cfg *config.Config) bool {
	for _, set := range cfg.Sets {
		if set == nil || !set.Enabled {
			continue
		}
		if set.TCP.RSTProtection.Enabled || set.Escalate.To != "" {
			return true
		}
	}
	return false
}

func (e *Engine) triggerReconcile() {
	select {
	case e.trigger <- struct{}{}:
	default:
	}
}

func (e *Engine) logForwardError(err error, src, dst string) {
	n := atomic.AddUint64(&e.fwdErrCount, 1)
	now := time.Now().Unix()
	last := atomic.LoadInt64(&e.lastFwdErrLog)
	if now-last >= 5 && atomic.CompareAndSwapInt64(&e.lastFwdErrLog, last, now) {
		log.Warnf("TUN: failed to forward packet out %s (%d errors, %d ok): %v [last fail %s -> %s]",
			e.config().Queue.TUN.OutInterface, n, atomic.LoadUint64(&e.fwdCount), err, src, dst)
	}
}

func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		if e.egressW != nil {
			e.egressW.Stop()
		}
		close(e.quit)

		if e.tunFile != nil {
			e.tunFile.Close()
		}

		e.wg.Wait()

		if e.routes != nil {
			e.routes.teardown()
		}
		if e.sender != nil {
			e.sender.Close()
		}
		if e.clientSender != nil {
			e.clientSender.Close()
		}
		e.markSendersMu.Lock()
		for mark, s := range e.markSenders {
			if s != nil {
				s.Close()
			}
			delete(e.markSenders, mark)
		}
		e.markSendersMu.Unlock()

		log.Infof("TUN: engine stopped (%d packets forwarded, %d forward errors, %d ipv6 dropped)",
			atomic.LoadUint64(&e.fwdCount), atomic.LoadUint64(&e.fwdErrCount), atomic.LoadUint64(&e.v6DropCount))
	})
}
