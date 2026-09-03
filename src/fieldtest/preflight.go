package fieldtest

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/validation"
)

// EnvPreflight is the local controller discovery result. Missing tools are
// recorded as BLOCKED, never as PASS.
type EnvPreflight struct {
	CheckedAt          time.Time                `json:"checked_at"`
	GOOS               string                   `json:"goos"`
	GOARCH             string                   `json:"goarch"`
	Docker             Check                    `json:"docker"`
	ADB                Check                    `json:"adb"`
	SSH                Check                    `json:"ssh"`
	RouterHTTP         Check                    `json:"router_http"`
	RouterSSH          Check                    `json:"router_ssh"`
	HostPreflight      validation.HostPreflight `json:"host_preflight"`
	AndroidSerial      string                   `json:"android_serial,omitempty"`
	AndroidPackages    map[string]string        `json:"android_packages,omitempty"`
	WindowsLANIP       string                   `json:"windows_lan_ip,omitempty"`
	ResultsDirWritable bool                     `json:"results_dir_writable"`
	Ready              bool                     `json:"ready"`
	Blocking           []string                 `json:"blocking,omitempty"`
}

type Check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"`
	Blocked string `json:"blocked,omitempty"`
}

// DiscoverEnv runs read-only environment discovery for b4-field-test preflight.
func DiscoverEnv(ctx context.Context, baseURL, resultsDir, routerHost string) EnvPreflight {
	if ctx == nil {
		ctx = context.Background()
	}
	p := EnvPreflight{
		CheckedAt:       time.Now().UTC(),
		GOOS:            runtime.GOOS,
		GOARCH:          runtime.GOARCH,
		HostPreflight:   validation.RunHostPreflight(),
		AndroidPackages: map[string]string{},
	}
	p.Docker = lookPathCheck("docker", "version")
	p.ADB = lookPathCheck("adb", "version")
	p.SSH = lookPathCheck("ssh", "-V")
	if ip := strings.TrimSpace(os.Getenv("B4_WINDOWS_LAN_IP")); ip != "" {
		p.WindowsLANIP = ip
	} else {
		p.WindowsLANIP = firstNonLoopbackIPv4()
	}
	if resultsDir != "" {
		if err := os.MkdirAll(resultsDir, 0o755); err == nil {
			f, err := os.CreateTemp(resultsDir, ".write-test-*")
			if err == nil {
				p.ResultsDirWritable = true
				_ = f.Close()
				_ = os.Remove(f.Name())
			}
		}
	}
	if baseURL != "" {
		p.RouterHTTP = probeHTTP(ctx, strings.TrimRight(baseURL, "/")+"/api/version")
	} else {
		p.RouterHTTP = Check{Name: "router_http", Blocked: "B4_BASE_URL not set"}
	}
	if routerHost != "" {
		p.RouterSSH = probeTCP(ctx, routerHost, "22")
	} else if host := os.Getenv("B4_ROUTER_HOST"); host != "" {
		p.RouterSSH = probeTCP(ctx, host, "22")
	} else {
		p.RouterSSH = Check{Name: "router_ssh", Blocked: "B4_ROUTER_HOST not set"}
	}
	if p.ADB.OK {
		serial, pkgs, detail := discoverADB(ctx)
		p.AndroidSerial = serial
		p.AndroidPackages = pkgs
		if serial == "" {
			p.ADB.OK = false
			p.ADB.Blocked = "no authorised device"
			p.ADB.Detail = detail
		} else {
			p.ADB.Detail = detail
		}
	}

	if !p.HostPreflight.Ready() {
		p.Blocking = append(p.Blocking, "host registry preflight")
	}
	if !p.ResultsDirWritable {
		p.Blocking = append(p.Blocking, "results dir not writable")
	}
	if !p.RouterHTTP.OK {
		p.Blocking = append(p.Blocking, "router HTTP")
	}
	// Router SSH is required for the scoped fault/rollback stages; a host
	// configured but unreachable on :22 is a preflight block, not a skip.
	if p.RouterSSH.Blocked != "" && (os.Getenv("B4_ROUTER_HOST") != "" || routerHost != "") {
		p.Blocking = append(p.Blocking, "router SSH: "+p.RouterSSH.Blocked)
	}
	// ADB present but no authorised device = fail-closed preflight block.
	// Missing adb.exe on PATH is recorded as a block as well (the Android
	// stages cannot be proven without it).
	if !p.ADB.OK {
		p.Blocking = append(p.Blocking, "android ADB: "+p.ADB.Blocked)
	}
	p.Ready = len(p.Blocking) == 0
	return p
}

func lookPathCheck(name string, args ...string) Check {
	c := Check{Name: name}
	path, err := exec.LookPath(name)
	if err != nil {
		c.Blocked = name + " not on PATH"
		return c
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	out, err := cmd.CombinedOutput()
	c.Detail = strings.TrimSpace(string(out))
	if len(c.Detail) > 240 {
		c.Detail = c.Detail[:240]
	}
	c.OK = err == nil || (name == "ssh" && strings.Contains(strings.ToLower(c.Detail), "openssh"))
	if !c.OK && c.Detail == "" {
		c.Blocked = err.Error()
	}
	if name == "ssh" && strings.Contains(strings.ToLower(string(out)), "openssh") {
		c.OK = true
		c.Blocked = ""
	}
	return c
}

func probeHTTP(ctx context.Context, url string) Check {
	c := Check{Name: "router_http"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		c.Blocked = err.Error()
		return c
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.Blocked = err.Error()
		return c
	}
	defer resp.Body.Close()
	c.Detail = fmt.Sprintf("status=%d", resp.StatusCode)
	c.OK = resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized
	if !c.OK {
		c.Blocked = c.Detail
	}
	return c
}

func probeTCP(ctx context.Context, host, port string) Check {
	c := Check{Name: "router_ssh"}
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		c.Blocked = err.Error()
		return c
	}
	_ = conn.Close()
	c.OK = true
	c.Detail = net.JoinHostPort(host, port)
	return c
}

// firstNonLoopbackIPv4 returns the host LAN IPv4 suitable as the FaultLab
// target for the router/phone. Virtual adapters (WSL, Hyper-V, Docker,
// Tailscale) are explicitly rejected: their addresses are not reachable
// from the Keenetic LAN.
func firstNonLoopbackIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	// Two passes: real interfaces first, virtual ones only as a last resort.
	real, virtual := []string{}, []string{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil || ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if isVirtualIfaceName(iface.Name) {
				virtual = append(virtual, ip.String())
			} else {
				real = append(real, ip.String())
			}
		}
	}
	if len(real) > 0 {
		return real[0]
	}
	if len(virtual) > 0 {
		return virtual[0]
	}
	return ""
}

func isVirtualIfaceName(name string) bool {
	n := strings.ToLower(name)
	for _, v := range []string{"vethernet", "wsl", "hyper-v", "docker", "vswitch", "tailscale", "default switch", "loopback"} {
		if strings.Contains(n, v) {
			return true
		}
	}
	return false
}

func discoverADB(ctx context.Context) (serial string, pkgs map[string]string, detail string) {
	pkgs = map[string]string{}
	out, err := exec.CommandContext(ctx, "adb", "devices", "-l").CombinedOutput()
	detail = strings.TrimSpace(string(out))
	if err != nil {
		return "", pkgs, detail
	}
	for _, line := range strings.Split(detail, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List of devices") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "device" {
			serial = fields[0]
			break
		}
	}
	if serial == "" {
		return "", pkgs, detail
	}
	want := map[string][]string{
		"official_youtube": {"com.google.android.youtube"},
		"revanced":         {"app.revanced.android.youtube", "app.rvx.android.youtube"},
		"telegram":         {"org.telegram.messenger", "org.telegram.messenger.web"},
		"gmail":            {"com.google.android.gm"},
		"google_app":       {"com.google.android.googlequicksearchbox"},
	}
	plist, err := exec.CommandContext(ctx, "adb", "-s", serial, "shell", "pm", "list", "packages").CombinedOutput()
	if err != nil {
		return serial, pkgs, detail
	}
	installed := string(plist)
	for role, candidates := range want {
		for _, pkg := range candidates {
			if strings.Contains(installed, pkg) {
				pkgs[role] = pkg
				break
			}
		}
	}
	return serial, pkgs, detail
}

func (p EnvPreflight) JSON() []byte {
	b, _ := json.MarshalIndent(p, "", "  ")
	return append(b, '\n')
}
