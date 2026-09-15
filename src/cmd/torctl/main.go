// Command torctl is the E-TOR CLI (patch-plan §9, design §9.6 — the
// fxvpnctl canon of a thin standalone binary). Unlike fxvpnctl (which
// talks to the upstream control plane directly), torctl talks to the
// RUNNING DAEMON's HTTP API: the tor runtime is a supervised child of b4,
// a second driver would race the supervisor. Subcommands:
//
//	torctl status            — full status JSON
//	torctl entry <mode>      — switch the entry mode (persisted)
//	torctl bridges           — stored bridge list
//	torctl bridges-refresh   — force one conveyor pass
//	torctl newnym            — rotate circuits
//	torctl restart           — teardown + restart from the winner
//	torctl test              — liveness + exit probes on demand
//
// Output is JSON (never secrets — the status projection is redacted by
// construction). Exit codes: 0 ok, 1 error, 2 usage.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const defaultBaseURL = "http://127.0.0.1:8055"

const (
	exitOK    = 0
	exitErr   = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) < 1 {
		usage()
		return exitUsage
	}
	fs := flag.NewFlagSet("torctl", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	baseURL := fs.String("base", defaultBaseURL, "daemon base URL (http://host:port)")
	token := fs.String("token", os.Getenv("B4_TOKEN"), "API bearer token (or B4_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() < 1 {
		usage()
		return exitUsage
	}
	cmd := fs.Arg(0)
	c := &client{base: strings.TrimSuffix(*baseURL, "/"), token: *token}
	switch cmd {
	case "status":
		return c.get("/api/tor/status")
	case "bridges":
		return c.get("/api/tor/bridges")
	case "bridges-refresh":
		return c.post("/api/tor/bridges/refresh")
	case "newnym":
		return c.post("/api/tor/newnym")
	case "restart":
		return c.post("/api/tor/restart")
	case "entry":
		if fs.NArg() != 2 {
			fmt.Fprintln(os.Stderr, "usage: torctl entry <auto|webtunnel|obfs4|snowflake|meek|vanilla|direct>")
			return exitUsage
		}
		return c.putJSON("/api/tor/entry", map[string]string{"mode": fs.Arg(1)})
	case "test":
		return c.test()
	default:
		fmt.Fprintf(os.Stderr, "torctl: unknown command %q\n", cmd)
		usage()
		return exitUsage
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: torctl [flags] <command>

commands:
  status            full E-TOR status (JSON)
  entry <mode>      switch entry mode: auto|webtunnel|obfs4|snowflake|meek|vanilla|direct
  bridges           stored bridge list (JSON)
  bridges-refresh   force one bridge collection pass
  newnym            rotate tor circuits
  restart           teardown + restart from the winner entry
  test              liveness + exit probes on demand

flags:
`)
}

type client struct {
	base  string
	token string
}

func (c *client) do(method, path string, body []byte) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := (&http.Client{Timeout: 120 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, payload, nil
}

func (c *client) get(path string) int {
	code, body, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "torctl: %v\n", err)
		return exitErr
	}
	return emit(code, body)
}

func (c *client) post(path string) int {
	code, body, err := c.do(http.MethodPost, path, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "torctl: %v\n", err)
		return exitErr
	}
	return emit(code, body)
}

func (c *client) putJSON(path string, payload any) int {
	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "torctl: %v\n", err)
		return exitErr
	}
	code, respBody, err := c.do(http.MethodPut, path, body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "torctl: %v\n", err)
		return exitErr
	}
	return emit(code, respBody)
}

// test: status first (the honest shapes), then a targeted verdict.
func (c *client) test() int {
	code, body, err := c.do(http.MethodGet, "/api/tor/status", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "torctl: %v\n", err)
		return exitErr
	}
	if code != http.StatusOK {
		return emit(code, body)
	}
	var st struct {
		Enabled   bool   `json:"enabled"`
		Listening bool   `json:"listening"`
		State     string `json:"state"`
		Exit      struct {
			IP      string `json:"ip"`
			Country string `json:"country"`
			IsTor   bool   `json:"is_tor"`
		} `json:"exit"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		fmt.Fprintf(os.Stderr, "torctl: decode status: %v\n", err)
		return exitErr
	}
	verdict := map[string]any{
		"enabled":   st.Enabled,
		"listening": st.Listening,
		"state":     st.State,
	}
	if st.Listening {
		verdict["exit_probe"] = map[string]any{
			"ip":      st.Exit.IP,
			"country": st.Exit.Country,
			"is_tor":  st.Exit.IsTor,
			// liveness = the exit probe SUCCEEDED through tor
			"liveness": st.Exit.IP != "",
		}
	}
	out, _ := json.MarshalIndent(verdict, "", "  ")
	fmt.Println(string(out))
	if !st.Enabled {
		return exitErr
	}
	return exitOK
}

func emit(code int, body []byte) int {
	var pretty bytes.Buffer
	if json.Indent(&pretty, body, "", "  ") == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(body))
	}
	if code >= 400 {
		return exitErr
	}
	return exitOK
}
