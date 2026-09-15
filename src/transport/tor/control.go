package tor

// Minimal tor control-protocol client (patch-plan §7.1): cookie-auth +
// GETINFO + SIGNAL + SETCONF. The parser preserves multiline boundaries so
// a `250+key=` data block can never swallow subsequent reply keys.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	controlReplyOK     = 250
	controlErrWildcard = '5'
	controlReadTimeout = 10 * time.Second
)

type ControlClient interface {
	Authenticate(cookie []byte) error
	GetInfo(keys ...string) (map[string]string, error)
	Signal(s string) error
	SetConf(kv ...[2]string) error
	Close() error
}

type ControlError struct {
	Code int
	Line string
}

func (e *ControlError) Error() string {
	return fmt.Sprintf("tor control %d: %s", e.Code, e.Line)
}

var ErrControlProtocol = errors.New("tor control protocol violation")

type realControlClient struct {
	conn net.Conn
	rw   *bufio.ReadWriter
	mu   sync.Mutex
}

func DialControl(ctx context.Context, network, addr string) (ControlClient, error) {
	d := net.Dialer{Timeout: controlReadTimeout}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("tor control dial: %w", err)
	}
	return &realControlClient{
		conn: conn,
		rw:   bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
	}, nil
}

func (c *realControlClient) Authenticate(cookie []byte) error {
	line := "AUTHENTICATE " + strings.ToLower(hexEncode(cookie))
	reply, err := c.roundtrip(line)
	if err != nil {
		return err
	}
	if code, _ := splitReply(reply); code != controlReplyOK {
		return replyError(reply)
	}
	return nil
}

func (c *realControlClient) GetInfo(keys ...string) (map[string]string, error) {
	if len(keys) == 0 {
		return map[string]string{}, nil
	}
	reply, err := c.roundtrip("GETINFO " + strings.Join(keys, " "))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	lines := strings.Split(reply, "\n")
	for i := 0; i < len(lines); i++ {
		l := strings.TrimRight(lines[i], "\r")
		if l == "" || l == "." {
			continue
		}
		code, rest, ok := splitReplyLine(l)
		if !ok {
			return nil, fmt.Errorf("%w: GETINFO reply %q", ErrControlProtocol, l)
		}
		if code >= 500 {
			return nil, &ControlError{Code: code, Line: rest}
		}
		if code == controlReplyOK && rest == "OK" {
			continue
		}
		if strings.HasPrefix(l, strconv.Itoa(controlReplyOK)+"+") {
			key := strings.TrimSuffix(rest, "=")
			var body []string
			foundTerminator := false
			i++
			for ; i < len(lines); i++ {
				ml := strings.TrimRight(lines[i], "\r")
				if ml == "." {
					foundTerminator = true
					break
				}
				body = append(body, ml)
			}
			if !foundTerminator {
				return nil, fmt.Errorf("%w: unterminated GETINFO multiline value %q", ErrControlProtocol, key)
			}
			out[key] = strings.Join(body, "\n")
			continue
		}
		if eq := strings.IndexByte(rest, '='); eq > 0 && code == controlReplyOK {
			out[rest[:eq]] = rest[eq+1:]
		}
	}
	return out, nil
}

func (c *realControlClient) Signal(s string) error {
	reply, err := c.roundtrip("SIGNAL " + s)
	if err != nil {
		return err
	}
	if code, _ := splitReply(reply); code != controlReplyOK {
		return replyError(reply)
	}
	return nil
}

func (c *realControlClient) SetConf(kv ...[2]string) error {
	if len(kv) == 0 {
		return nil
	}
	parts := make([]string, 0, len(kv))
	for _, pair := range kv {
		parts = append(parts, pair[0]+"="+pair[1])
	}
	reply, err := c.roundtrip("SETCONF " + strings.Join(parts, " "))
	if err != nil {
		return err
	}
	if code, _ := splitReply(reply); code != controlReplyOK {
		return replyError(reply)
	}
	return nil
}

func (c *realControlClient) Close() error { return c.conn.Close() }

// roundtrip writes one command and reads the complete reply block. For a
// `250+` data block the terminating dot is deliberately retained in the
// returned transcript; GetInfo uses it as the unambiguous boundary before
// any following `250-` key/value lines.
func (c *realControlClient) roundtrip(cmd string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.conn.SetDeadline(time.Now().Add(controlReadTimeout)); err != nil {
		return "", err
	}
	if _, err := c.rw.WriteString(cmd + "\r\n"); err != nil {
		return "", fmt.Errorf("tor control write: %w", err)
	}
	if err := c.rw.Flush(); err != nil {
		return "", fmt.Errorf("tor control flush: %w", err)
	}
	var lines []string
	for {
		line, err := c.rw.ReadString('\n')
		if err != nil {
			if err == io.EOF && len(lines) > 0 {
				break
			}
			return "", fmt.Errorf("tor control read: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		code, rest, ok := splitReplyLine(line)
		if !ok {
			return "", fmt.Errorf("%w: %q", ErrControlProtocol, line)
		}
		if strings.HasPrefix(line, strconv.Itoa(controlReplyOK)+"+") {
			for {
				ml, err := c.rw.ReadString('\n')
				if err != nil {
					return "", fmt.Errorf("tor control read multiline: %w", err)
				}
				ml = strings.TrimRight(ml, "\r\n")
				lines = append(lines, ml)
				if ml == "." {
					break
				}
			}
			continue
		}
		if code == controlReplyOK && (strings.HasPrefix(line, strconv.Itoa(controlReplyOK)+" ") || line == strconv.Itoa(controlReplyOK)) {
			break
		}
		if code >= 500 {
			break
		}
		_ = rest
	}
	return strings.Join(lines, "\n"), nil
}

func splitReply(block string) (int, string) {
	first := block
	if i := strings.IndexByte(block, '\n'); i >= 0 {
		first = block[:i]
	}
	code, rest, _ := splitReplyLine(first)
	return code, rest
}

func splitReplyLine(line string) (int, string, bool) {
	if len(line) < 3 {
		return 0, "", false
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, "", false
	}
	rest := ""
	if len(line) > 4 {
		rest = line[4:]
	}
	return code, rest, true
}

func replyError(block string) error {
	code, rest := splitReply(block)
	if code == 0 {
		return fmt.Errorf("%w: %q", ErrControlProtocol, block)
	}
	return &ControlError{Code: code, Line: rest}
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0x0f])
	}
	return string(out)
}

func ParseBootstrapPhase(v string) (progress int, tag, summary string) {
	for _, field := range strings.Fields(v) {
		switch {
		case strings.HasPrefix(field, "PROGRESS="):
			progress, _ = strconv.Atoi(strings.TrimPrefix(field, "PROGRESS="))
		case strings.HasPrefix(field, "TAG="):
			tag = strings.TrimPrefix(field, "TAG=")
		case strings.HasPrefix(field, "SUMMARY="):
			summary = strings.Trim(strings.TrimPrefix(field, "SUMMARY="), `"`)
		}
	}
	return progress, tag, summary
}
