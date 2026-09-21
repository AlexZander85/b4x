package vless

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

// upgradeWebsocket performs the RFC 6455 client handshake over the already
// established (optionally TLS-wrapped) connection and returns a message-based
// net.Conn carrying the VLESS byte stream.
func (d *Dialer) upgradeWebsocket(conn net.Conn) (net.Conn, error) {
	scheme := "ws"
	if d.Node.Security == SecurityTLS || d.Node.Security == SecurityReality {
		scheme = "wss"
	}
	u := &url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(d.Node.Host, strconv.Itoa(int(d.Node.Port))),
		Path:   defPath(d.Node.Path, "/"),
	}
	header := http.Header{}
	if d.Node.HostHeader != "" {
		header.Set("Host", d.Node.HostHeader)
	}
	wsc, resp, err := websocket.NewClient(conn, u, header, 0, 0)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("vless: websocket handshake: %w (http %d)", err, resp.StatusCode)
		}
		return nil, fmt.Errorf("vless: websocket handshake: %w", err)
	}
	return &wsConn{ws: wsc}, nil
}

// wsConn adapts a gorilla websocket to net.Conn: reads drain binary messages,
// writes emit one binary message per call (the Xray ws framing).
type wsConn struct {
	ws  *websocket.Conn
	buf []byte
}

func (c *wsConn) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		mt, data, err := c.ws.ReadMessage()
		if err != nil {
			return 0, err
		}
		if mt == websocket.CloseMessage {
			return 0, io.EOF
		}
		c.buf = data
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) Close() error                       { return c.ws.Close() }
func (c *wsConn) LocalAddr() net.Addr                { return c.ws.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr               { return c.ws.RemoteAddr() }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }
func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.ws.SetReadDeadline(t); err != nil {
		return err
	}
	return c.ws.SetWriteDeadline(t)
}

// upgradeHTTPUpgrade performs the Xray httpupgrade HTTP/1.1 switch: a GET with
// Connection: Upgrade / Upgrade: websocket, then a raw byte stream after the
// 101 response (no websocket framing).
func (d *Dialer) upgradeHTTPUpgrade(conn net.Conn) (net.Conn, error) {
	path := defPath(d.Node.Path, "/")
	host := d.Node.HostHeader
	if host == "" {
		host = net.JoinHostPort(d.Node.Host, strconv.Itoa(int(d.Node.Port)))
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, fmt.Errorf("vless: httpupgrade request: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("vless: httpupgrade response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("vless: httpupgrade status %d", resp.StatusCode)
	}
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// bufferedConn keeps bytes already buffered by the HTTP response reader.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
