//go:build linux

package fxvpn

import (
        "errors"
        "fmt"
        "net"
        "syscall"

        "golang.org/x/sys/unix"
)

// applyControlPlatform pins the socket per policy. Every constraint is
// applied-or-fail: a partial application must not silently produce an
// unpinned socket (addendum §18). A TTL-only policy (the preflight-fake
// bait socket) applies just the hop limit.
func applyControlPlatform(p DialPolicy, c syscall.RawConn) error {
        if !p.Constrained() && !p.RequireMark && !p.ttlActive() {
                return nil
        }
        var ctrlErr error
        err := c.Control(func(fd uintptr) {
                raw := int(fd)
                if p.FwMark != 0 {
                        ctrlErr = unix.SetsockoptInt(raw, unix.SOL_SOCKET, unix.SO_MARK, int(p.FwMark))
                        if ctrlErr != nil {
                                return
                        }
                }
                if p.BindDevice != "" {
                        iface, err := net.InterfaceByName(p.BindDevice)
                        if err != nil {
                                ctrlErr = fmt.Errorf("fxvpn: bind device %q: %w", p.BindDevice, err)
                                return
                        }
                        ctrlErr = unix.BindToDevice(raw, iface.Name)
                        if ctrlErr != nil {
                                return
                        }
                }
                if p.TTL > 0 {
                        // The bait must die in transit (masquerade §7.4.1); family
                        // option picked by the socket domain of THIS socket.
                        domain, derr := unix.GetsockoptInt(raw, unix.SOL_SOCKET, unix.SO_DOMAIN)
                        if derr != nil {
                                ctrlErr = fmt.Errorf("fxvpn: ttl socket domain: %w", derr)
                                return
                        }
                        level, opt := unix.IPPROTO_IP, unix.IP_TTL
                        if domain == unix.AF_INET6 {
                                level, opt = unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS
                        }
                        if terr := unix.SetsockoptInt(raw, level, opt, p.TTL); terr != nil {
                                ctrlErr = fmt.Errorf("fxvpn: ttl %d: %w", p.TTL, terr)
                                return
                        }
                }
                if p.RequireMark && p.FwMark == 0 {
                        ctrlErr = errors.New("fxvpn: policy requires SO_MARK but none configured")
                }
        })
        if err != nil {
                return err
        }
        return ctrlErr
}
