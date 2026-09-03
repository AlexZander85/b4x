package transportwarp

import (
	"encoding/binary"
	"sync"
)

// newFramePool builds a sync.Pool of outbound frame buffers sized for the
// configured inner MTU plus wire headroom. Both the H2 (CONNECT) and H3
// (QUIC datagram) uplink paths prepend up to two QUIC/HTTP varints to the IP
// packet, so the largest needed frame is headroom + MTU. Reusing these buffers
// across packets removes one allocation and one copy from the hot uplink path
// (KPI-3; addendum §43).
func newFramePool(mtu int) *sync.Pool {
	return &sync.Pool{
		New: func() any {
			buf := make([]byte, 0, 2*binary.MaxVarintLen64+mtu)
			return &buf
		},
	}
}

// getFrame borrows a frame; the returned *[]byte is reset to zero length but
// keeps its backing array.
func getFrame(p *sync.Pool) *[]byte {
	buf := p.Get().(*[]byte)
	*buf = (*buf)[:0]
	return buf
}

// putFrame returns a borrowed frame to its pool. Borrowers must put the frame
// back only after the network write (or SendDatagram) has returned, so the
// bytes have been fully copied out.
func putFrame(p *sync.Pool, buf *[]byte) {
	p.Put(buf)
}
