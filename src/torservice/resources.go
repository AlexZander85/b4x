package torservice

import "os"

func (r *Runtime) resourceSnapshot() ResourceView {
	r.mu.Lock()
	pid := os.Getpid()
	if r.proc != nil && r.proc.PID() > 0 {
		pid = r.proc.PID()
	}
	snowflakePacket := false
	if r.snowflake != nil {
		snowflakePacket = r.snowflake.DirectPacketAllowed()
	}
	ux := r.confluxUX
	r.mu.Unlock()

	p := platformResourceSnapshot(pid)
	return ResourceView{
		RSSBytes:              p.rssBytes,
		FDUsed:                p.fdUsed,
		FDLimit:               p.fdLimit,
		LowMemory:             p.lowMemory,
		SnowflakeDirectPacket: snowflakePacket,
		ConfluxUX:             ux,
	}
}

type platformResources struct {
	rssBytes  uint64
	fdUsed    int
	fdLimit   uint64
	lowMemory bool
}
