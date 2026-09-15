package tor

// Builtin snowflake sets (design §4.1 source #1, TOR-1 canon): embedded
// CDN77/AMP lines so the snowflake entry never waits for collection —
// "no point waiting for the full conveyor when the builtin set already
// dials". The CDN77 lines are VERBATIM from the pinned dependency's
// client/torrc (snowflake/v2 v2.14.1 — keep in sync when the fork moves);
// the AMP line follows the Tor Browser builtin AMP-cache shape
// (url=broker + ampcache=ampproject). Builtin lines do NOT count as
// "collected from the network" (a successful collection still requires
// ≥1 live network bridge) but they always join the candidate set.

// BuiltinSnowflakeCDN77 is the CDN77 rendezvous set (two bridges, one
// rendezvous) — VERBATIM from snowflake/v2 v2.14.1 client/torrc.
var BuiltinSnowflakeCDN77 = []string{
	"snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn",
	"snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn",
}

// BuiltinSnowflakeAMP is the AMP-cache rendezvous set: the Tor Browser
// builtin shape (broker url + ampproject ampcache; same ICE ladder as
// the pinned CDN77 set).
var BuiltinSnowflakeAMP = []string{
	"snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://snowflake-broker.torproject.net/ ampcache=https://cdn.ampproject.org/ ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn",
}

// BuiltinSnowflake returns the builtin snowflake bridge lines for the
// given set name ("cdn77" | "amp"), parsed through the same admission
// gate as every other line. Invalid lines are skipped with their notice —
// a builtin that fails its own parser is a packaging bug, not a runtime
// surprise (and the tests pin the shipped lines as parseable).
func BuiltinSnowflake(set string) []Bridge {
	var raw []string
	switch set {
	case "amp":
		raw = BuiltinSnowflakeAMP
	case "cdn77":
		raw = BuiltinSnowflakeCDN77
	default:
		return nil
	}
	out := make([]Bridge, 0, len(raw))
	for _, line := range raw {
		b, err := ParseBridgeLine(line)
		if err != nil {
			continue // admission gate is absolute — even for builtins
		}
		out = append(out, b)
	}
	return out
}
