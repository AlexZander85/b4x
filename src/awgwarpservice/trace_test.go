package awgwarpservice

import "testing"

// TestTraceDetail pins the FIELD2 phase E parser: loc=/colo=/warp= are read
// from the raw /cdn-cgi/trace body; the public exit IP is deliberately NOT
// part of the log line (redaction discipline).
func TestTraceDetail(t *testing.T) {
	body := "fl=903f76\nh=1.1.1.1\nip=203.0.113.9\nts=1\nvisit_scheme=https\nuag=curl\ncolo=DME\nsliver=none\nhttp=http/2\nloc=RU\ntls=TLSv1.3\nsni=off\nwarp=on\ngateway=off\n"
	got := traceDetail(body)
	if got != "loc=RU colo=DME warp=on" {
		t.Fatalf("traceDetail = %q", got)
	}
	if got2 := traceDetail("warp=on\n"); got2 != "loc= colo= warp=on" {
		t.Fatalf("missing keys must stay empty: %q", got2)
	}
}
