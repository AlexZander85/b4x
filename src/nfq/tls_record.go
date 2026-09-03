package nfq

// tlsHandshakeRecordIncomplete reports a TLS handshake record (type 0x16)
// whose header length is larger than this TCP payload. Typical Android
// ECH ClientHello is ~1802 bytes and arrives as 1396+tail. Combo-splitting
// the first piece leaves the server unable to reassemble with the raw tail
// (field seek hang 21:18 on 74.125.173.233: 16030106f0 / 1603010710).
func tlsHandshakeRecordIncomplete(payload []byte) bool {
	total := tlsHandshakeRecordTotal(payload)
	return total > len(payload)
}

// tlsHandshakeRecordTotal is 5+length from the TLS record header, or 0.
func tlsHandshakeRecordTotal(payload []byte) int {
	if len(payload) < 5 || payload[0] != 0x16 {
		return 0
	}
	return 5 + (int(payload[3])<<8 | int(payload[4]))
}
