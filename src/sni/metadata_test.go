package sni

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/daniellavrushin/b4/fixtures"
)

func TestTLSClientHelloMetadataCorpus(t *testing.T) {
	for _, fixture := range fixtures.TLSCorpus() {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			metadata := ParseTLSClientHelloMetadata(fixture.Record)
			if fixture.Malformed {
				if metadata.Complete {
					t.Fatalf("malformed metadata = %+v", metadata)
				}
				return
			}
			if !metadata.Complete || metadata.ParseError != "" {
				t.Fatalf("metadata incomplete/error = %+v", metadata)
			}
			if metadata.SNI != fixture.Host || metadata.MaxVersion != fixture.TLSVersion {
				t.Fatalf("metadata host/version = %q/%#x, want %q/%#x", metadata.SNI, metadata.MaxVersion, fixture.Host, fixture.TLSVersion)
			}
			if metadata.ECHPresent != fixture.ECH {
				t.Fatalf("ECH = %v, want %v", metadata.ECHPresent, fixture.ECH)
			}
			if fixture.ECH && metadata.ECHOuterName != "" {
				t.Fatalf("ECH outer name = %q", metadata.ECHOuterName)
			}
		})
	}
}

func TestTLSClientHelloMetadataNeedsExactRecordBytes(t *testing.T) {
	record := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	for _, cut := range []int{0, 1, 4, len(record) - 1} {
		metadata := ParseTLSClientHelloMetadata(record[:cut])
		if metadata.Complete || metadata.NeedBytes <= 0 {
			t.Fatalf("cut=%d metadata=%+v", cut, metadata)
		}
	}
	metadata := ParseTLSClientHelloMetadata(record[:len(record)-1])
	if metadata.RecordNeedBytes != 1 || metadata.NeedBytes != 1 {
		t.Fatalf("exact missing byte metadata=%+v", metadata)
	}
}

func TestTLSClientHelloMetadataSplitAndTrailingData(t *testing.T) {
	fixture := fixtures.TLSCorpus()[1]
	partial := ParseTLSClientHelloMetadata(fixture.Segments[0].Payload)
	if partial.Complete || partial.NeedBytes <= 0 {
		t.Fatalf("split first segment metadata=%+v", partial)
	}
	complete := ParseTLSClientHelloMetadata(fixture.Record)
	if !complete.Complete || complete.ClientHelloSize <= 4 || complete.RecordCount != 1 {
		t.Fatalf("complete split fixture metadata=%+v", complete)
	}
	trailing := ParseTLSClientHelloMetadata(fixtures.TLSCorpus()[11].Record)
	if !trailing.Complete || trailing.TrailingDataBytes != 6 {
		t.Fatalf("coalesced trailing metadata=%+v", trailing)
	}
}

// TestTLSClientHelloMetadataTruncatedRecordSNI locks in hostname extraction
// from the first segment of a ClientHello record larger than one MSS. The
// SNI extension precedes padding/key shares, so it must be observed without
// waiting for reassembly of the remaining segments.
func TestTLSClientHelloMetadataTruncatedRecordSNI(t *testing.T) {
	record := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1700)
	if len(record) <= 1400 {
		t.Fatalf("fixture record too small for split: %d", len(record))
	}
	metadata := ParseTLSClientHelloMetadata(record[:1400])
	if metadata.Complete || metadata.NeedBytes <= 0 || metadata.RecordNeedBytes <= 0 {
		t.Fatalf("truncated record metadata=%+v", metadata)
	}
	if metadata.SNI != "api.youtube.com" {
		t.Fatalf("truncated record SNI = %q, want api.youtube.com (metadata=%+v)", metadata.SNI, metadata)
	}
	if metadata.MaxVersion != 0x0304 {
		t.Fatalf("truncated record MaxVersion = %#x, want 0x0304", metadata.MaxVersion)
	}
}

// TestTLSClientHelloMetadataTruncatedBeforeSNI verifies that a segment cut
// before the SNI extension yields no hostname and no parse error.
func TestTLSClientHelloMetadataTruncatedBeforeSNI(t *testing.T) {
	record := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 1700)
	// Cut inside the fixed ClientHello header (legacy_version + random),
	// long before any extension.
	metadata := ParseTLSClientHelloMetadata(record[:20])
	if metadata.Complete || metadata.SNI != "" || metadata.ParseError != "" {
		t.Fatalf("early-cut metadata=%+v", metadata)
	}
}

func TestTLSClientHelloMetadataALPNAndECHOuterName(t *testing.T) {
	metadata := ParseTLSClientHelloMetadata(buildMetadataALPNRecord())
	if !metadata.Complete || metadata.ParseError != "" || metadata.SNI != "api.youtube.com" || metadata.MaxVersion != 0x0304 {
		t.Fatalf("ALPN metadata = %+v", metadata)
	}
	if len(metadata.ALPN) != 2 || metadata.ALPN[0] != "h2" || metadata.ALPN[1] != "http/1.1" {
		t.Fatalf("ALPN = %v", metadata.ALPN)
	}
	outer := ParseTLSClientHelloMetadata(fixtures.BuildTLSClientHello("outer.example", 0x0304, true, 0))
	if !outer.Complete || !outer.ECHPresent || outer.ECHOuterName != "outer.example" {
		t.Fatalf("ECH outer metadata = %+v", outer)
	}
}

func buildMetadataALPNRecord() []byte {
	host := []byte("api.youtube.com")
	var sni bytes.Buffer
	binary.Write(&sni, binary.BigEndian, uint16(3+len(host)))
	sni.WriteByte(0)
	binary.Write(&sni, binary.BigEndian, uint16(len(host)))
	sni.Write(host)

	alpnData := []byte{0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	var extensions bytes.Buffer
	binary.Write(&extensions, binary.BigEndian, uint16(0))
	binary.Write(&extensions, binary.BigEndian, uint16(sni.Len()))
	extensions.Write(sni.Bytes())
	binary.Write(&extensions, binary.BigEndian, uint16(0x10))
	binary.Write(&extensions, binary.BigEndian, uint16(len(alpnData)))
	extensions.Write(alpnData)
	binary.Write(&extensions, binary.BigEndian, uint16(0x2b))
	binary.Write(&extensions, binary.BigEndian, uint16(3))
	extensions.Write([]byte{2, 3, 4})

	var body bytes.Buffer
	binary.Write(&body, binary.BigEndian, uint16(0x0303))
	body.Write(make([]byte, 32))
	body.WriteByte(0)
	binary.Write(&body, binary.BigEndian, uint16(2))
	body.Write([]byte{0x13, 0x01})
	body.Write([]byte{1, 0})
	binary.Write(&body, binary.BigEndian, uint16(extensions.Len()))
	body.Write(extensions.Bytes())

	var record bytes.Buffer
	record.Write([]byte{0x16, 0x03, 0x03, 0, 0})
	binary.BigEndian.PutUint16(record.Bytes()[3:5], uint16(4+body.Len()))
	record.Write([]byte{1, 0, 0, byte(body.Len())})
	record.Write(body.Bytes())
	return record.Bytes()
}

func FuzzParseTLSClientHelloMetadataNeverPanics(f *testing.F) {
	f.Add(fixtures.BuildTLSClientHello("youtubei.googleapis.com", 0x0304, false, 0))
	f.Add([]byte{0x16, 0x03, 0x03, 0, 4, 1, 0, 0, 0xff})
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, input []byte) {
		metadata := ParseTLSClientHelloMetadata(input)
		if metadata.Complete && metadata.ParseError != "" {
			t.Fatalf("complete metadata contains parse error: %+v", metadata)
		}
		if metadata.NeedBytes < 0 || metadata.RecordNeedBytes < 0 {
			t.Fatalf("negative need in metadata: %+v", metadata)
		}
	})
}

func BenchmarkParseTLSClientHelloMetadata(b *testing.B) {
	input := fixtures.BuildTLSClientHello("r1---sn-4g5e6nzz.googlevideo.com", 0x0304, true, 1800)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		metadata := ParseTLSClientHelloMetadata(input)
		if !metadata.Complete {
			b.Fatal("benchmark fixture did not parse")
		}
	}
}

func TestParseTLSClientHelloMetadataAcrossMultipleRecords(t *testing.T) {
	record := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 32*1024-5)
	if len(record) < 5 || len(record[5:]) <= 16*1024 {
		t.Fatalf("fixture does not require multiple records: %d", len(record))
	}
	payload := record[5:]
	multi := make([]byte, 0, len(record)+5)
	for len(payload) > 0 {
		n := len(payload)
		if n > 16*1024 {
			n = 16 * 1024
		}
		header := []byte{0x16, 0x03, 0x03, 0, 0}
		binary.BigEndian.PutUint16(header[3:5], uint16(n))
		multi = append(multi, header...)
		multi = append(multi, payload[:n]...)
		payload = payload[n:]
	}
	metadata := ParseTLSClientHelloMetadata(multi)
	if !metadata.Complete || metadata.SNI != "api.youtube.com" || metadata.RecordCount != 2 || metadata.ClientHelloSize == 0 {
		t.Fatalf("multi-record ClientHello not parsed: %+v", metadata)
	}
}
