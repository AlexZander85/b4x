package geodat

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/urlesistiana/v2dat/v2data"
	"google.golang.org/protobuf/proto"
)

// LoadCountryPrefixes loads the FULL per-country IPv4 prefix index from a
// geoip.dat (the E7 nonru classify-oracle source). Unlike the per-category
// loaders, this walks every entry: the nonru geo quorum needs the ACTUAL
// country of an arbitrary non-RU egress IP, not membership in one pinned
// category. Non-country pseudo-tags (private, cloudflare "1", ...) are kept
// verbatim — the oracle decides what a hit means; a prefix that maps only
// to a pseudo-tag classifies as "" (unknown), never as a country.
func LoadCountryPrefixes(geoipPath string) (map[string][]netip.Prefix, error) {
	b, err := os.ReadFile(geoipPath)
	if err != nil {
		return nil, err
	}
	geoIPList, err := v2data.LoadGeoIPListFromDAT(b)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]netip.Prefix, len(geoIPList.GetEntry()))
	for _, geo := range geoIPList.GetEntry() {
		tag := strings.ToLower(geo.GetCountryCode())
		if tag == "" {
			continue
		}
		for _, cidr := range geo.GetCidr() {
			addr, ok := netip.AddrFromSlice(cidr.GetIp())
			if !ok || !addr.Is4() {
				continue // v4 index: the §43 egress observations are IPv4 by design
			}
			pfx, perr := addr.Prefix(int(cidr.GetPrefix()))
			if perr != nil {
				continue
			}
			out[tag] = append(out[tag], pfx)
		}
	}
	return out, nil
}

func UnpackGeoIP(args *UnpackArgs) error {
	filePath, wantTags := args.File, args.Filters

	save := func(tag string, geo *v2data.GeoIP) error {
		return convertV2CidrToText(geo.GetCidr(), os.Stdout)
	}

	if len(wantTags) != 0 {
		return streamGeoIP(filePath, wantTags, save)
	}

	b, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	geoIPList, err := v2data.LoadGeoIPListFromDAT(b)
	if err != nil {
		return err
	}
	for _, geo := range geoIPList.GetEntry() {
		tag := strings.ToLower(geo.GetCountryCode())
		if err := save(tag, geo); err != nil {
			return err
		}
	}
	return nil
}

func streamGeoIP(file string, filters []string, save func(string, *v2data.GeoIP) error) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	want := map[string]struct{}{}
	for _, tag := range filters {
		want[strings.ToLower(tag)] = struct{}{}
	}
	got := map[string]struct{}{}

	r := bufio.NewReaderSize(f, 32*1024)
	for {
		tagByte, err := r.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if tagByte != 0x0A {
			return fmt.Errorf("unexpected wire tag %02X", tagByte)
		}
		length, err := binary.ReadUvarint(r)
		if err != nil {
			return err
		}
		msg := make([]byte, length)
		if _, err := io.ReadFull(r, msg); err != nil {
			return err
		}
		tag, err := readCountryCode(msg)
		if err != nil {
			return err
		}
		if _, ok := want[tag]; !ok {
			continue
		}
		var geo v2data.GeoIP
		if err := proto.Unmarshal(msg, &geo); err != nil {
			return err
		}
		if err := save(tag, &geo); err != nil {
			return err
		}
		got[tag] = struct{}{}
		if len(got) == len(want) {
			return nil
		}
	}
	return nil
}

func convertV2CidrToText(cidr []*v2data.CIDR, w io.Writer) error {
	bw := bufio.NewWriter(w)
	for i, record := range cidr {
		ip, ok := netip.AddrFromSlice(record.Ip)
		if !ok {
			return fmt.Errorf("invalid ip at index #%d, %s", i, record.Ip)
		}
		prefix, err := ip.Prefix(int(record.Prefix))
		if err != nil {
			return fmt.Errorf("invalid prefix at index #%d, %w", i, err)
		}

		if _, err := bw.WriteString(prefix.String()); err != nil {
			return err
		}
		if _, err := bw.WriteRune('\n'); err != nil {
			return err
		}
	}
	return bw.Flush()
}
