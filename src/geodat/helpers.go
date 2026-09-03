package geodat

import (
	"net/netip"
	"os"

	"github.com/daniellavrushin/b4/log"
	"github.com/urlesistiana/v2dat/v2data"
)

func LoadDomainsFromCategories(geodataPath string, categories []string) ([]string, error) {
	if geodataPath == "" || len(categories) == 0 {
		return []string{}, nil
	}

	if _, err := os.Stat(geodataPath); os.IsNotExist(err) {
		log.Errorf("Geosite file not found: %s - categories will be ignored", geodataPath)
		return []string{}, nil
	}

	allDomains := []string{}

	save := func(tag string, domainList []*v2data.Domain) error {
		for _, d := range domainList {
			domain := extractDomainValue(d)
			if domain != "" {
				allDomains = append(allDomains, domain)
			}
		}
		return nil
	}

	if err := streamGeoSite(geodataPath, categories, save); err != nil {
		return nil, err
	}

	return allDomains, nil
}

func LoadIpsFromCategories(geodataPath string, categories []string) ([]string, error) {
	if geodataPath == "" || len(categories) == 0 {
		return []string{}, nil
	}

	if _, err := os.Stat(geodataPath); os.IsNotExist(err) {
		log.Errorf("GeoIP file not found: %s - categories will be ignored", geodataPath)
		return []string{}, nil
	}

	allIps := []string{}

	save := func(tag string, geo *v2data.GeoIP) error {
		for _, cidr := range geo.GetCidr() {
			ip, ok := netip.AddrFromSlice(cidr.Ip)
			if !ok {
				continue
			}
			prefix, err := ip.Prefix(int(cidr.Prefix))
			if err != nil {
				continue
			}
			allIps = append(allIps, prefix.String())
		}
		return nil
	}

	if err := streamGeoIP(geodataPath, categories, save); err != nil {
		return nil, err
	}

	return allIps, nil
}

func extractDomainValue(d *v2data.Domain) string {
	switch d.Type {
	case v2data.Domain_Plain:
		return d.Value
	case v2data.Domain_Regex:
		return "regexp:" + d.Value
	case v2data.Domain_Full:
		return d.Value
	case v2data.Domain_Domain:
		return d.Value
	default:
		return d.Value
	}
}
