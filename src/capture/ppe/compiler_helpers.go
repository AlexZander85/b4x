package ppe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

func desiredHash(state DesiredState) (string, error) {
	clone := state
	clone.Generation = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 31 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func joinPorts(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, port := range ports {
		parts[i] = strconv.Itoa(int(port))
	}
	return strings.Join(parts, ",")
}

func chunkPorts(ports []uint16, size int) [][]uint16 {
	var chunks [][]uint16
	for len(ports) > 0 {
		n := size
		if len(ports) < n {
			n = len(ports)
		}
		chunks = append(chunks, append([]uint16(nil), ports[:n]...))
		ports = ports[n:]
	}
	return chunks
}

func intersectPorts(configured []uint16, inspected map[uint16]struct{}, all bool) []uint16 {
	seen := make(map[uint16]struct{}, len(configured))
	out := make([]uint16, 0, len(configured))
	for _, port := range configured {
		if port == 0 {
			continue
		}
		if !all {
			if _, ok := inspected[port]; !ok {
				continue
			}
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
