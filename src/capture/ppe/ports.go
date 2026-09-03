package ppe

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/daniellavrushin/b4/config"
)

func inspectionPorts(cfg *config.Config, tcp bool) (map[uint16]struct{}, bool, error) {
	ports := make(map[uint16]struct{})
	anyEnabled := false
	for _, set := range cfg.Sets {
		if set == nil || !set.Enabled {
			continue
		}
		anyEnabled = true
		expression := set.UDP.DPortFilter
		if tcp {
			expression = set.TCP.DPortFilter
		}
		expression = strings.TrimSpace(expression)
		if expression == "" {
			return ports, true, nil
		}
		expanded, err := expandPortExpression(expression)
		if err != nil {
			return nil, false, fmt.Errorf("set %q: %w", set.Name, err)
		}
		for port := range expanded {
			ports[port] = struct{}{}
		}
	}
	if !anyEnabled {
		return ports, false, nil
	}
	return ports, false, nil
}

func expandPortExpression(value string) (map[uint16]struct{}, error) {
	out := make(map[uint16]struct{})
	for _, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		parts := strings.Split(token, "-")
		if len(parts) > 2 {
			return nil, fmt.Errorf("invalid port token %q", token)
		}
		start, err := parsePort(parts[0])
		if err != nil {
			return nil, err
		}
		end := start
		if len(parts) == 2 {
			end, err = parsePort(parts[1])
			if err != nil {
				return nil, err
			}
			if end < start {
				return nil, fmt.Errorf("descending port range %q", token)
			}
		}
		for port := start; port <= end; port++ {
			out[uint16(port)] = struct{}{}
		}
	}
	return out, nil
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	return port, nil
}
