package conn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const defaultPort = 22

// Destination represents a parsed SSH destination in the form of [user@]hostname[:port].
type Destination struct {
	User string
	Host string
	Port uint16
}

// ParseDestination parses "[user@]hostname[:port]".
// A leading "user@" overrides any --username flag.
func ParseDestination(dest string) (*Destination, error) {
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return nil, errors.New("destination cannot be empty")
	}

	if strings.HasPrefix(dest, "-") {
		return nil, errors.New("targets cannot start with a '-' character")
	}

	// extract user@ prefix if present
	var user string
	if i := strings.LastIndex(dest, "@"); i != -1 {
		var host string
		user, host = dest[:i], dest[i+1:]
		if user == "" || host == "" {
			return nil, fmt.Errorf("invalid destination %q; expected user@hostname[:port]", dest)
		}
		dest = host
	}

	// parse the remaining host[:port] part
	host, port, err := parseHostPort(dest)
	if err != nil {
		return nil, err
	}

	return &Destination{
		User: user,
		Host: strings.ToLower(host),
		Port: port,
	}, nil
}

func parseHostPort(dest string) (string, uint16, error) {
	// a valid IPv6 address contains colons but has no explicit port
	if addr, err := netip.ParseAddr(dest); err == nil {
		return addr.String(), defaultPort, nil
	}

	// Standard host:port syntax, including [IPv6]:port.
	if host, portStr, err := net.SplitHostPort(dest); err == nil {
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || port == 0 {
			return "", 0, fmt.Errorf("invalid SSH port %q", portStr)
		}

		return host, uint16(port), nil
	}

	// a single colon implies attempted hostname:port syntax
	if strings.Count(dest, ":") == 1 {
		return "", 0, fmt.Errorf(
			"invalid destination %q; expected <hostname>[:port]",
			dest,
		)
	}

	// leave it alone and let SSH/the OS resolve it
	return dest, defaultPort, nil
}
