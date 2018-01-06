package tls13measurements

import (
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/zmap/zgrab/tls13measurements/traceroute"
)

type Route map[int]string

func TraceRoute(ip net.IP) Route {
	return TraceRoute_GO(ip)
}

func TraceRoute_GO(ip net.IP) Route {
	options := traceroute.TracerouteOptions{}
	options.SetRetries(0)
	options.SetMaxHops(30 + 1)

	return Route(traceroute.Traceroute(ip, &options))
}

func TraceRoute_SYS(ip net.IP) Route {
	out, err := exec.Command("traceroute", "-n", "-N 30", ip.String()).Output()
	if err != nil {
		return nil
	}

	route := make(Route)
	results := strings.Split(string(out), "\n")
	results = results[1 : len(results)-1] // skip info and empty last line

	for _, s := range results {
		dat := strings.Fields(s)
		if dat[1] == "*" {
			continue
		}
		idx, err := strconv.Atoi(dat[0])
		if err == nil {
			route[idx] = dat[1]
		}
	}

	return route
}
