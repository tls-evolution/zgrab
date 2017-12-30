package tls13measurements

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
)

type Route map[int]string

func TraceRoute(ip net.IP) Route {
	out, err := exec.Command("traceroute", "-n", "-N 1", ip.String()).Output()
	if err != nil {
		return nil
	}

	route := make(Route)
	results := strings.Split(string(out), "\n")
	results = results[1 : len(results)-1] // skip info and empty last line

	for _, s := range results {
		dat := strings.Fields(s)
		idx, err := strconv.Atoi(dat[0])
		if err == nil {
			route[idx] = dat[1]
		}
	}

	return route
}
