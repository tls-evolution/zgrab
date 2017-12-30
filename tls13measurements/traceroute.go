package tls13measurements

import (
	"log"
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

	route := make(Route)
	res, err := traceroute.Traceroute(ip.String(), &options)
	if err != nil {
		log.Print("Traceroute error: ", err)
	}

	for _, hop := range res.Hops {
		if hop.Success {
			route[hop.TTL] = hop.AddressString()
		}
	}

	if len(route) == 0 {
		return nil
	}

	return route
}

func TraceRoute_SYS(ip net.IP) Route {
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
