package zlib

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	blacklistError = errors.New("blacklisted")
	blacklistNets  []*net.IPNet
	once           sync.Once
)

func initBlacklist(blacklist string) {
	response, err := http.Get(blacklist)
	if err != nil {
		return // no blacklist active
	}

	scanner := bufio.NewScanner(response.Body)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		addr := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if addr == "" {
			continue
		}
		if _, ipv4Net, err := net.ParseCIDR(addr); err == nil {
			blacklistNets = append(blacklistNets, ipv4Net)
		} else if _, ipv4Net, err := net.ParseCIDR(addr + "/32"); err == nil {
			blacklistNets = append(blacklistNets, ipv4Net)
		}

	}
}

func isBlacklisted(ip net.IP) bool {
	for _, i4net := range blacklistNets {
		if i4net.Contains(ip) {
			return true
		}
	}
	return false
}

func GrabBlacklist(config *Config, target *GrabTarget) *Grab {
	once.Do(func() { initBlacklist(config.Blacklist) }) // lazy init the blacklist

	addr := target.Addr
	if config.LookupDomain {
		if res, err := net.LookupIP(target.Domain); err != nil {
			return nil
		} else {
			addr = res[0]
		}
	}
	if isBlacklisted(addr) {
		return &Grab{
			IP:           target.Addr,
			Domain:       target.Domain,
			ComsysDate:   target.ComsysDate,
			ComsysInput:  target.ComsysInput,
			ComsysSource: target.ComsysSource,
			Time:         time.Now(),
			Error:        blacklistError,
		}
	}
	return nil
}
