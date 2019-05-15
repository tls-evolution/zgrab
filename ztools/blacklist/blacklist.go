package blacklist

import (
	"errors"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/zmap/zgrab/ztools/zlog"
)

var (
	BlacklistError = errors.New("blacklisted")
	blacklistNets  []*net.IPNet
	once           sync.Once
	domLock        sync.RWMutex
	ipLock         sync.RWMutex
	domRex         *regexp.Regexp
)

func updateBlacklistIP(data string) {
	ipLock.Lock()
	defer ipLock.Unlock()

	entrys := strings.Split(data, "\n")
	blacklistNets = nil

	for _, entry := range entrys {
		addr := strings.TrimSpace(strings.SplitN(entry, "#", 2)[0])

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

func updateBlacklistDom(data string) {
	domLock.Lock()
	defer domLock.Unlock()

	entrys := strings.Split(data, "\n")
	var exp string
	exp = "(^$)" // prevent always matching if no entries are given
	for _, entry := range entrys {
		ereal := strings.TrimSpace(strings.SplitN(entry, "#", 2)[0])
		if len(ereal) > 0 {
			exp = exp + "|(" + ereal + ")"
		}
	}

	if rex, err := regexp.CompilePOSIX(exp); err == nil {
		domRex = rex
	} else {
		zlog.Warn("Domain blacklist cannot be compiled as regex")
	}
}

func touch(file string) {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE, 0755)
	if err == nil {
		f.Close()
	}
}

func monitorFile(file string, f func()) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		zlog.Fatal(err)
	}
	defer watcher.Close()

	err = watcher.Add(file)
	if err != nil {
		zlog.Fatal(err)
	}

	for event := range watcher.Events {
		if event.Op&fsnotify.Write == fsnotify.Write {
			f()
		}
	}
}

func reload(file string, f func(string)) {
	zlog.Info("Reloading blacklist: " + file)
	dat, err := ioutil.ReadFile(file)
	if err != nil {
		zlog.Warn("Could not reload " + file + ". Retrying in one Minute.")
		go func() {
			time.Sleep(time.Minute)
			dat, err = ioutil.ReadFile(file)
			if err != nil {
				zlog.Warn("Could not reload " + file + " during retry, giving up.")
			} else {
				f(string(dat))
			}
		}()
	} else {
		f(string(dat))
	}
}

func initMonitoredFile(file string, f func(string)) {
	touch(file)
	reload(file, f)
	go func() {
		monitorFile(file, func() { reload(file, f) })
	}()
}

func Init(fileIP string, fileDom string) {
	once.Do(func() {
		initMonitoredFile(fileIP, updateBlacklistIP)
		initMonitoredFile(fileDom, updateBlacklistDom)
	})
}

func IsBlacklisted(ip net.IP) bool {
	ipLock.RLock()
	defer ipLock.RUnlock()
	for _, i4net := range blacklistNets {
		if i4net.Contains(ip) {
			return true
		}
	}
	return false
}

func IsBlacklistedDom(dom string) bool {
	domLock.RLock()
	defer domLock.RUnlock()
	if domRex == nil {
		return false
	}
	return domRex.MatchString(dom)
}
