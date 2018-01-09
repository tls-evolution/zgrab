// Modified version
// original at https://github.com/aeden/traceroute

package traceroute

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

const DEFAULT_PORT = 33434
const DEFAULT_MAX_HOPS = 30
const DEFAULT_TIMEOUT_MS = 500
const DEFAULT_RETRIES = 3
const DEFAULT_PACKET_SIZE = 52

type Route map[int]string

type hopInfo struct {
	reply  chan *hopInfo
	socket int
	port   uint16
	ok     bool
	ttl    int
	addr   [4]byte
}

var (
	portInfo     map[uint16]*hopInfo
	portInfoLock sync.Mutex
	initOnce     sync.Once
)

func lazyInit() {
	portInfo = make(map[uint16]*hopInfo)
	socketAddr, err := socketAddr()
	if err != nil {
		return
	}
	var p = make([]byte, DEFAULT_PACKET_SIZE)

	// Set up the socket to receive inbound packets
	recvSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		panic(err)
	}

	// For the moment we leak the socket!
	//defer syscall.Close(recvSocket)

	// This sets the timeout to wait for a response from the remote host
	//tv := syscall.NsecToTimeval(math.MinInt64)
	//syscall.SetsockoptTimeval(recvSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Bind to the local socket to listen for ICMP packets
	if err := syscall.Bind(recvSocket, &syscall.SockaddrInet4{Port: DEFAULT_PORT, Addr: socketAddr}); err != nil {
		panic(err)
	}

	go func() {
		for {
			n, from, err := syscall.Recvfrom(recvSocket, p, syscall.MSG_WAITALL)
			if err == nil {
				currAddr := from.(*syscall.SockaddrInet4).Addr
				if n >= 52 {
					z := p[20+8+20:] // Skip IP header, ICMP header and echoed IP header
					srcPort := uint16(z[1]) | uint16(z[0])<<8

					portInfoLock.Lock()
					if hi, ok := portInfo[srcPort]; ok {
						delete(portInfo, srcPort)
						hi.addr = currAddr
						hi.ok = true
						hi.reply <- hi
						//hi.typ = p[20]
						//hi.code = p[21]
					}
					portInfoLock.Unlock()
				}
			} else {
				log.Print("Tracert error (1): ", err)
			}
		}
	}()

}

// Return the first non-loopback address as a 4 byte IP address. This address
// is used for sending packets out.
func socketAddr() (addr [4]byte, err error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if len(ipnet.IP.To4()) == net.IPv4len {
				copy(addr[:], ipnet.IP.To4())
				return
			}
		}
	}
	err = errors.New("You do not appear to be connected to the Internet")
	return
}

// TracrouteOptions type
type TracerouteOptions struct {
	maxHops   int
	timeoutMs int
	retries   int
}

func (options *TracerouteOptions) MaxHops() int {
	if options.maxHops == 0 {
		options.maxHops = DEFAULT_MAX_HOPS
	}
	return options.maxHops
}

func (options *TracerouteOptions) SetMaxHops(maxHops int) {
	options.maxHops = maxHops
}

func (options *TracerouteOptions) TimeoutMs() int {
	if options.timeoutMs == 0 {
		options.timeoutMs = DEFAULT_TIMEOUT_MS
	}
	return options.timeoutMs
}

func (options *TracerouteOptions) SetTimeoutMs(timeoutMs int) {
	options.timeoutMs = timeoutMs
}

func (options *TracerouteOptions) Retries() int {
	if options.retries == 0 {
		options.retries = DEFAULT_RETRIES
	}
	return options.retries
}

func (options *TracerouteOptions) SetRetries(retries int) {
	options.retries = retries
}

// Traceroute uses the given dest (hostname) and options to execute a traceroute
// from your machine to the remote host.
//
// Outbound packets are UDP packets and inbound packets are ICMP.
//
// Returns a TracerouteResult which contains an array of hops. Each hop includes
// the elapsed time and its IP address.
func Traceroute(ip net.IP, options *TracerouteOptions) Route {
	initOnce.Do(lazyInit)
	if ip == nil {
		return nil
	}
	var sendSocket int = -1
	var err error

	ip = ip.To4()
	hops := make([]hopInfo, options.MaxHops()+1)
	destAddr := [4]byte{ip[0], ip[1], ip[2], ip[3]}
	ch := make(chan *hopInfo, options.MaxHops())
	serial := true

	for ttl := 1; ttl <= options.maxHops; ttl++ {
		hi := &hops[ttl]

		// Set up the socket to send packets out.
		if !serial || (sendSocket == -1) {
			sendSocket, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
			if err != nil {
				log.Print("Tracert error (2): ", err)
				continue
			}
			defer syscall.Close(sendSocket)
		}
		// This sets the current hop TTL
		if err := syscall.SetsockoptInt(sendSocket, 0x0, syscall.IP_TTL, ttl); err != nil {
			log.Print("Tracert error (3): ", err)
			continue
		}

		hi.socket = sendSocket

		// Signal the receiving gofunc, that we are interested in ICMP echoing this udp port
		portInfoLock.Lock()

		// Send a single null byte UDP packet, this allocates the port
		if err := syscall.Sendto(sendSocket, []byte{0x0}, 0, &syscall.SockaddrInet4{Port: DEFAULT_PORT, Addr: destAddr}); err != nil {
			portInfoLock.Unlock()
			log.Print("Tracert error (4): ", err)
			continue
		}
		addr, _ := syscall.Getsockname(sendSocket)
		localPort := uint16(addr.(*syscall.SockaddrInet4).Port)
		hi.port = localPort
		hi.ttl = ttl
		hi.reply = ch

		portInfo[localPort] = hi
		portInfoLock.Unlock()

		if serial {
			select {
			case <-ch:
			case <-time.After(time.Second * 5):
			}
			portInfoLock.Lock()
			delete(portInfo, localPort)
			portInfoLock.Unlock()
		}

	}

	if !serial {
	Collect:
		for ttl := 1; ttl <= options.MaxHops(); ttl++ {
			select {
			case <-ch:
				{
				}
			case <-time.After(time.Second * 5):
				{
					break Collect
				}
			}
		}
	}

	// remove all unanswered entries
	portInfoLock.Lock()
	for _, hi := range hops[1:] {
		delete(portInfo, hi.port)
	}
	portInfoLock.Unlock()
	close(ch)

	result := make(Route)
	for i, hi := range hops[1:] {
		if hi.ok {
			result[i] = fmt.Sprintf("%v.%v.%v.%v", hi.addr[0], hi.addr[1], hi.addr[2], hi.addr[3])
			if hi.addr == destAddr {
				break
			}
		}
	}

	return result
}
