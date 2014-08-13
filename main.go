package main

import (
	"encoding/json"
	"./banner"
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

// Command-line flags
var (
	encoding                      string
	outputFileName, inputFileName string
	logFileName, metadataFileName string
	messageFileName               string
	interfaceName                 string
	portFlag                      uint
	inputFile, metadataFile       *os.File
	senders                       uint
	udp bool
	timeout uint
)

// Module configurations
var (
	grabConfig   banner.GrabConfig
	outputConfig banner.OutputConfig
)

type Summary struct {
	Success uint			`json:"success_count"`
	Error uint				`json:"error_count"`
	Total uint				`json:"total"`
	Protocol string `json:"protocol"`
	Port uint16 `json:"port"`
	Start time.Time `json:"start_time"`
	End time.Time `json:"end_time"`
	Duration time.Duration `json:"duration"`
	Timeout uint `json:"timeout"`
}

// Pre-main bind flags to variables
func init() {

	flag.StringVar(&encoding, "encoding", "string", "Encode banner as string|hex|base64")
	flag.StringVar(&outputFileName, "output-file", "-", "Output filename, use - for stdout")
	flag.StringVar(&inputFileName, "input-file", "-", "Input filename, use - for stdin")
	flag.StringVar(&metadataFileName, "metadata-file", "-", "File to record banner-grab metadata, use - for stdout")
	flag.StringVar(&logFileName, "log-file", "-", "File to log to, use - for stderr")
	flag.StringVar(&interfaceName, "interface", "", "Network interface to send on")
	flag.UintVar(&portFlag, "port", 80, "Port to grab on")
	flag.UintVar(&timeout, "timeout", 10, "Set connection timeout in seconds")
	flag.BoolVar(&grabConfig.Tls, "tls", false, "Grab over TLS")
	flag.BoolVar(&udp, "udp", false, "Grab over UDP")
	flag.UintVar(&senders, "senders", 1000, "Number of send coroutines to use")
	flag.BoolVar(&grabConfig.Banners, "banners", false, "Read banner upon connection creation")
	flag.StringVar(&messageFileName, "data", "", "Optional message to send (%s will be replaced with destination IP)")
	flag.BoolVar(&grabConfig.ReadResponse, "read-response", false, "Read response to message")
	flag.BoolVar(&grabConfig.StartTls, "starttls", false, "Send STARTTLS before negotiating (implies --tls)")
	flag.BoolVar(&grabConfig.Heartbleed, "heartbleed", false, "Check if server is vulnerable to Heartbleed (implies --tls)")
	flag.Parse()

	// STARTTLS cannot be used with TLS
	if grabConfig.StartTls && grabConfig.Tls {
		log.Fatal("Cannot both initiate a TLS and STARTTLS connection")
	}

	// Heartbleed requires STARTTLS or TLS
	if (grabConfig.Heartbleed && !(grabConfig.StartTls || grabConfig.Tls)) {
		log.Fatal("Must specify one of --tls or --starttls for --heartbleed")
	}

	// Validate port
	if portFlag > 65535 {
		log.Fatal("Port", portFlag, "out of range")
	}
	grabConfig.Port = uint16(portFlag)

	// Validate timeout
	grabConfig.Timeout = time.Duration(timeout) * time.Second

	// Check UDP
	if udp {
		log.Print("Warning: UDP is untested")
		grabConfig.Protocol = "udp"
	} else {
		grabConfig.Protocol = "tcp"
	}

	// Validate senders
	if senders == 0 {
		log.Fatal("Error: Need at least one sender")
	}

	// Check output type

	// Check the network interface
	var err error
	/*
	if interfaceName != "" {
		var iface *net.Interface
		if iface, err = net.InterfaceByName(interfaceName); err != nil {
			log.Fatal("Error: Invalid network interface: ", interfaceName)
		}
		var addrs []net.Addr
		if addrs, err = iface.Addrs(); err != nil || len(addrs) == 0 {
			log.Fatal("Error: No addresses for interface ", interfaceName)
		}
		grabConfig.LocalAddr = addrs[0]
	}
	*/

	// Open input and output files
	switch inputFileName {
	case "-":
		inputFile = os.Stdin
	default:
		if inputFile, err = os.Open(inputFileName); err != nil {
			log.Fatal(err)
		}
	}

	switch outputFileName {
	case "-":
		outputConfig.OutputFile = os.Stdout
	default:
		if outputConfig.OutputFile, err = os.Create(outputFileName); err != nil {
			log.Fatal(err)
		}
	}

	// Open message file, if applicable
	if messageFileName != "" {
		if messageFile, err := os.Open(messageFileName); err != nil {
			log.Fatal(err)
		} else {
			buf := make([]byte, 1024)
			n, err := messageFile.Read(buf)
			grabConfig.SendMessage = true
			grabConfig.Message = buf[0:n]
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			messageFile.Close()
		}
	}

	if grabConfig.ReadResponse && !grabConfig.SendMessage {
		log.Fatal("--read-response requires --data to be sent")
	}

	// Open metadata file
	if metadataFileName == "-" {
		metadataFile = os.Stdout
	} else {
		if metadataFile, err = os.Create(metadataFileName); err != nil {
			log.Fatal(err)
		}
	}

	// Open log file, attach to configs
	var logFile *os.File
	if logFileName == "-" {
		logFile = os.Stderr
	} else {
		if logFile, err = os.Create(logFileName); err != nil {
			log.Fatal(err)
		}
	}
	logger := log.New(logFile, "[BANNER-GRAB] ", log.LstdFlags)
	outputConfig.ErrorLog = logger
	grabConfig.ErrorLog = logger
}

func ReadInput(addrChan chan net.IP, inputFile *os.File) {
	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		ipString := scanner.Text()
		ip := net.ParseIP(ipString)
		if ip == nil {
			fmt.Fprintln(os.Stderr, "Invalid IP address: ", ipString)
			continue
		}

		addrChan <- ip
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Reading stdin: ", err)
	}
	close(addrChan)
}

func (s *Summary) AddProgress(p *banner.Progress) {
	s.Success += p.Success
	s.Error += p.Error
	s.Total += p.Total
}

func main() {
	addrChan := make(chan net.IP, senders*4)
	grabChan := make(chan banner.Grab, senders*4)
	doneChan := make(chan banner.Progress)
	outputDoneChan := make(chan int)

	s := Summary {
		Start: time.Now(),
		Protocol: grabConfig.Protocol,
		Port: grabConfig.Port,
		Timeout: timeout,
	}

	go banner.WriteOutput(grabChan, outputDoneChan, &outputConfig)
	for i := uint(0); i < senders; i += 1 {
		go banner.GrabBanner(addrChan, grabChan, doneChan, &grabConfig)
	}
	ReadInput(addrChan, inputFile)

	// Wait for grabbers to finish
	for i := uint(0); i < senders; i += 1 {
		finalProgress := <- doneChan
		s.AddProgress(&finalProgress)
	}
	close(grabChan)
	close(doneChan)
	s.End = time.Now()
	s.Duration = s.End.Sub(s.Start) / time.Second

	<- outputDoneChan
	close(outputDoneChan)

	if inputFile != os.Stdin {
		inputFile.Close()
	}
	if outputConfig.OutputFile != os.Stdout {
		outputConfig.OutputFile.Close()
	}

	enc := json.NewEncoder(metadataFile)
	if err := enc.Encode(s); err != nil {
		log.Fatal(err)
	}
}
