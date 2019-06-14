/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zgrab/zlib"
	"github.com/zmap/zgrab/ztools/blacklist"
	"github.com/zmap/zgrab/ztools/processing"
	"github.com/zmap/zgrab/ztools/zlog"
)

// Command-line flags
var (
	outputFileName, inputFileName string
	logFileName, metadataFileName string
	messageFileName               string
	interfaceName                 string
	ehlo                          string
	portFlag                      uint
	inputFile, metadataFile       *os.File
	timeout                       uint
	tlsVersion                    string
	rootCAFileName                string
	prometheusAddress             string
	clientHelloFileName           string
)

// Module configurations
var (
	config       zlib.Config
	outputConfig zlib.OutputConfig
)

var (
	mailType string
)

// Pre-main bind flags to variables
func init() {

	flag.StringVar(&outputFileName, "output-file", "-", "Output filename, use - for stdout")
	flag.StringVar(&inputFileName, "input-file", "-", "Input filename, use - for stdin")
	flag.StringVar(&metadataFileName, "metadata-file", "-", "File to record banner-grab metadata, use - for stdout")
	flag.StringVar(&logFileName, "log-file", "-", "File to log to, use - for stderr")
	flag.StringVar(&prometheusAddress, "prometheus", "", "Address to use for Prometheus server (e.g. localhost:8080). If empty, Prometheus is disabled.")
	flag.BoolVar(&config.LookupDomain, "lookup-domain", false, "Input contains only domain names")
	flag.StringVar(&interfaceName, "interface", "", "Network interface to send on")
	flag.UintVar(&portFlag, "port", 80, "Port to grab on")
	flag.UintVar(&timeout, "timeout", 10, "Set connection timeout in seconds")
	flag.BoolVar(&config.TLS, "tls", false, "Grab over TLS")
	flag.StringVar(&tlsVersion, "tls-version", "", "Max TLS version to use (implies --tls)")
	flag.UintVar(&config.Senders, "senders", 1000, "Number of send coroutines to use")
	flag.UintVar(&config.ConnectionsPerHost, "connections-per-host", 1, "Number of times to connect to each host (results in more output)")
	flag.BoolVar(&config.Banners, "banners", false, "Read banner upon connection creation")
	flag.StringVar(&messageFileName, "data", "", "Send a message and read response (%s will be replaced with destination IP)")
	flag.StringVar(&config.HTTP.Endpoint, "http", "", "Send an HTTP request to an endpoint")
	flag.StringVar(&config.HTTP.Method, "http-method", "GET", "Set HTTP request method type")
	flag.StringVar(&config.HTTP.UserAgent, "http-user-agent", "Mozilla/5.0 zgrab/0.x", "Set a custom HTTP user agent")
	flag.StringVar(&config.HTTP.ProxyDomain, "http-proxy-domain", "", "Send a CONNECT <domain> first")
	flag.IntVar(&config.HTTP.MaxSize, "http-max-size", 256, "Max kilobytes to read in response to an HTTP request")
	flag.IntVar(&config.HTTP.MaxRedirects, "http-max-redirects", 0, "Max number of redirects to follow")
	flag.BoolVar(&config.HTTP.FollowLocalhostRedirects, "follow-localhost-redirects", true, "Follow HTTP redirects to localhost")
	flag.BoolVar(&config.TLSExtendedRandom, "tls-extended-random", false, "send extended random extension")
	flag.BoolVar(&config.SignedCertificateTimestampExt, "signed-certificate-timestamp", true, "request SCTs during TLS handshake")

	flag.StringVar(&config.EHLODomain, "ehlo", "", "Send an EHLO with the specified domain (implies --smtp)")
	flag.BoolVar(&config.SMTPHelp, "smtp-help", false, "Send a SMTP help (implies --smtp)")
	flag.BoolVar(&config.StartTLS, "starttls", false, "Send STARTTLS before negotiating")
	flag.BoolVar(&config.SMTP, "smtp", false, "Conform to SMTP when reading responses and sending STARTTLS")
	flag.BoolVar(&config.IMAP, "imap", false, "Conform to IMAP rules when sending STARTTLS")
	flag.BoolVar(&config.POP3, "pop3", false, "Conform to POP3 rules when sending STARTTLS")
	flag.BoolVar(&config.Modbus, "modbus", false, "Send some modbus data")
	flag.BoolVar(&config.BACNet, "bacnet", false, "Send some BACNet data")
	flag.BoolVar(&config.Fox, "fox", false, "Send some Niagara Fox Tunneling data")
	flag.BoolVar(&config.S7, "s7", false, "Send some Siemens S7 data")
	flag.BoolVar(&config.NoSNI, "no-sni", false, "Do not send domain name in TLS handshake regardless of whether known")

	flag.StringVar(&clientHelloFileName, "raw-client-hello", "", "Provide a raw ClientHello to be sent; only the SNI will be rewritten")

	flag.BoolVar(&config.ExportsOnly, "export-ciphers", false, "Send only export ciphers")
	flag.BoolVar(&config.ExportsDHOnly, "export-dhe-ciphers", false, "Send only export DHE ciphers")
	flag.BoolVar(&config.DHEOnly, "dhe-ciphers", false, "Send only DHE ciphers (not ECDHE)")
	flag.BoolVar(&config.ECDHEOnly, "ecdhe-ciphers", false, "Send only ECDHE ciphers (not DHE)")

	flag.BoolVar(&config.ChromeOnly, "chrome-ciphers", false, "Send Chrome Ordered Cipher Suites")
	flag.BoolVar(&config.ChromeNoDHE, "chrome-no-dhe-ciphers", false, "Send chrome ciphers minus DHE suites")

	flag.BoolVar(&config.FirefoxOnly, "firefox-ciphers", false, "Send Firefox Ordered Cipher Suites")

	flag.BoolVar(&config.SafariOnly, "safari-ciphers", false, "Send Safari Ordered Cipher Suites")
	flag.BoolVar(&config.SafariNoDHE, "safari-no-dhe-ciphers", false, "Send Safari ciphers minus DHE suites")

	flag.BoolVar(&config.TLS13Measurements, "tlsm", false, "Vary Cipher Suites and Curves for TLS13Measurement experiment")

	flag.BoolVar(&config.Heartbleed, "heartbleed", false, "Check if server is vulnerable to Heartbleed (implies --tls)")

	flag.BoolVar(&config.GatherSessionTicket, "tls-session-ticket", false, "Send support for TLS Session Tickets and output ticket if presented")
	flag.BoolVar(&config.ExtendedMasterSecret, "tls-extended-master-secret", false, "Offer RFC 7627 Extended Master Secret extension")
	flag.BoolVar(&config.TLSVerbose, "tls-verbose", false, "Add extra TLS information to JSON output (client hello, client KEX, key material, etc)")

	flag.StringVar(&rootCAFileName, "ca-file", "", "List of trusted root certificate authorities in PEM format")
	flag.IntVar(&config.GOMAXPROCS, "gomaxprocs", 3, "Set GOMAXPROCS (default 3)")
	flag.BoolVar(&config.FTP, "ftp", false, "Read FTP banners")
	flag.BoolVar(&config.FTPAuthTLS, "ftp-authtls", false, "Collect FTPS certificates in addition to FTP banners")
	flag.BoolVar(&config.DNP3, "dnp3", false, "Read DNP3 banners")
	flag.BoolVar(&config.Telnet, "telnet", false, "Read telnet banners")
	flag.IntVar(&config.TelnetMaxSize, "telnet-max-size", 65536, "Max bytes to read for telnet banner")

	// Flags for XSSH scanner
	flag.BoolVar(&config.XSSH.XSSH, "xssh", false, "Use the x/crypto SSH scanner")

	// Flags for SMB scanner
	flag.BoolVar(&config.SMB.SMB, "smb", false, "Scan for SMB")
	flag.IntVar(&config.SMB.Protocol, "smb-protocol", 1, "Specify which SMB protocol to scan for")

	flag.StringVar(&config.Blacklist, "blacklist", "", "URI for CIDR blacklist")
	flag.BoolVar(&config.TraceRoute, "traceroute", false, "Trace route information to host")

	flag.StringVar(&config.Proxy, "proxy", "", "Connect through given proxy. Example: socks5://localhost:9050")

	flag.Parse()

	// Validate Go Runtime config
	if config.GOMAXPROCS < 1 {
		zlog.Fatalf("Invalid GOMAXPROCS (must be at least 1, given %d)", config.GOMAXPROCS)
	}

	// Stop the lowliest idiot from using this to DoS people
	if config.ConnectionsPerHost > 50 || config.ConnectionsPerHost < 1 {
		zlog.Fatalf("--connections-per-host must be in the range [0,50]")
	}

	// Validate HTTP
	if config.HTTP.Method != "GET" && config.HTTP.Method != "HEAD" {
		zlog.Fatalf("Bad HTTP Method: %s. Valid options are: GET, HEAD.", config.HTTP.Method)
	}

	// Validate FTP
	if config.FTP && config.Banners {
		zlog.Fatal("--ftp and --banners are mutually exclusive")
	}
	if config.FTPAuthTLS && !config.FTP {
		zlog.Fatal("--ftp-authtls requires usage of --ftp")
	}

	// Validate Telnet
	if config.Telnet && config.Banners {
		zlog.Fatal("--telnet and --banners are mutually exclusive")
	}

	// Validate TLS Versions
	tv := strings.ToUpper(tlsVersion)
	if tv != "" {
		config.TLS = true
	}

	if config.TLS || config.HTTP.MaxRedirects > 0 {

		switch tv {
		case "SSLV3", "SSLV30", "SSLV3.0":
			config.TLSVersion = tls.VersionSSL30
			tlsVersion = "SSLv3"
		case "TLSV1", "TLSV10", "TLSV1.0":
			config.TLSVersion = tls.VersionTLS10
			tlsVersion = "TLSv1.0"
		case "TLSV11", "TLSV1.1":
			config.TLSVersion = tls.VersionTLS11
			tlsVersion = "TLSv1.1"
		case "", "TLSV12", "TLSV1.2":
			config.TLSVersion = tls.VersionTLS12
			tlsVersion = "TLSv1.2"
		case "TLSV13", "TLSV1.3":
			config.TLSVersion = tls.VersionTLS13
			tlsVersion = "TLSv1.3"
		case "TLSV13D18", "TLSV1.3.18":
			config.TLSVersion = tls.VersionTLS13Draft18
			tlsVersion = "TLSv1.3.18"
		case "TLSV13D19", "TLSV1.3.19":
			config.TLSVersion = tls.VersionTLS13Draft19
			tlsVersion = "TLSv1.3.19"
		case "TLSV13D20", "TLSV1.3.20":
			config.TLSVersion = tls.VersionTLS13Draft20
			tlsVersion = "TLSv1.3.20"
		case "TLSV13D21", "TLSV1.3.21":
			config.TLSVersion = tls.VersionTLS13Draft21
			tlsVersion = "TLSv1.3.21"
		case "TLSV13D22", "TLSV1.3.22":
			config.TLSVersion = tls.VersionTLS13Draft22
			tlsVersion = "TLSv1.3.22"
		case "TLSV13D23", "TLSV1.3.23":
			config.TLSVersion = tls.VersionTLS13Draft23
			tlsVersion = "TLSv1.3.23"
		case "TLSV13D24", "TLSV1.3.24":
			config.TLSVersion = tls.VersionTLS13Draft24
			tlsVersion = "TLSv1.3.24"
		case "TLSV13D25", "TLSV1.3.25":
			config.TLSVersion = tls.VersionTLS13Draft25
			tlsVersion = "TLSv1.3.25"
		case "TLSV13D26", "TLSV1.3.26":
			config.TLSVersion = tls.VersionTLS13Draft26
			tlsVersion = "TLSv1.3.26"
		case "TLSV13D27", "TLSV1.3.27":
			config.TLSVersion = tls.VersionTLS13Draft27
			tlsVersion = "TLSv1.3.27"
		case "TLSV13D28", "TLSV1.3.28":
			config.TLSVersion = tls.VersionTLS13Draft28
			tlsVersion = "TLSv1.3.28"
		default:
			zlog.Fatal("Invalid SSL/TLS versions")
		}
	}

	// STARTTLS cannot be used with TLS
	if config.StartTLS && config.TLS {
		zlog.Fatal("Cannot both initiate a TLS and STARTTLS connection")
	}

	if config.EHLODomain != "" {
		config.EHLO = true
	}

	if config.SMTPHelp || config.EHLO {
		config.SMTP = true
	}

	if config.SMTP && !config.EHLO {
		name, err := os.Hostname()
		if err != nil {
			zlog.Fatalf("unable to get hostname for EHLO: %s", err.Error())
		}
		config.EHLODomain = name
		config.EHLO = true
	}

	if config.SMTP && (config.IMAP || config.POP3) {
		zlog.Fatal("Cannot conform to SMTP and IMAP/POP3 at the same time")
	}

	if config.IMAP && config.POP3 {
		zlog.Fatal("Cannot conform to IMAP and POP3 at the same time")
	}

	if config.EHLO && (config.IMAP || config.POP3) {
		zlog.Fatal("Cannot send an EHLO when conforming to IMAP or POP3")
	}

	if config.SMTP {
		mailType = "SMTP"
	} else if config.POP3 {
		mailType = "POP3"
	} else if config.IMAP {
		mailType = "IMAP"
	}

	// Heartbleed requires STARTTLS or TLS
	if config.Heartbleed && !(config.StartTLS || config.TLS) {
		zlog.Fatal("Must specify one of --tls or --starttls for --heartbleed")
	}

	// Validate SMB
	if config.SMB.SMB {
		if config.SMB.Protocol != 1 {
			zlog.Fatal("Currently only smbv1 is supported")
		}
	}

	// Validate port
	if portFlag > 65535 {
		zlog.Fatal("Port", portFlag, "out of range")
	}
	config.Port = uint16(portFlag)

	// Validate timeout
	config.Timeout = time.Duration(timeout) * time.Second

	// Validate senders
	if config.Senders == 0 {
		zlog.Fatal("Error: Need at least one sender")
	}

	// Check the network interface
	var err error

	// Look at CA file
	if rootCAFileName != "" {
		var fd *os.File
		if fd, err = os.Open(rootCAFileName); err != nil {
			zlog.Fatal(err)
		}
		caBytes, readErr := ioutil.ReadAll(fd)
		if readErr != nil {
			zlog.Fatal(err)
		}
		config.RootCAPool = x509.NewCertPool()
		ok := config.RootCAPool.AppendCertsFromPEM(caBytes)
		if !ok {
			zlog.Fatal("Could not read certificates from PEM file. Invalid PEM?")
		}
	}

	if kv, ok := os.LookupEnv("SSLKEYLOGFILE"); ok {
		if f, err := os.Create(kv); err == nil {
			config.KeylogFile = bufio.NewWriter(f)
		}
	}

	// Open input and output files
	switch inputFileName {
	case "-":
		inputFile = os.Stdin
	default:
		if inputFile, err = os.Open(inputFileName); err != nil {
			zlog.Fatal(err)
		}
	}

	switch outputFileName {
	case "-":
		outputConfig.OutputFile = os.Stdout
	default:
		if outputConfig.OutputFile, err = os.Create(outputFileName); err != nil {
			zlog.Fatal(err)
		}
	}

	// Open message file, if applicable
	if messageFileName != "" {
		if messageFile, err := os.Open(messageFileName); err != nil {
			zlog.Fatal(err)
		} else {
			buf := make([]byte, 1024)
			n, err := messageFile.Read(buf)
			config.SendData = true
			config.Data = buf[0:n]
			if err != nil && err != io.EOF {
				zlog.Fatal(err)
			}
			messageFile.Close()
		}
	}

	// Open metadata file
	if metadataFileName == "-" {
		metadataFile = os.Stdout
	} else {
		if metadataFile, err = os.Create(metadataFileName); err != nil {
			zlog.Fatal(err)
		}
	}

	// Open log file, attach to configs
	var logFile *os.File
	if logFileName == "-" {
		logFile = os.Stderr
	} else {
		if logFile, err = os.Create(logFileName); err != nil {
			zlog.Fatal(err)
		}
	}
	logger := zlog.New(logFile, "banner-grab")
	config.ErrorLog = logger

	// Open TLS ClientHello, if applicable
	if clientHelloFileName != "" {
		if clientHello, err := ioutil.ReadFile(clientHelloFileName); err != nil {
			zlog.Fatal(err)
		} else {
			config.ExternalClientHello = clientHello
		}
	}
}

func main() {
	runtime.GOMAXPROCS(config.GOMAXPROCS)
	if prometheusAddress != "" {
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			if err := http.ListenAndServe(prometheusAddress, nil); err != nil {
				config.ErrorLog.Fatalf("could not run prometheus server: %s", err.Error())
			}
		}()
	}

	blacklist.Init(config.Blacklist)

	decoder := zlib.NewGrabTargetDecoder(inputFile, config.LookupDomain)
	marshaler := zlib.NewGrabMarshaler()
	worker := zlib.NewGrabWorker(&config)

	start := time.Now()
	config.ErrorLog.Infof("started grab at %s", start.Format(time.RFC3339))

	processing.Process(decoder, outputConfig.OutputFile, worker, marshaler, config.Senders)

	end := time.Now()
	config.ErrorLog.Infof("finished grab (%d success; %d failure) at %s", worker.Success(), worker.Failure(), end.Format(time.RFC3339))

	s := Summary{
		Port:       config.Port,
		Success:    worker.Success(),
		Failure:    worker.Failure(),
		Total:      worker.Total(),
		StartTime:  start,
		EndTime:    end,
		Duration:   end.Sub(start),
		Senders:    config.Senders,
		Timeout:    config.Timeout,
		TLSVersion: tlsVersion,
		MailType:   mailType,
		SNISupport: !config.NoSNI,
		Flags:      os.Args,
	}
	enc := json.NewEncoder(metadataFile)
	if err := enc.Encode(&s); err != nil {
		config.ErrorLog.Errorf("Unable to write summary: %s", err.Error())
	}
	if config.KeylogFile != nil {
		config.KeylogFile.Flush()
	}
}
