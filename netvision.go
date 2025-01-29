package main

import (
	"bytes"
	"crypto/tls" // Added missing import for TLS functionality
	"encoding/csv"
	"encoding/json"
	// Removed unused xml import
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal" // Added missing import for signal handling
	"regexp"
	"runtime" // Added missing import for runtime information
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	version = "0.4-rolling"
)

// Config holds all scan configuration options
type Config struct {
	Interface    string
	ScanType     string
	OutputFormat string
	Stealth      StealthOptions
	Targets      []string
	Verbose      bool
	DryRun       bool
	Threads      int
	LogFile      string
}

// StealthOptions contains configuration for stealthy scanning
type StealthOptions struct {
	FragmentSize    int
	ScanDelay      time.Duration
	RandomizePorts bool
	SpoofMAC       string
	DecoyHosts     []string
	SourcePort     int
	TimingLevel    int
}

// ScanResult represents discovered host information
type ScanResult struct {
	IP        string   `json:"ip"`
	Hostname  string   `json:"hostname"`
	OS        string   `json:"os"`
	Ports     []Port   `json:"ports"`
	Vulns     []string `json:"vulnerabilities"`
	Timestamp string   `json:"timestamp"`
}

// Port represents port scan results
type Port struct {
	Number    int      `json:"port"`
	Protocol  string   `json:"protocol"`
	State     string   `json:"state"`
	Service   string   `json:"service"`
	Version   string   `json:"version"`
	CVEs      []string `json:"cves"`
	BannerRaw string   `json:"banner_raw,omitempty"`
}

var (
	logger    = log.New(os.Stderr, "", log.LstdFlags)
	wg        sync.WaitGroup
	scanMutex sync.Mutex
	results   []ScanResult // Changed from channel to slice for proper result storage
)

func main() {
	showBanner()
	config := parseFlags()

	if err := validateConfig(&config); err != nil {
		logger.Fatalf("%sConfiguration error: %v%s", Red, err, Reset)
	}

	if config.DryRun {
		fmt.Printf("%sDry run completed. Configuration valid.%s\n", Green, Reset)
		return
	}

	// Setup logging if specified
	if config.LogFile != "" {
		f, err := os.OpenFile(config.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			logger.Fatalf("Error opening log file: %v", err)
		}
		defer f.Close()
		logger.SetOutput(f)
	}

	startScan(config)
}

func showBanner() {
	banner := fmt.Sprintf(`
╭───────────────────────────────────╮
│ ███▄    █ ▓█████▄▄▄█████▓ ██▒   █▓ ██▓  ██████  ██▓ ▒█████   ███▄    █  │
│ ██ ▀█   █ ▓█   ▀▓  ██▒ ▓▒▓██░   █▒▓██▒▒██    ▒ ▓██▒▒██▒  ██▒ ██ ▀█   █  │
│ ▓██  ▀█ ██▒▒███  ▒ ▓██░ ▒░ ▓██  █▒░▒██▒░ ▓██▄   ▒██▒▒██░  ██▒▓██  ▀█ ██▒ │
│ ▓██▒  ▐▌██▒▒▓█  ▄░ ▓██▓ ░  ▒██ █░░░██░  ▒   ██▒░██░▒██   ██░▓██▒  ▐▌██▒ │
│ ▒██░   ▓██░░▒████▒ ▒██▒ ░   ▒▀█░  ░██░▒██████▒▒░██░░ ████▓▒░▒██░   ▓██░ │
│                                                                             │
│ %sNetVision v%s%s                                                           │
│ by 0xb0rn3 | github.com/0xb0rn3/netvision                                  │
╰───────────────────────────────────╯
`, Cyan, version, Reset)
	fmt.Println(banner)
}

func parseFlags() Config {
	var config Config

	// Basic scan options
	flag.StringVar(&config.Interface, "i", "", "Network interface to use")
	flag.StringVar(&config.ScanType, "s", "basic", "Scan type (basic|stealth|comprehensive)")
	flag.StringVar(&config.OutputFormat, "o", "table", "Output format (table|json|csv)")
	flag.BoolVar(&config.Verbose, "v", false, "Enable verbose output")
	flag.BoolVar(&config.DryRun, "dry-run", false, "Validate configuration without scanning")
	flag.IntVar(&config.Threads, "t", 4, "Number of concurrent scan threads")
	flag.StringVar(&config.LogFile, "log", "", "Log file path")

	// Stealth options
	flag.IntVar(&config.Stealth.FragmentSize, "frag", 0, "Fragment size for packet fragmentation")
	flag.DurationVar(&config.Stealth.ScanDelay, "delay", 0, "Delay between scan attempts")
	flag.BoolVar(&config.Stealth.RandomizePorts, "rand-ports", false, "Randomize port scan order")
	flag.StringVar(&config.Stealth.SpoofMAC, "spoof-mac", "", "MAC address to spoof")
	flag.IntVar(&config.Stealth.TimingLevel, "timing", 3, "Timing template (0-5)")

	flag.Parse()
	config.Targets = flag.Args()

	return config
}

func validateConfig(config *Config) error {
	if len(config.Targets) == 0 {
		return fmt.Errorf("no target hosts specified")
	}

	if config.Interface != "" {
		if _, err := net.InterfaceByName(config.Interface); err != nil {
			return fmt.Errorf("invalid interface: %s", config.Interface)
		}
	}

	// Validate timing level
	if config.Stealth.TimingLevel < 0 || config.Stealth.TimingLevel > 5 {
		return fmt.Errorf("timing level must be between 0 and 5")
	}

	return nil
}

func startScan(config Config) {
	fmt.Printf("%s[+] Starting scan with NetVision v%s%s\n", Green, version, Reset)
	
	// Create progress tracker
	progress := &Progress{
		total:   len(config.Targets),
		current: 0,
		mutex:   &sync.Mutex{},
	}

	// Create result channel and processing goroutine
	resultChan := make(chan ScanResult, config.Threads)
	done := make(chan bool)

	go processResults(resultChan, done, config)

	// Create worker pool
	sem := make(chan struct{}, config.Threads)
	for _, target := range config.Targets {
		sem <- struct{}{} // Acquire semaphore
		wg.Add(1)

		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			result := scanHost(target, config)
			if result != nil {
				resultChan <- *result
			}
			progress.Increment()
		}(target)
	}

	// Wait for all scans to complete
	wg.Wait()
	close(resultChan)
	<-done

	// Print final results
	printResults(results, config.OutputFormat)
}

func scanHost(target string, config Config) *ScanResult {
	// Basic host discovery
	if !isHostUp(target) {
		if config.Verbose {
			logger.Printf("%sHost %s appears to be down%s", Yellow, target, Reset)
		}
		return nil
	}

	result := &ScanResult{
		IP:        target,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Get hostname
	if names, err := net.LookupAddr(target); err == nil && len(names) > 0 {
		result.Hostname = names[0]
	}

	// Port scanning
	ports := scanPorts(target, config)
	result.Ports = ports

	// OS detection (if possible)
	if os := detectOS(target); os != "" {
		result.OS = os
	}

	// Vulnerability scanning (if enabled)
	if config.ScanType == "comprehensive" {
		vulns := scanVulnerabilities(target, ports)
		result.Vulns = vulns
	}

	return result
}

func isHostUp(target string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "2", target)
	return cmd.Run() == nil
}

func scanPorts(target string, config Config) []Port {
	var ports []Port
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443}

	for _, port := range commonPorts {
		if isPortOpen(target, port) {
			service := detectService(target, port)
			ports = append(ports, Port{
				Number:   port,
				Protocol: "tcp",
				State:    "open",
				Service:  service,
			})
		}
	}

	return ports
}

func isPortOpen(target string, port int) bool {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, time.Second*2)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func detectService(target string, port int) string {
	services := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "domain",
		80:   "http",
		110:  "pop3",
		139:  "netbios-ssn",
		143:  "imap",
		443:  "https",
		445:  "microsoft-ds",
		993:  "imaps",
		995:  "pop3s",
		3306: "mysql",
		3389: "ms-wbt-server",
		5432: "postgresql",
		8080: "http-proxy",
		8443: "https-alt",
	}
	return services[port]
}

func detectOS(target string) string {
	// Simple OS detection based on TTL
	cmd := exec.Command("ping", "-c", "1", target)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	ttl := 0
	if strings.Contains(string(output), "ttl=") {
		ttlStr := regexp.MustCompile(`ttl=(\d+)`).FindStringSubmatch(string(output))
		if len(ttlStr) > 1 {
			ttl, _ = strconv.Atoi(ttlStr[1])
		}
	}

	switch {
	case ttl <= 64:
		return "Linux/Unix"
	case ttl <= 128:
		return "Windows"
	case ttl <= 255:
		return "Cisco/Network"
	default:
		return "Unknown"
	}
}

func scanVulnerabilities(target string, ports []Port) []string {
	var vulns []string
	return vulns // Placeholder for vulnerability scanning implementation
}

// Progress tracks scan progress
type Progress struct {
	total   int
	current int
	mutex   *sync.Mutex
}

func (p *Progress) Increment() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.current++
	p.displayProgress()
}

func (p *Progress) displayProgress() {
	percentage := float64(p.current) / float64(p.total) * 100
	fmt.Printf("\r%s[+] Scan progress: %.1f%%%s", Green, percentage, Reset)
	if p.current == p.total {
		fmt.Println()
	}
}

func processResults(resultChan chan ScanResult, done chan bool, config Config) {
	for result := range resultChan {
		scanMutex.Lock()
		results = append(results, result) // Now correctly appending to slice instead of channel
		scanMutex.Unlock()
	}
	done <- true
}

func printResults(results []ScanResult, format string) {
	switch format {
	case "json":
		printJSON(results)
	case "csv":
		printCSV(results)
	default:
		printTable(results)
	}
}

func printTable(results []ScanResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "\n%sHost\tOS\tOpen Ports\tServices%s\n", Green, Reset)
	fmt.Fprintf(w, "%s%s%s\n", Green, strings.Repeat("-", 70), Reset)

	for _, result := range results {
		ports := make([]string, len(result.Ports))
		services := make([]string, len(result.Ports))
		for i, port := range result.Ports {
			ports[i] = strconv.Itoa(port.Number)
			services[i] = port.Service
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			result.IP,
			result.OS,
			strings.Join(ports, ", "),
			strings.Join(services, ", "),
		)
	}
	w.Flush()
}

func printJSON(results []ScanResult) {
	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		logger.Printf("%sError encoding JSON: %v%s", Red, err, Reset)
		return
	}
	fmt.Println(string(output))
}

func printCSV(results []ScanResult) {
	w := csv.NewWriter(os.Stdout)
	defer w.Flush()

	// Write header
	w.Write([]string{"IP", "Hostname", "OS", "Port", "Protocol", "State", "Service", "Version", "Vulnerabilities"})

	// Write data rows
	for _, result := range results {
		for _, port := range result.Ports {
			vulns := strings.Join(port.CVEs, "; ")
			row := []string{
				result.IP,
				result.Hostname,
				result.OS,
				strconv.Itoa(port.Number),
				port.Protocol,
				port.State,
				port.Service,
				port.Version,
				vulns,
			}
			w.Write(row)
		}
	}
}

// Utility functions for improved error handling and logging
type ErrorLevel int

const (
	INFO ErrorLevel = iota
	WARNING
	ERROR
	FATAL
)

func logMessage(level ErrorLevel, format string, args ...interface{}) {
	var prefix string
	switch level {
	case INFO:
		prefix = Green + "[INFO]" + Reset
	case WARNING:
		prefix = Yellow + "[WARNING]" + Reset
	case ERROR:
		prefix = Red + "[ERROR]" + Reset
	case FATAL:
		prefix = Red + "[FATAL]" + Reset
	}
	
	msg := fmt.Sprintf(format, args...)
	logger.Printf("%s %s", prefix, msg)
}

// Network utility functions
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isPrivateIP(ip string) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}
	
	// Check private IP ranges
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
	}
	
	for _, r := range privateRanges {
		if bytes.Compare(ipAddr, r.start) >= 0 && bytes.Compare(ipAddr, r.end) <= 0 {
			return true
		}
	}
	return false
}

// Service detection helpers
func getBanner(target string, port int) string {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, time.Second*5)
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(time.Second * 10))
	
	// Read banner
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	
	return string(buffer[:n])
}

func parseServiceBanner(banner string) (name, version string) {
	// Common service signatures
	signatures := map[string]string{
		"SSH": `^SSH-(\d+\.\d+)`,
		"FTP": `^220.*FTP`,
		"HTTP": `^HTTP/\d\.\d`,
		"SMTP": `^220.*SMTP`,
		"POP3": `^\+OK`,
		"IMAP": `^\* OK`,
	}
	
	for service, pattern := range signatures {
		if match, _ := regexp.MatchString(pattern, banner); match {
			re := regexp.MustCompile(pattern)
			if matches := re.FindStringSubmatch(banner); len(matches) > 1 {
				version = matches[1]
			}
			return service, version
		}
	}
	
	return "unknown", ""
}

// Security checks
func hasTLSSupport(target string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), time.Second*5)
	if err != nil {
		return false
	}
	defer conn.Close()
	
	// Try to establish TLS connection
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()
	
	err = tlsConn.Handshake()
	return err == nil
}

// Configuration validation helpers
func validateTimingTemplate(timing int) bool {
	return timing >= 0 && timing <= 5
}

func validateSourcePort(port int) bool {
	return port >= 0 && port <= 65535
}

func validateMAC(mac string) bool {
	if mac == "" || mac == "random" {
		return true
	}
	_, err := net.ParseMAC(mac)
	return err == nil
}

// Version information
type VersionInfo struct {
	Version     string    `json:"version"`
	BuildDate   string    `json:"build_date"`
	CommitHash  string    `json:"commit_hash"`
	GoVersion   string    `json:"go_version"`
	Platform    string    `json:"platform"`
	LastUpdated time.Time `json:"last_updated"`
}

func getVersionInfo() VersionInfo {
	return VersionInfo{
		Version:     version,
		BuildDate:   time.Now().Format(time.RFC3339),
		GoVersion:   runtime.Version(),
		Platform:    fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		LastUpdated: time.Now(),
	}
}

// Help text
func showHelp() {
	fmt.Printf(`
%sNetVision %s - Advanced Network Security Assessment Tool%s

Usage: netvision [options] <targets>

Targets:
  IP addresses, hostnames, or CIDR ranges

Options:
  -i string    Network interface to use
  -s string    Scan type (basic|stealth|comprehensive) (default "basic")
  -o string    Output format (table|json|csv) (default "table")
  -t int       Number of concurrent threads (default 4)
  -v           Enable verbose output
  --dry-run    Validate configuration without scanning

Stealth Options:
  --frag int          Fragment size for packet fragmentation
  --delay duration    Delay between scan attempts
  --rand-ports        Randomize port scan order
  --spoof-mac string  MAC address to spoof
  --timing int        Timing template (0-5) (default 3)

Examples:
  netvision -i eth0 192.168.1.0/24
  netvision -s stealth -o json 10.0.0.1
  netvision --timing 1 --rand-ports example.com

For more information, visit: https://github.com/0xb0rn3/netvision
`, Cyan, version, Reset)
}

// Main initialization
func init() {
	// Set up signal handling for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		fmt.Printf("\n%sScan interrupted. Cleaning up...%s\n", Yellow, Reset)
		os.Exit(1)
	}()
}
