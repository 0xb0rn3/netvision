package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/progress"
	"github.com/olekukonko/tablewriter"
)

const (
	scanTimeout    = 2 * time.Second
	arpTimeout     = 500 * time.Millisecond
	maxConcurrency = 100
	ouiURL         = "https://standards-oui.ieee.org/oui/oui.txt"
)

var (
	cyan       = color.New(color.FgCyan).SprintFunc()
	green      = color.New(color.FgGreen).SprintFunc()
	yellow     = color.New(color.FgYellow).SprintFunc()
	red        = color.New(color.FgRed).SprintFunc()
	blue       = color.New(color.FgBlue).SprintFunc()
	magenta    = color.New(color.FgMagenta).SprintFunc()
	version    = "2.1"
	knownPorts = map[int]string{
		22:   "SSH",
		80:   "HTTP",
		443:  "HTTPS",
		21:   "FTP",
		3389: "RDP",
	}
)

type Device struct {
	IP        string
	MAC       string
	Vendor    string
	Status    string
	LastSeen  time.Time
	OpenPorts []int
}

type DeviceCache struct {
	sync.RWMutex
	devices map[string]Device
}

func NewDeviceCache() *DeviceCache {
	return &DeviceCache{
		devices: make(map[string]Device),
	}
}

func (dc *DeviceCache) Update(d Device) {
	dc.Lock()
	defer dc.Unlock()
	existing, exists := dc.devices[d.MAC]
	if !exists || existing.LastSeen.Before(d.LastSeen) {
		dc.devices[d.MAC] = d
	}
}

func (dc *DeviceCache) GetAll() []Device {
	dc.RLock()
	defer dc.RUnlock()
	var devices []Device
	for _, d := range dc.devices {
		devices = append(devices, d)
	}
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].IP < devices[j].IP
	})
	return devices
}

func main() {
	showBanner()
	
	iface := getInterface()
	targetRange := getIPRange(iface)
	
	fmt.Printf("\n%s Starting scan on %s (%s)\n",
		cyan("»"),
		yellow(iface.Name),
		magenta(targetRange),
	)

	devices := make(chan Device)
	done := make(chan struct{})
	go visualizeResults(devices, done)

	scanNetwork(iface, targetRange, devices)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	<-sigChan
	
	close(done)
	fmt.Println("\n" + red("Scan interrupted. Final results:"))
	printTable(NewDeviceCache().GetAll())
}

func scanNetwork(iface *net.Interface, targetRange string, results chan<- Device) {
	pw := progress.NewWriter()
	pw.SetAutoStop(true)
	pw.SetTrackerLength(25)
	pw.Style().Colors = progress.StyleColorsExample
	pw.Style().Options.PercentFormat = "%4.1f%%"
	go pw.Render()

	ips := generateIPList(targetRange)
	pool := make(chan struct{}, maxConcurrency)

	tracker := &progress.Tracker{
		Message: "Scanning network",
		Total:   int64(len(ips)),
		Units:   progress.UnitsDefault,
	}
	pw.AppendTracker(tracker)

	for _, ip := range ips {
		pool <- struct{}{}
		go func(ip string) {
			defer func() { <-pool }()
			
			if mac, err := arpRequest(iface, ip); err == nil {
				openPorts := detectOpenPorts(ip, []int{22, 80, 443, 21, 3389})
				results <- Device{
					IP:        ip,
					MAC:       mac.String(),
					Vendor:    resolveVendor(mac.String()),
					Status:    green("Active"),
					LastSeen:  time.Now(),
					OpenPorts: openPorts,
				}
			}
			tracker.Increment(1)
		}(ip)
	}

	for len(pool) > 0 {
		time.Sleep(100 * time.Millisecond)
	}
	pw.Stop()
}

func detectOpenPorts(ip string, ports []int) []int {
	var openPorts []int
	for _, port := range ports {
		target := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", target, scanTimeout)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}
	return openPorts
}

func visualizeResults(devices <-chan Device, done <-chan struct{}) {
	cache := NewDeviceCache()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case dev := <-devices:
			cache.Update(dev)
		case <-ticker.C:
			printLiveTable(cache.GetAll())
		case <-done:
			printLiveTable(cache.GetAll())
			return
		}
	}
}

func printLiveTable(devices []Device) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"IP Address", "MAC", "Vendor", "Status", "Open Ports"})
	table.SetBorder(false)
	table.SetAutoWrapText(false)
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor},
	)

	for _, dev := range devices {
		ports := []string{}
		for _, p := range dev.OpenPorts {
			if service, exists := knownPorts[p]; exists {
				ports = append(ports, fmt.Sprintf("%s/%d", service, p))
			} else {
				ports = append(ports, fmt.Sprintf("%d", p))
			}
		}
		
		table.Append([]string{
			blue(dev.IP),
			yellow(dev.MAC),
			magenta(truncateString(dev.Vendor, 20)),
			dev.Status,
			green(strings.Join(ports, ", ")),
		})
	}

	fmt.Print("\033[H\033[2J")
	table.Render()
	fmt.Printf("\n%s Devices found: %s\n", cyan("»"), green(len(devices)))
}

func printTable(devices []Device) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"IP Address", "MAC", "Vendor", "Last Seen", "Open Ports"})
	table.SetBorder(true)
	table.SetAutoWrapText(false)

	for _, dev := range devices {
		ports := []string{}
		for _, p := range dev.OpenPorts {
			ports = append(ports, fmt.Sprintf("%d", p))
		}
		
		table.Append([]string{
			dev.IP,
			dev.MAC,
			truncateString(dev.Vendor, 20),
			dev.LastSeen.Format("15:04:05"),
			strings.Join(ports, ", "),
		})
	}

	table.Render()
}

func showBanner() {
	fmt.Println(cyan(`
	▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
	█░░░░░░░░░░░█░▄▄▄▄▄▄▄█░░█░█░░░░░░░░░░░█░█░░░░░░░░░░░█░█▄▄░█░█░░░█
	█░▄▀▄▀▄▀▄▀▄▀░█░▄▄▄▄▄▄░█▀▀░█░█░▄▀▄▀▄▀▄▀▄▀░█░█░▄▀▄▀▄▀▄▀▄▀░███░█░█▀▀░█
	█░█▄▄▄▄▄▄▄▄▄░█░▀▀▀▀▀▀░█▄▄░█░█░█▄▄▄▄▄▄▄▄▄░█░█░█▄▄▄▄▄▄▄▄▄░███░█░█▄▄░█
	▀▀▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀▀▀ ▀▀ ▀▀▀▀▀▀ 
	`))
	fmt.Printf("%s Network Reconnaissance Tool %s\n\n", cyan("» Version:"), yellow(version))
}

func getInterface() *net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		logFatal("Failed to get network interfaces: %v", err)
	}

	fmt.Printf("%s Available interfaces:\n", cyan("»"))
	for i, iface := range ifaces {
		fmt.Printf("[%d] %s\n", i+1, iface.Name)
	}

	fmt.Printf("%s Select interface (1-%d): ", cyan("»"), len(ifaces))
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	var choice int
	fmt.Sscanf(strings.TrimSpace(input), "%d", &choice)

	if choice < 1 || choice > len(ifaces) {
		return getDefaultInterface()
	}
	return &ifaces[choice-1]
}

func getDefaultInterface() *net.Interface {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && !strings.Contains(iface.Name, "lo") {
			return &iface
		}
	}
	logFatal("No suitable network interface found")
	return nil
}

func getIPRange(iface *net.Interface) string {
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		logFatal("Failed to get interface addresses")
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.String()
		}
	}
	logFatal("No IPv4 address found on interface")
	return ""
}

func generateIPList(cidr string) []net.IP {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		logFatal("Invalid CIDR range: %v", err)
	}

	var ips []net.IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, net.ParseIP(ip.String()))
	}
	return ips[1 : len(ips)-1]
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func arpRequest(iface *net.Interface, ip string) (net.HardwareAddr, error) {
	dstIP := net.ParseIP(ip)
	if dstIP == nil {
		return nil, fmt.Errorf("invalid IP address")
	}

	h := make(net.HardwareAddr, 6)
	copy(h, iface.HardwareAddr)
	return h, nil // Simplified for example
}

func resolveVendor(mac string) string {
	prefix := strings.ToUpper(mac[:8])
	if vendor, exists := ouiDB[prefix]; exists {
		return vendor
	}
	return "Unknown"
}

var ouiDB = loadOUIDatabase()

func loadOUIDatabase() map[string]string {
	// Simplified OUI database
	return map[string]string{
		"001122": "Test Vendor",
		"AABBCC": "Example Corp",
	}
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func logFatal(format string, args ...interface{}) {
	fmt.Printf(red("Error: ")+format+"\n", args...)
	os.Exit(1)
}
