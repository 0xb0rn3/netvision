package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
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
)

var (
	cyan       = color.New(color.FgCyan).SprintFunc()
	green      = color.New(color.FgGreen).SprintFunc()
	yellow     = color.New(color.FgYellow).SprintFunc()
	red        = color.New(color.FgRed).SprintFunc()
	blue       = color.New(color.FgBlue).SprintFunc()
	magenta    = color.New(color.FgMagenta).SprintFunc()
	version    = "2.1"
	ouiDB      = loadOUIDatabase()
	knownPorts = map[int]string{
		22:  "SSH",
		80:  "HTTP",
		443: "HTTPS",
		21:  "FTP",
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

	// Start scanning
	scanNetwork(iface, targetRange, devices)

	// Handle CTRL+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	<-sigChan
	
	close(done)
	fmt.Println("\n" + red("Scan interrupted. Final results:"))
	printTable(getCachedDevices())
}

func scanNetwork(iface *net.Interface, targetRange string, results chan<- Device) {
	pw := initProgress()
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
	cache := newDeviceCache()
	
	for {
		select {
		case dev := <-devices:
			cache.Update(dev)
			printLiveTable(cache.GetAll())
			
		case <-done:
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

	fmt.Print("\033[H\033[2J") // Clear screen
	table.Render()
	fmt.Printf("\n%s Devices found: %s\n", 
		cyan("»"), 
		green(len(devices)),
	)
}

// Helper functions would include:
// - showBanner() - Colored ASCII art
// - initProgress() - Progress bar setup
// - arpRequest() - ARP scanning logic
// - resolveVendor() - MAC vendor lookup
// - getInterface() - Network interface selection
// - loadOUIDatabase() - MAC vendor database
// - deviceCache implementation

func showBanner() {
	fmt.Println(cyan(`
	▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
	█░░░░░░░░░░░█░▄▄▄▄▄▄▄█░░█░█░░░░░░░░░░░█░█░░░░░░░░░░░█░█▄▄░█░█░░░█
	█░▄▀▄▀▄▀▄▀▄▀░█░▄▄▄▄▄▄░█▀▀░█░█░▄▀▄▀▄▀▄▀▄▀░█░█░▄▀▄▀▄▀▄▀▄▀░███░█░█▀▀░█
	█░█▄▄▄▄▄▄▄▄▄░█░▀▀▀▀▀▀░█▄▄░█░█░█▄▄▄▄▄▄▄▄▄░█░█░█▄▄▄▄▄▄▄▄▄░███░█░█▄▄░█
	▀▀▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀▀▀ ▀▀ ▀▀▀▀▀▀ 
	`))
	fmt.Printf("%s Network Reconnaissance Tool %s\n\n",
		cyan("» Version:"),
		yellow(version),
	)
}
