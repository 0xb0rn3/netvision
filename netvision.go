package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jedib0t/go-pretty/v6/progress"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/mdlayher/arp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// [Core Constants and Variables]
const (
	version    = "1.0-RELEASE"
	ouiURL     = "https://standards-oui.ieee.org/oui/oui.txt"
	cacheTime  = 30 * time.Minute
	scanTimeout= 2 * time.Second
)

var (
	cyan    = color.New(color.FgCyan).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	white   = color.New(color.FgWhite).SprintFunc()
	ouiDB   = loadOUI()
	config  = struct {
		iface      string
		rate       int
		stealth    bool
		ports      []int
		gateway    string
	}{}
)

type Host struct {
	IP        string
	MAC       string
	Vendor    string
	Ports     []int
	LastSeen  time.Time
	FirstSeen time.Time
}

type Engine struct {
	sync.RWMutex
	hosts    map[string]*Host
	progress *progress.Writer
	start    time.Time
}

// [Main Execution Flow]
func main() {
	showBanner()
	checkPrivileges()
	initInterface()
	defer cleanup()

	engine := &Engine{
		hosts:    make(map[string]*Host),
		progress: initProgress(),
		start:    time.Now(),
	}
	go engine.progress.Render()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go engine.passiveCapture()
	go engine.activeProbe()

	<-sig
	engine.printResults()
}

// [Network Operations]
func (e *Engine) passiveCapture() {
	handle, err := pcap.OpenLive(config.iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(red("Capture failed: "), err)
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		e.processPacket(packet)
	}
}

func (e *Engine) activeProbe() {
	ips := generateIPs()
	ticker := time.NewTicker(time.Second / time.Duration(config.rate))
	defer ticker.Stop()

	for _, ip := range ips {
		<-ticker.C
		go e.arpProbe(ip)
		if !config.stealth {
			go e.icmpProbe(ip)
		}
	}
}

func (e *Engine) arpProbe(ip string) {
	client, err := arp.Dial(nil)
	if err != nil {
		return
	}
	defer client.Close()

	target := net.ParseIP(ip)
	pkt, _ := arp.NewPacket(arp.OperationRequest, client.HardwareAddr(), net.IPv4zero, client.HardwareAddr(), target)
	
	if err := client.WriteTo(pkt, client.HardwareAddr()); err == nil {
		e.updateHost(ip, "ARP", "")
	}
}

func (e *Engine) icmpProbe(ip string) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("NETVISION"),
		},
	}

	msgBytes, _ := msg.Marshal(nil)
	conn.WriteTo(msgBytes, &net.IPAddr{IP: net.ParseIP(ip)})
}

// [Data Processing]
func (e *Engine) processPacket(packet gopacket.Packet) {
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		e.updateHost(net.IP(arp.SourceProtAddress).String(), "ARP", net.HardwareAddr(arp.SourceHwAddress).String())
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if tcp.SYN && tcp.ACK {
			e.updatePorts(net.IP(packet.NetworkLayer().NetworkFlow().Src().Raw()), int(tcp.SrcPort))
		}
	}
}

func (e *Engine) updateHost(ip, method, mac string) {
	e.Lock()
	defer e.Unlock()

	host, exists := e.hosts[ip]
	if !exists {
		host = &Host{
			IP:        ip,
			MAC:       mac,
			Vendor:    resolveVendor(mac),
			FirstSeen: time.Now(),
		}
		e.hosts[ip] = host
	}

	host.LastSeen = time.Now()
	if mac != "" && host.MAC == "" {
		host.MAC = mac
		host.Vendor = resolveVendor(mac)
	}
}

// [UI and Reporting]
func (e *Engine) printResults() {
	e.progress.Stop()
	fmt.Printf("\n\n%s Scan duration: %s\n", cyan("»"), time.Since(e.start))

	t := table.NewWriter()
	t.AppendHeader(table.Row{"IP Address", "MAC", "Vendor", "Open Ports", "First Seen", "Last Seen"})
	
	e.RLock()
	defer e.RUnlock()
	
	var ips []string
	for ip := range e.hosts {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	for _, ip := range ips {
		h := e.hosts[ip]
		ports := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(h.Ports)), ","), "[]")
		t.AppendRow(table.Row{
			green(h.IP),
			white(h.MAC),
			cyan(h.Vendor),
			yellow(ports),
			h.FirstSeen.Format("15:04:05"),
			h.LastSeen.Format("15:04:05"),
		})
	}

	fmt.Println(t.Render())
}

// [Helper Functions]
func initInterface() {
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					config.iface = i.Name
					config.gateway = getGateway()
					return
				}
			}
		}
	}
	log.Fatal(red("No active interface found"))
}

func getGateway() string {
	if runtime.GOOS == "windows" {
		out, _ := exec.Command("route", "print", "0.0.0.0").Output()
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "0.0.0.0") {
				fields := strings.Fields(line)
				return fields[2]
			}
		}
	} else {
		out, _ := exec.Command("route", "-n").Output()
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) > 1 && fields[0] == "0.0.0.0" {
				return fields[1]
			}
		}
	}
	return "unknown"
}

// [Initialization and Cleanup]
func checkPrivileges() {
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		log.Fatal(red("Requires root/administrator privileges"))
	}
}

func cleanup() {
	fmt.Printf("\n%s Cleaning up...\n", cyan("»"))
}

// [Banner and Presentation]
func showBanner() {
	fmt.Printf(`
▓██   ██▓ ▒█████   ██▀███  ▄▄▄█████▓
 ▒██  ██▒▒██▒  ██▒▓██ ▒ ██▒▓  ██▒ ▓▒
  ▒██ ██░▒██░  ██▒▓██ ░▄█ ▒▒ ▓██░ ▒░
  ░ ▐██▓░▒██   ██░▒██▀▀█▄  ░ ▓██▓ ░ 
  ░ ██▒▓░░ ████▓▒░░██▓ ▒██▒  ▒██▒ ░ 
   ██▒▒▒ ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░  ▒ ░░   
 ▓██ ░▒░   ░ ▒ ▒░   ░▒ ░ ▒░    ░    
 ▒ ▒ ░░  ░ ░ ░ ▒    ░░   ░   ░      
 ░ ░         ░ ░     ░              
 ░ ░                                

%s %s // github.com/0xb0rn3/netvision
`, cyan("NETVISION"), magenta(version))
}

// [OUI Database Handling]
func loadOUI() map[string]string {
	// Implement OUI database loading
	return make(map[string]string)
}

func resolveVendor(mac string) string {
	prefix := strings.ToUpper(mac[:8])
	if vendor, exists := ouiDB[prefix]; exists {
		return vendor
	}
	return "Unknown"
}

// [Utility Functions]
func generateIPs() []string {
	// Implement CIDR to IP list generation
	return []string{}
}

func initProgress() *progress.Writer {
	pw := progress.NewWriter()
	pw.SetStyle(progress.StyleCircle)
	pw.SetTrackerLength(25)
	pw.Style().Colors = progress.StyleColorsExample
	return &pw
}
