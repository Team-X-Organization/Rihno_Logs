package main

import (
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// CompleteFeatureVector with all host and network features
type CompleteFeatureVector struct {
	Timestamp time.Time `json:"timestamp"`

	// ========== HOST-BASED FEATURES ==========
	// Process Features
	ProcessCount           int     `json:"process_count"`
	ProcessCreationRate    int     `json:"process_creation_rate"`
	ProcessTermRate        int     `json:"process_termination_rate"`
	HighCPUProcessCount    int     `json:"high_cpu_process_count"`
	HighMemProcessCount    int     `json:"high_mem_process_count"`
	AvgProcessCPU          float64 `json:"avg_process_cpu"`
	AvgProcessMemory       float64 `json:"avg_process_memory"`
	AvgProcessRSS          uint64  `json:"avg_process_rss"`
	AvgProcessVMS          uint64  `json:"avg_process_vms"`
	TotalThreads           int     `json:"total_threads"`
	ZombieProcessCount     int     `json:"zombie_process_count"`
	RootProcessCount       int     `json:"root_process_count"`
	AvgProcessAge          float64 `json:"avg_process_age_seconds"`
	ProcessWithManyThreads int     `json:"process_with_many_threads"` // >100 threads
	SuspiciousProcessNames int     `json:"suspicious_process_names"`
	TotalFileDescriptors   int     `json:"total_file_descriptors"`

	// System Resources
	SystemCPU           float64   `json:"system_cpu"`
	PerCoreCPU          []float64 `json:"per_core_cpu"` // Will be averaged for CSV
	AvgCoreCPU          float64   `json:"avg_core_cpu"`
	SystemMemoryPercent float64   `json:"system_memory_percent"`
	SystemMemoryUsed    uint64    `json:"system_memory_used"`
	SystemMemoryAvail   uint64    `json:"system_memory_available"`
	SystemMemoryTotal   uint64    `json:"system_memory_total"`
	SwapUsedPercent     float64   `json:"swap_used_percent"`
	SwapTotal           uint64    `json:"swap_total"`
	SwapUsed            uint64    `json:"swap_used"`

	// Disk I/O
	DiskReadBytes  uint64  `json:"disk_read_bytes"`
	DiskWriteBytes uint64  `json:"disk_write_bytes"`
	DiskReadRate   float64 `json:"disk_read_rate"`
	DiskWriteRate  float64 `json:"disk_write_rate"`
	DiskReadCount  uint64  `json:"disk_read_count"`
	DiskWriteCount uint64  `json:"disk_write_count"`
	DiskIORate     float64 `json:"disk_io_rate"` // Combined read+write rate

	// User Sessions
	LoggedInUsers  int      `json:"logged_in_users"`
	UserTerminals  []string `json:"user_terminals"`
	UserHosts      []string `json:"user_hosts"`
	SystemUptime   uint64   `json:"system_uptime"`
	SystemBootTime uint64   `json:"system_boot_time"`

	// Derived Host Features
	CPUUsageSpike    float64 `json:"cpu_usage_spike"`
	MemoryUsageSpike float64 `json:"memory_usage_spike"`

	// ========== NETWORK-BASED FEATURES ==========
	// Connection Statistics
	TotalConnections       int `json:"total_connections"`
	TCPConnections         int `json:"tcp_connections"`
	UDPConnections         int `json:"udp_connections"`
	EstablishedConnections int `json:"established_connections"`
	ListenConnections      int `json:"listen_connections"`
	TimeWaitConnections    int `json:"time_wait_connections"`
	SynSentConnections     int `json:"syn_sent_connections"`
	SynRecvConnections     int `json:"syn_recv_connections"`
	CloseWaitConnections   int `json:"close_wait_connections"`
	FinWaitConnections     int `json:"fin_wait_connections"`

	// Interface Statistics
	NetBytesSent      uint64  `json:"net_bytes_sent"`
	NetBytesRecv      uint64  `json:"net_bytes_recv"`
	NetPacketsSent    uint64  `json:"net_packets_sent"`
	NetPacketsRecv    uint64  `json:"net_packets_recv"`
	NetErrorsIn       uint64  `json:"net_errors_in"`
	NetErrorsOut      uint64  `json:"net_errors_out"`
	NetDropsIn        uint64  `json:"net_drops_in"`
	NetDropsOut       uint64  `json:"net_drops_out"`
	NetSendRate       float64 `json:"net_send_rate"`
	NetRecvRate       float64 `json:"net_recv_rate"`
	NetPacketSendRate float64 `json:"net_packet_send_rate"`
	NetPacketRecvRate float64 `json:"net_packet_recv_rate"`

	// IP Address Features
	UniqueSourceIPs      int    `json:"unique_source_ips"`
	UniqueDestIPs        int    `json:"unique_dest_ips"`
	NewSourceIPs         int    `json:"new_source_ips"`
	PrivateIPConnections int    `json:"private_ip_connections"`
	PublicIPConnections  int    `json:"public_ip_connections"`
	TopSourceIPCount     int    `json:"top_source_ip_count"`
	TopSourceIP          string `json:"top_source_ip"`

	// Port Features
	UniqueLocalPorts    int `json:"unique_local_ports"`
	UniqueRemotePorts   int `json:"unique_remote_ports"`
	WellKnownPortConns  int `json:"well_known_port_connections"`
	EphemeralPortConns  int `json:"ephemeral_port_connections"`
	SuspiciousPortConns int `json:"suspicious_port_connections"`
	PortScanIndicators  int `json:"port_scan_indicators"`

	// Protocol Distribution
	TCPRatio    float64 `json:"tcp_ratio"`
	UDPRatio    float64 `json:"udp_ratio"`
	TCPUDPRatio float64 `json:"tcp_udp_ratio"`

	// Process Network Activity
	ProcessesWithNetActivity int     `json:"processes_with_net_activity"`
	AvgConnectionsPerProcess float64 `json:"avg_connections_per_process"`

	// Traffic Rates
	ConnectionCreationRate    int `json:"connection_creation_rate"`
	ConnectionTerminationRate int `json:"connection_termination_rate"`

	// Geographic/External
	ExternalIPCount      int `json:"external_ip_count"`
	LoopbackConnections  int `json:"loopback_connections"`
	BroadcastConnections int `json:"broadcast_connections"`

	// Derived Network Features
	ConnectionChurnRate   float64 `json:"connection_churn_rate"`
	ConnectionDensity     float64 `json:"connection_density"`
	PortScanningScore     float64 `json:"port_scanning_score"`
	DataExfiltrationScore float64 `json:"data_exfiltration_score"`
	BandwidthAsymmetry    float64 `json:"bandwidth_asymmetry"`
	C2CommunicationScore  float64 `json:"c2_communication_score"`
	FailedConnectionRatio float64 `json:"failed_connection_ratio"`
}

// Collector state for tracking changes
type CompleteCollectorState struct {
	// Host state
	LastPIDs           map[int32]bool
	LastDiskReadBytes  uint64
	LastDiskWriteBytes uint64
	LastCPU            float64
	LastMemory         float64

	// Network state
	LastNetBytesSent   uint64
	LastNetBytesRecv   uint64
	LastNetPacketsSent uint64
	LastNetPacketsRecv uint64
	LastConnections    map[string]bool
	LastSourceIPs      map[string]bool

	// For C2 detection
	ConnectionTimestamps []time.Time
	PacketSizes          []uint64

	LastTimestamp time.Time
}

func NewCompleteCollectorState() *CompleteCollectorState {
	return &CompleteCollectorState{
		LastPIDs:             make(map[int32]bool),
		LastConnections:      make(map[string]bool),
		LastSourceIPs:        make(map[string]bool),
		ConnectionTimestamps: make([]time.Time, 0),
		PacketSizes:          make([]uint64, 0),
		LastTimestamp:        time.Now(),
	}
}

// List of suspicious ports commonly used by malware
var suspiciousPorts = map[uint32]bool{
	1337: true, 31337: true, // Elite/leet hacker ports
	4444: true, 5555: true, // Metasploit default
	6667: true, 6668: true, 6669: true, // IRC (potential botnet C2)
	12345: true, 54321: true, // NetBus trojan
	1234: true,             // SubSeven trojan
	9999: true,             // Various trojans
	8866: true, 8888: true, // Various backdoors
}

// Suspicious process name patterns
var suspiciousProcessPatterns = []string{
	"mimikatz", "psexec", "procdump", "lazagne",
	"nc.exe", "netcat", "powershell", "cmd.exe",
	"wscript", "cscript", "mshta", "rundll32",
	"regsvr32", "certutil", "bitsadmin",
}

func CollectCompleteFeatures(state *CompleteCollectorState) (*CompleteFeatureVector, error) {
	features := &CompleteFeatureVector{
		Timestamp: time.Now(),
	}

	timeDelta := features.Timestamp.Sub(state.LastTimestamp).Seconds()
	if timeDelta == 0 {
		timeDelta = 10
	}

	// ========== COLLECT HOST FEATURES ==========
	if err := collectHostFeatures(features, state, timeDelta); err != nil {
		return nil, err
	}

	// ========== COLLECT NETWORK FEATURES ==========
	if err := collectNetworkFeatures(features, state, timeDelta); err != nil {
		return nil, err
	}

	// ========== CALCULATE DERIVED FEATURES ==========
	calculateDerivedFeatures(features, state)

	// Update state for next iteration
	state.LastTimestamp = features.Timestamp
	state.LastCPU = features.SystemCPU
	state.LastMemory = features.SystemMemoryPercent

	return features, nil
}

func collectHostFeatures(features *CompleteFeatureVector, state *CompleteCollectorState, timeDelta float64) error {
	// Process features
	processes, err := process.Processes()
	if err != nil {
		return fmt.Errorf("error getting processes: %w", err)
	}

	features.ProcessCount = len(processes)
	currentPIDs := make(map[int32]bool)

	var totalCPU, totalMemory, totalRSS, totalVMS uint64
	var totalAge float64
	var cpuCount, memCount, rssCount, ageCount int

	for _, p := range processes {
		pid := p.Pid
		currentPIDs[pid] = true

		// CPU
		cpuPercent, err := p.CPUPercent()
		if err == nil {
			totalCPU += uint64(cpuPercent * 1000) // Store as int for averaging
			cpuCount++
			if cpuPercent > 50.0 {
				features.HighCPUProcessCount++
			}
		}

		// Memory percent
		memPercent, err := p.MemoryPercent()
		if err == nil {
			totalMemory += uint64(memPercent * 1000)
			memCount++
			if memPercent > 10.0 {
				features.HighMemProcessCount++
			}
		}

		// Memory info (RSS, VMS)
		memInfo, err := p.MemoryInfo()
		if err == nil {
			totalRSS += memInfo.RSS
			totalVMS += memInfo.VMS
			rssCount++
		}

		// Threads
		numThreads, err := p.NumThreads()
		if err == nil {
			features.TotalThreads += int(numThreads)
			if numThreads > 100 {
				features.ProcessWithManyThreads++
			}
		}

		// Status
		status, err := p.Status()
		if err == nil && len(status) > 0 {
			if status[0] == "zombie" || status[0] == "Z" {
				features.ZombieProcessCount++
			}
		}

		// Username
		username, err := p.Username()
		if err == nil && (username == "root" || username == "SYSTEM" || username == "NT AUTHORITY\\SYSTEM") {
			features.RootProcessCount++
		}

		// Process age
		createTime, err := p.CreateTime()
		if err == nil {
			age := float64(time.Now().Unix()) - float64(createTime/1000)
			totalAge += age
			ageCount++
		}

		// Process name - check for suspicious patterns
		name, err := p.Name()
		if err == nil {
			nameLower := strings.ToLower(name)
			for _, pattern := range suspiciousProcessPatterns {
				if strings.Contains(nameLower, pattern) {
					features.SuspiciousProcessNames++
					break
				}
			}
		}

		// File descriptors (Linux/macOS only)
		numFDs, err := p.NumFDs()
		if err == nil {
			features.TotalFileDescriptors += int(numFDs)
		}
	}

	// Calculate averages
	if cpuCount > 0 {
		features.AvgProcessCPU = float64(totalCPU) / float64(cpuCount) / 1000.0
	}
	if memCount > 0 {
		features.AvgProcessMemory = float64(totalMemory) / float64(memCount) / 1000.0
	}
	if rssCount > 0 {
		features.AvgProcessRSS = totalRSS / uint64(rssCount)
		features.AvgProcessVMS = totalVMS / uint64(rssCount)
	}
	if ageCount > 0 {
		features.AvgProcessAge = totalAge / float64(ageCount)
	}

	// Calculate process creation/termination
	for pid := range currentPIDs {
		if !state.LastPIDs[pid] {
			features.ProcessCreationRate++
		}
	}
	for pid := range state.LastPIDs {
		if !currentPIDs[pid] {
			features.ProcessTermRate++
		}
	}
	state.LastPIDs = currentPIDs

	// System CPU
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err == nil && len(cpuPercent) > 0 {
		features.SystemCPU = cpuPercent[0]
	}

	// Per-core CPU
	perCoreCPU, err := cpu.Percent(time.Second, true)
	if err == nil {
		features.PerCoreCPU = perCoreCPU
		var sum float64
		for _, cpuVal := range perCoreCPU {
			sum += cpuVal
		}
		if len(perCoreCPU) > 0 {
			features.AvgCoreCPU = sum / float64(len(perCoreCPU))
		}
	}

	// Memory
	memInfo, err := mem.VirtualMemory()
	if err == nil {
		features.SystemMemoryPercent = memInfo.UsedPercent
		features.SystemMemoryUsed = memInfo.Used
		features.SystemMemoryAvail = memInfo.Available
		features.SystemMemoryTotal = memInfo.Total
	}

	// Swap
	swapInfo, err := mem.SwapMemory()
	if err == nil {
		features.SwapUsedPercent = swapInfo.UsedPercent
		features.SwapTotal = swapInfo.Total
		features.SwapUsed = swapInfo.Used
	}

	// Disk I/O
	diskIO, err := disk.IOCounters()
	if err == nil {
		var totalReadBytes, totalWriteBytes, totalReadCount, totalWriteCount uint64
		for _, io := range diskIO {
			totalReadBytes += io.ReadBytes
			totalWriteBytes += io.WriteBytes
			totalReadCount += io.ReadCount
			totalWriteCount += io.WriteCount
		}
		features.DiskReadBytes = totalReadBytes
		features.DiskWriteBytes = totalWriteBytes
		features.DiskReadCount = totalReadCount
		features.DiskWriteCount = totalWriteCount

		if state.LastDiskReadBytes > 0 {
			features.DiskReadRate = float64(totalReadBytes-state.LastDiskReadBytes) / timeDelta
		}
		if state.LastDiskWriteBytes > 0 {
			features.DiskWriteRate = float64(totalWriteBytes-state.LastDiskWriteBytes) / timeDelta
		}
		features.DiskIORate = features.DiskReadRate + features.DiskWriteRate

		state.LastDiskReadBytes = totalReadBytes
		state.LastDiskWriteBytes = totalWriteBytes
	}

	// User sessions
	users, err := host.Users()
	if err == nil {
		features.LoggedInUsers = len(users)
		for _, user := range users {
			if user.Terminal != "" {
				features.UserTerminals = append(features.UserTerminals, user.Terminal)
			}
			if user.Host != "" {
				features.UserHosts = append(features.UserHosts, user.Host)
			}
		}
	}

	// System info
	uptime, err := host.Uptime()
	if err == nil {
		features.SystemUptime = uptime
	}

	bootTime, err := host.BootTime()
	if err == nil {
		features.SystemBootTime = bootTime
	}

	return nil
}

func collectNetworkFeatures(features *CompleteFeatureVector, state *CompleteCollectorState, timeDelta float64) error {
	// Network interface statistics
	netIO, err := psnet.IOCounters(false)
	if err == nil && len(netIO) > 0 {
		features.NetBytesSent = netIO[0].BytesSent
		features.NetBytesRecv = netIO[0].BytesRecv
		features.NetPacketsSent = netIO[0].PacketsSent
		features.NetPacketsRecv = netIO[0].PacketsRecv
		features.NetErrorsIn = netIO[0].Errin
		features.NetErrorsOut = netIO[0].Errout
		features.NetDropsIn = netIO[0].Dropin
		features.NetDropsOut = netIO[0].Dropout

		// Calculate rates
		if state.LastNetBytesSent > 0 {
			features.NetSendRate = float64(netIO[0].BytesSent-state.LastNetBytesSent) / timeDelta
		}
		if state.LastNetBytesRecv > 0 {
			features.NetRecvRate = float64(netIO[0].BytesRecv-state.LastNetBytesRecv) / timeDelta
		}
		if state.LastNetPacketsSent > 0 {
			features.NetPacketSendRate = float64(netIO[0].PacketsSent-state.LastNetPacketsSent) / timeDelta
		}
		if state.LastNetPacketsRecv > 0 {
			features.NetPacketRecvRate = float64(netIO[0].PacketsRecv-state.LastNetPacketsRecv) / timeDelta
		}

		state.LastNetBytesSent = netIO[0].BytesSent
		state.LastNetBytesRecv = netIO[0].BytesRecv
		state.LastNetPacketsSent = netIO[0].PacketsSent
		state.LastNetPacketsRecv = netIO[0].PacketsRecv
	}

	// Get all connections
	connections, err := psnet.Connections("all")
	if err != nil {
		return fmt.Errorf("error getting connections: %w", err)
	}

	features.TotalConnections = len(connections)

	// Track unique IPs and ports
	sourceIPs := make(map[string]bool)
	destIPs := make(map[string]bool)
	localPorts := make(map[uint32]bool)
	remotePorts := make(map[uint32]bool)
	currentConnections := make(map[string]bool)
	currentSourceIPs := make(map[string]bool)

	// Track connections per IP for port scan detection
	portsPerIP := make(map[string]map[uint32]bool)
	connectionsPerSourceIP := make(map[string]int)

	// Process-level network tracking
	processConnections := make(map[int32]int)

	// Failed connections tracking
	failedConnections := 0

	for _, conn := range connections {
		// Connection states
		switch conn.Status {
		case "ESTABLISHED":
			features.EstablishedConnections++
		case "LISTEN":
			features.ListenConnections++
		case "TIME_WAIT":
			features.TimeWaitConnections++
			failedConnections++ // Consider TIME_WAIT as potentially failed
		case "SYN_SENT":
			features.SynSentConnections++
		case "SYN_RECV":
			features.SynRecvConnections++
		case "CLOSE_WAIT":
			features.CloseWaitConnections++
		case "FIN_WAIT1", "FIN_WAIT2":
			features.FinWaitConnections++
		}

		// Protocol counting
		switch conn.Type {
		case 1: // SOCK_STREAM (TCP)
			features.TCPConnections++
		case 2: // SOCK_DGRAM (UDP)
			features.UDPConnections++
		}

		// IP tracking
		if conn.Raddr.IP != "" {
			sourceIPs[conn.Raddr.IP] = true
			currentSourceIPs[conn.Raddr.IP] = true
			connectionsPerSourceIP[conn.Raddr.IP]++

			// Track ports per IP for port scan detection
			if portsPerIP[conn.Raddr.IP] == nil {
				portsPerIP[conn.Raddr.IP] = make(map[uint32]bool)
			}
			portsPerIP[conn.Raddr.IP][conn.Laddr.Port] = true

			// Check if IP is private or public
			if isPrivateIP(conn.Raddr.IP) {
				features.PrivateIPConnections++
			} else {
				features.PublicIPConnections++
				features.ExternalIPCount++
			}

			// Check for loopback
			if isLoopback(conn.Raddr.IP) {
				features.LoopbackConnections++
			}

			// Check for broadcast
			if isBroadcast(conn.Raddr.IP) {
				features.BroadcastConnections++
			}
		}

		if conn.Laddr.IP != "" {
			destIPs[conn.Laddr.IP] = true
		}

		// Port tracking
		if conn.Laddr.Port > 0 {
			localPorts[conn.Laddr.Port] = true

			if conn.Laddr.Port < 1024 {
				features.WellKnownPortConns++
			} else if conn.Laddr.Port > 32768 {
				features.EphemeralPortConns++
			}
		}

		if conn.Raddr.Port > 0 {
			remotePorts[conn.Raddr.Port] = true

			// Check for suspicious ports
			if suspiciousPorts[conn.Raddr.Port] || suspiciousPorts[conn.Laddr.Port] {
				features.SuspiciousPortConns++
			}
		}

		// Track connection for churn calculation
		connKey := fmt.Sprintf("%s:%d-%s:%d-%s",
			conn.Laddr.IP, conn.Laddr.Port,
			conn.Raddr.IP, conn.Raddr.Port,
			conn.Status)
		currentConnections[connKey] = true

		// Process network activity
		if conn.Pid > 0 {
			processConnections[conn.Pid]++
		}
	}

	// Calculate unique counts
	features.UniqueSourceIPs = len(sourceIPs)
	features.UniqueDestIPs = len(destIPs)
	features.UniqueLocalPorts = len(localPorts)
	features.UniqueRemotePorts = len(remotePorts)

	// Calculate new source IPs
	for ip := range currentSourceIPs {
		if !state.LastSourceIPs[ip] {
			features.NewSourceIPs++
		}
	}
	state.LastSourceIPs = currentSourceIPs

	// Find top source IP
	maxConns := 0
	for ip, count := range connectionsPerSourceIP {
		if count > maxConns {
			maxConns = count
			features.TopSourceIP = ip
		}
	}
	features.TopSourceIPCount = maxConns

	// Port scan detection
	for _, ports := range portsPerIP {
		if len(ports) > 10 {
			features.PortScanIndicators++
		}
	}

	// Protocol ratios
	if features.TotalConnections > 0 {
		features.TCPRatio = float64(features.TCPConnections) / float64(features.TotalConnections)
		features.UDPRatio = float64(features.UDPConnections) / float64(features.TotalConnections)
		features.FailedConnectionRatio = float64(failedConnections) / float64(features.TotalConnections)
	}
	if features.UDPConnections > 0 {
		features.TCPUDPRatio = float64(features.TCPConnections) / float64(features.UDPConnections)
	}

	// Process network activity
	features.ProcessesWithNetActivity = len(processConnections)
	if features.ProcessesWithNetActivity > 0 {
		features.AvgConnectionsPerProcess = float64(features.TotalConnections) / float64(features.ProcessesWithNetActivity)
	}

	// Connection churn
	newConns := 0
	for conn := range currentConnections {
		if !state.LastConnections[conn] {
			newConns++
			state.ConnectionTimestamps = append(state.ConnectionTimestamps, time.Now())
		}
	}
	closedConns := 0
	for conn := range state.LastConnections {
		if !currentConnections[conn] {
			closedConns++
		}
	}
	features.ConnectionCreationRate = newConns
	features.ConnectionTerminationRate = closedConns
	state.LastConnections = currentConnections

	return nil
}

func calculateDerivedFeatures(features *CompleteFeatureVector, state *CompleteCollectorState) {
	// Host-based derived features
	features.CPUUsageSpike = features.SystemCPU - state.LastCPU
	features.MemoryUsageSpike = features.SystemMemoryPercent - state.LastMemory

	// Connection churn rate
	if features.TotalConnections > 0 {
		features.ConnectionChurnRate = float64(features.ConnectionCreationRate+features.ConnectionTerminationRate) /
			float64(features.TotalConnections)
	}

	// Connection density
	if features.ProcessesWithNetActivity > 0 {
		features.ConnectionDensity = float64(features.TotalConnections) /
			float64(features.ProcessesWithNetActivity)
	}

	// Port scanning score
	features.PortScanningScore = float64(features.PortScanIndicators) * 10.0
	if features.SynSentConnections > 50 {
		features.PortScanningScore += float64(features.SynSentConnections) / 10.0
	}

	// Data exfiltration score
	if features.NetRecvRate > 0 {
		outboundRatio := features.NetSendRate / (features.NetSendRate + features.NetRecvRate)
		if outboundRatio > 0.8 && features.NetSendRate > 1024*1024 {
			features.DataExfiltrationScore = outboundRatio * 100.0
		}
	}

	// Bandwidth asymmetry
	totalBandwidth := features.NetSendRate + features.NetRecvRate
	if totalBandwidth > 0 {
		diff := features.NetSendRate - features.NetRecvRate
		if diff < 0 {
			diff = -diff
		}
		features.BandwidthAsymmetry = diff / totalBandwidth
	}

	// C2 Communication Score (regular intervals detection)
	if len(state.ConnectionTimestamps) > 5 {
		// Keep only last 100 timestamps
		if len(state.ConnectionTimestamps) > 100 {
			state.ConnectionTimestamps = state.ConnectionTimestamps[len(state.ConnectionTimestamps)-100:]
		}

		// Calculate interval regularity
		if len(state.ConnectionTimestamps) >= 3 {
			intervals := make([]float64, 0)
			for i := 1; i < len(state.ConnectionTimestamps); i++ {
				interval := state.ConnectionTimestamps[i].Sub(state.ConnectionTimestamps[i-1]).Seconds()
				intervals = append(intervals, interval)
			}

			// Calculate variance
			if len(intervals) > 0 {
				var sum, mean, variance float64
				for _, interval := range intervals {
					sum += interval
				}
				mean = sum / float64(len(intervals))

				for _, interval := range intervals {
					variance += (interval - mean) * (interval - mean)
				}
				variance /= float64(len(intervals))

				// Low variance = regular intervals = potential C2
				if mean > 0 && variance/mean < 0.1 {
					features.C2CommunicationScore = 100.0 * (1.0 - variance/mean)
				}
			}
		}
	}
}

func isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range private {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func isLoopback(ip string) bool {
	return strings.HasPrefix(ip, "127.") || ip == "::1"
}

func isBroadcast(ip string) bool {
	return ip == "255.255.255.255"
}

// getCSVHeaders returns all the CSV column headers
func getCSVHeaders() []string {
	return []string{
		"timestamp",
		// Host-based features
		"process_count",
		"process_creation_rate",
		"process_termination_rate",
		"high_cpu_process_count",
		"high_mem_process_count",
		"avg_process_cpu",
		"avg_process_memory",
		"avg_process_rss",
		"avg_process_vms",
		"total_threads",
		"zombie_process_count",
		"root_process_count",
		"avg_process_age_seconds",
		"process_with_many_threads",
		"suspicious_process_names",
		"total_file_descriptors",
		"system_cpu",
		"avg_core_cpu",
		"system_memory_percent",
		"system_memory_used",
		"system_memory_available",
		"system_memory_total",
		"swap_used_percent",
		"swap_total",
		"swap_used",
		"disk_read_bytes",
		"disk_write_bytes",
		"disk_read_rate",
		"disk_write_rate",
		"disk_read_count",
		"disk_write_count",
		"disk_io_rate",
		"logged_in_users",
		"system_uptime",
		"system_boot_time",
		"cpu_usage_spike",
		"memory_usage_spike",
		// Network-based features
		"total_connections",
		"tcp_connections",
		"udp_connections",
		"established_connections",
		"listen_connections",
		"time_wait_connections",
		"syn_sent_connections",
		"syn_recv_connections",
		"close_wait_connections",
		"fin_wait_connections",
		"net_bytes_sent",
		"net_bytes_recv",
		"net_packets_sent",
		"net_packets_recv",
		"net_errors_in",
		"net_errors_out",
		"net_drops_in",
		"net_drops_out",
		"net_send_rate",
		"net_recv_rate",
		"net_packet_send_rate",
		"net_packet_recv_rate",
		"unique_source_ips",
		"unique_dest_ips",
		"new_source_ips",
		"private_ip_connections",
		"public_ip_connections",
		"top_source_ip_count",
		"top_source_ip",
		"unique_local_ports",
		"unique_remote_ports",
		"well_known_port_connections",
		"ephemeral_port_connections",
		"suspicious_port_connections",
		"port_scan_indicators",
		"tcp_ratio",
		"udp_ratio",
		"tcp_udp_ratio",
		"processes_with_net_activity",
		"avg_connections_per_process",
		"connection_creation_rate",
		"connection_termination_rate",
		"external_ip_count",
		"loopback_connections",
		"broadcast_connections",
		"connection_churn_rate",
		"connection_density",
		"port_scanning_score",
		"data_exfiltration_score",
		"bandwidth_asymmetry",
		"c2_communication_score",
		"failed_connection_ratio",
	}
}

// featureToCSVRow converts a feature vector to CSV row
func featureToCSVRow(f *CompleteFeatureVector) []string {
	return []string{
		f.Timestamp.Format("2006-01-02 15:04:05"),
		// Host-based features
		strconv.Itoa(f.ProcessCount),
		strconv.Itoa(f.ProcessCreationRate),
		strconv.Itoa(f.ProcessTermRate),
		strconv.Itoa(f.HighCPUProcessCount),
		strconv.Itoa(f.HighMemProcessCount),
		strconv.FormatFloat(f.AvgProcessCPU, 'f', 6, 64),
		strconv.FormatFloat(f.AvgProcessMemory, 'f', 6, 64),
		strconv.FormatUint(f.AvgProcessRSS, 10),
		strconv.FormatUint(f.AvgProcessVMS, 10),
		strconv.Itoa(f.TotalThreads),
		strconv.Itoa(f.ZombieProcessCount),
		strconv.Itoa(f.RootProcessCount),
		strconv.FormatFloat(f.AvgProcessAge, 'f', 2, 64),
		strconv.Itoa(f.ProcessWithManyThreads),
		strconv.Itoa(f.SuspiciousProcessNames),
		strconv.Itoa(f.TotalFileDescriptors),
		strconv.FormatFloat(f.SystemCPU, 'f', 6, 64),
		strconv.FormatFloat(f.AvgCoreCPU, 'f', 6, 64),
		strconv.FormatFloat(f.SystemMemoryPercent, 'f', 6, 64),
		strconv.FormatUint(f.SystemMemoryUsed, 10),
		strconv.FormatUint(f.SystemMemoryAvail, 10),
		strconv.FormatUint(f.SystemMemoryTotal, 10),
		strconv.FormatFloat(f.SwapUsedPercent, 'f', 6, 64),
		strconv.FormatUint(f.SwapTotal, 10),
		strconv.FormatUint(f.SwapUsed, 10),
		strconv.FormatUint(f.DiskReadBytes, 10),
		strconv.FormatUint(f.DiskWriteBytes, 10),
		strconv.FormatFloat(f.DiskReadRate, 'f', 6, 64),
		strconv.FormatFloat(f.DiskWriteRate, 'f', 6, 64),
		strconv.FormatUint(f.DiskReadCount, 10),
		strconv.FormatUint(f.DiskWriteCount, 10),
		strconv.FormatFloat(f.DiskIORate, 'f', 6, 64),
		strconv.Itoa(f.LoggedInUsers),
		strconv.FormatUint(f.SystemUptime, 10),
		strconv.FormatUint(f.SystemBootTime, 10),
		strconv.FormatFloat(f.CPUUsageSpike, 'f', 6, 64),
		strconv.FormatFloat(f.MemoryUsageSpike, 'f', 6, 64),
		// Network-based features
		strconv.Itoa(f.TotalConnections),
		strconv.Itoa(f.TCPConnections),
		strconv.Itoa(f.UDPConnections),
		strconv.Itoa(f.EstablishedConnections),
		strconv.Itoa(f.ListenConnections),
		strconv.Itoa(f.TimeWaitConnections),
		strconv.Itoa(f.SynSentConnections),
		strconv.Itoa(f.SynRecvConnections),
		strconv.Itoa(f.CloseWaitConnections),
		strconv.Itoa(f.FinWaitConnections),
		strconv.FormatUint(f.NetBytesSent, 10),
		strconv.FormatUint(f.NetBytesRecv, 10),
		strconv.FormatUint(f.NetPacketsSent, 10),
		strconv.FormatUint(f.NetPacketsRecv, 10),
		strconv.FormatUint(f.NetErrorsIn, 10),
		strconv.FormatUint(f.NetErrorsOut, 10),
		strconv.FormatUint(f.NetDropsIn, 10),
		strconv.FormatUint(f.NetDropsOut, 10),
		strconv.FormatFloat(f.NetSendRate, 'f', 6, 64),
		strconv.FormatFloat(f.NetRecvRate, 'f', 6, 64),
		strconv.FormatFloat(f.NetPacketSendRate, 'f', 6, 64),
		strconv.FormatFloat(f.NetPacketRecvRate, 'f', 6, 64),
		strconv.Itoa(f.UniqueSourceIPs),
		strconv.Itoa(f.UniqueDestIPs),
		strconv.Itoa(f.NewSourceIPs),
		strconv.Itoa(f.PrivateIPConnections),
		strconv.Itoa(f.PublicIPConnections),
		strconv.Itoa(f.TopSourceIPCount),
		f.TopSourceIP,
		strconv.Itoa(f.UniqueLocalPorts),
		strconv.Itoa(f.UniqueRemotePorts),
		strconv.Itoa(f.WellKnownPortConns),
		strconv.Itoa(f.EphemeralPortConns),
		strconv.Itoa(f.SuspiciousPortConns),
		strconv.Itoa(f.PortScanIndicators),
		strconv.FormatFloat(f.TCPRatio, 'f', 6, 64),
		strconv.FormatFloat(f.UDPRatio, 'f', 6, 64),
		strconv.FormatFloat(f.TCPUDPRatio, 'f', 6, 64),
		strconv.Itoa(f.ProcessesWithNetActivity),
		strconv.FormatFloat(f.AvgConnectionsPerProcess, 'f', 6, 64),
		strconv.Itoa(f.ConnectionCreationRate),
		strconv.Itoa(f.ConnectionTerminationRate),
		strconv.Itoa(f.ExternalIPCount),
		strconv.Itoa(f.LoopbackConnections),
		strconv.Itoa(f.BroadcastConnections),
		strconv.FormatFloat(f.ConnectionChurnRate, 'f', 6, 64),
		strconv.FormatFloat(f.ConnectionDensity, 'f', 6, 64),
		strconv.FormatFloat(f.PortScanningScore, 'f', 6, 64),
		strconv.FormatFloat(f.DataExfiltrationScore, 'f', 6, 64),
		strconv.FormatFloat(f.BandwidthAsymmetry, 'f', 6, 64),
		strconv.FormatFloat(f.C2CommunicationScore, 'f', 6, 64),
		strconv.FormatFloat(f.FailedConnectionRatio, 'f', 6, 64),
	}
}

// writeToCSV appends a feature vector to the CSV file
func writeToCSV(filename string, features *CompleteFeatureVector, isNewFile bool) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error opening CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write headers if it's a new file
	if isNewFile {
		if err := writer.Write(getCSVHeaders()); err != nil {
			return fmt.Errorf("error writing CSV headers: %w", err)
		}
	}

	// Write the data row
	if err := writer.Write(featureToCSVRow(features)); err != nil {
		return fmt.Errorf("error writing CSV row: %w", err)
	}

	return nil
}

func printCompleteFeatureSummary(f *CompleteFeatureVector) {
	fmt.Printf("\n========== Feature Collection at %s ==========\n",
		f.Timestamp.Format("2006-01-02 15:04:05"))

	fmt.Println("\n--- HOST-BASED FEATURES ---")
	fmt.Printf("Processes: %d (Created: %d, Terminated: %d)\n",
		f.ProcessCount, f.ProcessCreationRate, f.ProcessTermRate)
	fmt.Printf("System CPU: %.2f%% (Avg Core: %.2f%%) | Spike: %.2f%%\n",
		f.SystemCPU, f.AvgCoreCPU, f.CPUUsageSpike)
	fmt.Printf("Memory: %.2f%% (Used: %d MB) | Spike: %.2f%%\n",
		f.SystemMemoryPercent, f.SystemMemoryUsed/(1024*1024), f.MemoryUsageSpike)
	fmt.Printf("Swap: %.2f%% (Used: %d MB / Total: %d MB)\n",
		f.SwapUsedPercent, f.SwapUsed/(1024*1024), f.SwapTotal/(1024*1024))
	fmt.Printf("High CPU/Mem Procs: %d/%d | Zombies: %d | Root: %d\n",
		f.HighCPUProcessCount, f.HighMemProcessCount, f.ZombieProcessCount, f.RootProcessCount)
	fmt.Printf("Suspicious Processes: %d | Many Threads: %d\n",
		f.SuspiciousProcessNames, f.ProcessWithManyThreads)
	fmt.Printf("Avg Process: CPU=%.2f%% Mem=%.2f%% Age=%.0fs\n",
		f.AvgProcessCPU, f.AvgProcessMemory, f.AvgProcessAge)
	fmt.Printf("Disk I/O: Read %.2f KB/s | Write %.2f KB/s | Total: %.2f KB/s\n",
		f.DiskReadRate/1024, f.DiskWriteRate/1024, f.DiskIORate/1024)
	fmt.Printf("Users: %d | Uptime: %d seconds\n",
		f.LoggedInUsers, f.SystemUptime)

	fmt.Println("\n--- NETWORK-BASED FEATURES ---")
	fmt.Printf("Total Connections: %d (TCP: %d, UDP: %d)\n",
		f.TotalConnections, f.TCPConnections, f.UDPConnections)
	fmt.Printf("States: ESTABLISHED=%d, LISTEN=%d, TIME_WAIT=%d, SYN_SENT=%d\n",
		f.EstablishedConnections, f.ListenConnections, f.TimeWaitConnections, f.SynSentConnections)
	fmt.Printf("Unique IPs: Source=%d, Dest=%d | New Sources: %d\n",
		f.UniqueSourceIPs, f.UniqueDestIPs, f.NewSourceIPs)
	fmt.Printf("IP Types: Private=%d, Public=%d, Loopback=%d\n",
		f.PrivateIPConnections, f.PublicIPConnections, f.LoopbackConnections)
	fmt.Printf("Top Source IP: %s (%d connections)\n",
		f.TopSourceIP, f.TopSourceIPCount)
	fmt.Printf("Ports: Local=%d, Remote=%d | Well-known=%d, Suspicious=%d\n",
		f.UniqueLocalPorts, f.UniqueRemotePorts, f.WellKnownPortConns, f.SuspiciousPortConns)
	fmt.Printf("Network I/O: Send %.2f KB/s | Recv %.2f KB/s\n",
		f.NetSendRate/1024, f.NetRecvRate/1024)
	fmt.Printf("Packets: Send %.2f pps | Recv %.2f pps\n",
		f.NetPacketSendRate, f.NetPacketRecvRate)
	fmt.Printf("Errors/Drops: In=%d/%d, Out=%d/%d\n",
		f.NetErrorsIn, f.NetDropsIn, f.NetErrorsOut, f.NetDropsOut)
	fmt.Printf("Connection Churn: Created=%d, Terminated=%d, Rate=%.3f\n",
		f.ConnectionCreationRate, f.ConnectionTerminationRate, f.ConnectionChurnRate)
	fmt.Printf("Processes with Network Activity: %d (Avg %.2f conns/process)\n",
		f.ProcessesWithNetActivity, f.AvgConnectionsPerProcess)

	fmt.Println("\n--- DERIVED SECURITY SCORES ---")
	fmt.Printf("Port Scan Indicators: %d (Score: %.2f)\n",
		f.PortScanIndicators, f.PortScanningScore)
	fmt.Printf("Data Exfiltration Score: %.2f\n", f.DataExfiltrationScore)
	fmt.Printf("C2 Communication Score: %.2f\n", f.C2CommunicationScore)
	fmt.Printf("Bandwidth Asymmetry: %.3f\n", f.BandwidthAsymmetry)
	fmt.Printf("Connection Density: %.2f connections/process\n", f.ConnectionDensity)
	fmt.Printf("Failed Connection Ratio: %.3f\n", f.FailedConnectionRatio)

	fmt.Println("\n" + strings.Repeat("=", 70))
}

func main() {
	csvFilename := "reading.csv"
	state := NewCompleteCollectorState()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	fmt.Println("Starting Complete Host + Network-Based IDS Feature Collection")
	fmt.Println("Collection interval: 10 seconds")
	fmt.Println("Output file: " + csvFilename)
	fmt.Println("Total metrics: 87")
	fmt.Println(strings.Repeat("=", 70))

	// Check if file exists to determine if we need to write headers
	_, err := os.Stat(csvFilename)
	isNewFile := os.IsNotExist(err)

	// Initial collection
	features, err := CollectCompleteFeatures(state)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		printCompleteFeatureSummary(features)

		// Write to CSV
		if err := writeToCSV(csvFilename, features, isNewFile); err != nil {
			fmt.Printf("Error writing to CSV: %v\n", err)
		} else {
			fmt.Printf("✓ Data saved to %s\n", csvFilename)
		}
		isNewFile = false
	}

	for range ticker.C {
		features, err := CollectCompleteFeatures(state)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		printCompleteFeatureSummary(features)

		// Write to CSV
		if err := writeToCSV(csvFilename, features, false); err != nil {
			fmt.Printf("Error writing to CSV: %v\n", err)
		} else {
			fmt.Printf("✓ Data saved to %s\n", csvFilename)
		}
	}
}
