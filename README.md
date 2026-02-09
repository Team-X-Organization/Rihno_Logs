## Complete Host + Network-Based IDS Features for 10-Second Collection

| **Feature Name** | **Go Function/Method** | **Data Type** | **CPU Impact** | **IDS Value** | **Notes** |
|------------------|------------------------|---------------|----------------|---------------|-----------|
| **HOST-BASED: Process Metrics** |
| Total process count | `len(process.Processes())` | Integer | Very Low | High | Quick count operation |
| Process CPU usage | `process.CPUPercent()` | Float64 (per process) | Low | High | Lightweight, per-process |
| Process memory percent | `process.MemoryPercent()` | Float32 (per process) | Low | High | Lightweight, per-process |
| Process memory info (RSS, VMS) | `process.MemoryInfo()` | Struct | Low | High | Detailed memory metrics |
| Process thread count | `process.NumThreads()` | Int32 (per process) | Low | Medium | Detects thread injection |
| Process status | `process.Status()` | String | Very Low | Medium | Running, sleeping, zombie |
| Process name | `process.Name()` | String | Very Low | High | Process identification |
| Process PID | `process.Pid` | Int32 | Very Low | High | Process tracking |
| Process parent PID | `process.Ppid()` | Int32 | Very Low | High | Parent-child relationships |
| Process owner/username | `process.Username()` | String | Low | High | Privilege context |
| Process command line | `process.Cmdline()` | String | Low | High | Execution parameters |
| Process creation time | `process.CreateTime()` | Int64 (timestamp) | Very Low | High | Process age tracking |
| Number of file descriptors | `process.NumFDs()` | Int32 | Low | Medium | Linux/macOS only |
| **HOST-BASED: System Resources** |
| System CPU usage | `cpu.Percent(1*time.Second, false)` | Float64 | Very Low | Medium | Overall CPU load |
| Per-core CPU usage | `cpu.Percent(1*time.Second, true)` | []Float64 | Low | Low | Individual core usage |
| Total memory usage | `mem.VirtualMemory()` | Struct | Very Low | Medium | RAM statistics |
| Memory used percent | `mem.VirtualMemory().UsedPercent` | Float64 | Very Low | Medium | Memory pressure |
| Available memory | `mem.VirtualMemory().Available` | Uint64 | Very Low | Medium | Free RAM |
| Swap usage | `mem.SwapMemory()` | Struct | Very Low | Low | Swap statistics |
| Swap used percent | `mem.SwapMemory().UsedPercent` | Float64 | Very Low | Low | Swap pressure |
| **HOST-BASED: Disk I/O** |
| Disk I/O counters | `disk.IOCounters()` | Map | Low | Medium | Read/write operations |
| Disk read count | `disk.IOCounters()[device].ReadCount` | Uint64 | Low | Medium | Total reads |
| Disk write count | `disk.IOCounters()[device].WriteCount` | Uint64 | Low | Medium | Total writes |
| Disk read bytes | `disk.IOCounters()[device].ReadBytes` | Uint64 | Low | Medium | Data read volume |
| Disk write bytes | `disk.IOCounters()[device].WriteBytes` | Uint64 | Low | Medium | Data write volume |
| **HOST-BASED: User Sessions** |
| Logged in users | `host.Users()` | []Struct | Low | High | Current sessions |
| User terminal | `host.Users()[].Terminal` | String | Low | Medium | Session terminal |
| User host | `host.Users()[].Host` | String | Low | Medium | Remote host if SSH |
| User session start time | `host.Users()[].Started` | Int64 | Low | Medium | Login timestamp |
| **HOST-BASED: System Info** |
| System boot time | `host.BootTime()` | Uint64 | Very Low | Low | Last reboot |
| System uptime | `host.Uptime()` | Uint64 | Very Low | Low | Seconds since boot |
| **NETWORK-BASED: Connection Statistics** |
| Total active connections | `len(net.Connections("all"))` | Integer | Medium | High | All connection states |
| TCP connections | `len(net.Connections("tcp"))` | Integer | Medium | High | TCP only |
| UDP connections | `len(net.Connections("udp"))` | Integer | Medium | Medium | UDP only |
| ESTABLISHED connections | Count by state | Integer | Low | High | Active connections |
| LISTEN connections | Count by state | Integer | Low | High | Listening ports |
| TIME_WAIT connections | Count by state | Integer | Low | Medium | Closing connections |
| SYN_SENT connections | Count by state | Integer | Low | High | Outbound connection attempts |
| SYN_RECV connections | Count by state | Integer | Low | High | Inbound connection attempts |
| CLOSE_WAIT connections | Count by state | Integer | Low | Medium | Half-closed connections |
| FIN_WAIT connections | Count by state | Integer | Low | Medium | Terminating connections |
| **NETWORK-BASED: Interface Statistics** |
| Network bytes sent | `net.IOCounters()[].BytesSent` | Uint64 | Low | High | Total outbound bytes |
| Network bytes received | `net.IOCounters()[].BytesRecv` | Uint64 | Low | High | Total inbound bytes |
| Network packets sent | `net.IOCounters()[].PacketsSent` | Uint64 | Low | Medium | Total outbound packets |
| Network packets received | `net.IOCounters()[].PacketsRecv` | Uint64 | Low | Medium | Total inbound packets |
| Network errors in | `net.IOCounters()[].Errin` | Uint64 | Low | Medium | Inbound errors |
| Network errors out | `net.IOCounters()[].Errout` | Uint64 | Low | Medium | Outbound errors |
| Network drops in | `net.IOCounters()[].Dropin` | Uint64 | Low | Medium | Inbound packet drops |
| Network drops out | `net.IOCounters()[].Dropout` | Uint64 | Low | Medium | Outbound packet drops |
| **NETWORK-BASED: IP Address Features** |
| Unique source IPs | Count unique from `net.Connections()` | Integer | Medium | High | Distinct remote hosts |
| Unique destination IPs | Count unique local IPs | Integer | Medium | Medium | Distinct local endpoints |
| Connections per source IP | Group by remote IP | Map[string]int | Medium | High | Detect port scanning |
| Connections per dest IP | Group by local IP | Map[string]int | Medium | Medium | Internal service usage |
| New source IPs | Compare with previous | Integer | Medium | High | New external hosts |
| Private IP connections | Count RFC1918 IPs | Integer | Low | Medium | Internal network traffic |
| Public IP connections | Count public IPs | Integer | Low | High | External connections |
| Top source IP count | Max connections from single IP | Integer | Low | High | Potential DDoS source |
| **NETWORK-BASED: Port Features** |
| Unique local ports | Count distinct local ports | Integer | Medium | Medium | Services in use |
| Unique remote ports | Count distinct remote ports | Integer | Medium | High | Service diversity |
| Connections per local port | Group by local port | Map[int]int | Medium | High | Service load |
| Connections per remote port | Group by remote port | Map[int]int | Medium | High | Outbound service usage |
| Well-known port connections | Count ports < 1024 | Integer | Low | Medium | Standard services |
| Ephemeral port connections | Count ports > 32768 | Integer | Low | Low | Client connections |
| Suspicious port connections | Known malware ports | Integer | Medium | High | C2 communication |
| Port scan indicators | Many ports, same IP | Integer | Medium | High | Scanning detection |
| **NETWORK-BASED: Protocol Distribution** |
| TCP connection ratio | TCP / Total | Float64 | Low | Low | Protocol mix |
| UDP connection ratio | UDP / Total | Float64 | Low | Low | Protocol mix |
| TCP/UDP ratio | TCP count / UDP count | Float64 | Low | Medium | Traffic pattern |
| **NETWORK-BASED: Per-Connection Features** |
| Connection local address | `conn.Laddr.IP` | String | Low | High | Local endpoint |
| Connection local port | `conn.Laddr.Port` | Uint32 | Low | High | Local service |
| Connection remote address | `conn.Raddr.IP` | String | Low | High | Remote endpoint |
| Connection remote port | `conn.Raddr.Port` | Uint32 | Low | High | Remote service |
| Connection state | `conn.Status` | String | Low | High | Connection state |
| Connection PID | `conn.Pid` | Int32 | Low | High | Owning process |
| Connection file descriptor | `conn.Fd` | Uint32 | Low | Low | Socket descriptor |
| **NETWORK-BASED: Process Network Activity** |
| Process connection count | `len(process.Connections())` | Integer | Medium | High | Per-process connections |
| Process listening ports | Filter LISTEN state | []Integer | Medium | High | Services per process |
| Process remote IPs | Unique remote IPs | []String | Medium | High | External communication |
| Processes with network activity | Count processes with conns | Integer | Low | High | Network-active processes |
| **NETWORK-BASED: Traffic Rate Features** |
| Bytes sent rate | (Current - Previous) / 10s | Float64 | Very Low | High | Outbound bandwidth |
| Bytes received rate | (Current - Previous) / 10s | Float64 | Very Low | High | Inbound bandwidth |
| Packets sent rate | (Current - Previous) / 10s | Float64 | Very Low | Medium | Outbound packet rate |
| Packets received rate | (Current - Previous) / 10s | Float64 | Very Low | Medium | Inbound packet rate |
| Connection creation rate | New connections / 10s | Integer | Medium | High | Connection churn |
| Connection termination rate | Closed connections / 10s | Integer | Medium | Medium | Connection lifecycle |
| **NETWORK-BASED: Geographic/External** |
| External IP count | Public IPs only | Integer | Low | High | External exposure |
| Loopback connections | 127.0.0.1 connections | Integer | Low | Low | Local services |
| Broadcast connections | 255.255.255.255 | Integer | Low | Medium | Broadcast traffic |
| **DERIVED: Host-Based Features** |
| Process creation rate | Count new PIDs vs last poll | Integer | Low | High | New processes per 10s |
| Process termination rate | Count disappeared PIDs | Integer | Low | High | Killed processes per 10s |
| CPU usage spike | Current - Previous | Float64 | Very Low | Medium | Sudden CPU changes |
| Memory usage spike | Current - Previous | Float64 | Very Low | Medium | Sudden memory changes |
| Disk I/O rate | (Current - Previous) / 10s | Float64 | Very Low | Medium | Disk activity rate |
| High CPU processes count | Count processes > threshold | Integer | Low | High | Resource hogs |
| High memory processes count | Count processes > threshold | Integer | Low | High | Memory hogs |
| Suspicious process names | Pattern matching | Integer | Low | High | Known malware names |
| Process with many threads | Count processes with threads > N | Integer | Low | Medium | Potential injection |
| **DERIVED: Network-Based Features** |
| Connection churn rate | (Created + Terminated) / Total | Float64 | Low | High | Connection volatility |
| Connection density | Connections per active process | Float64 | Low | Medium | Network intensity |
| Port scanning score | Heuristic calculation | Float64 | Medium | High | Scan detection |
| Data exfiltration score | Large outbound, little inbound | Float64 | Medium | High | Data theft detection |
| C2 communication score | Regular intervals, small packets | Float64 | Medium | High | Botnet detection |
| Bandwidth asymmetry | |Sent - Recv| / Total | Float64 | Low | Medium | Traffic balance |
| Failed connection ratio | Failed / Total attempts | Float64 | Medium | High | Connection issues |

## Complete Go Implementation with Network Features

```go
package main

import (
    "fmt"
    "net"
    "strings"
    "time"
    "github.com/shirou/gopsutil/v3/process"
    "github.com/shirou/gopsutil/v3/cpu"
    "github.com/shirou/gopsutil/v3/mem"
    "github.com/shirou/gopsutil/v3/disk"
    psnet "github.com/shirou/gopsutil/v3/net"
    "github.com/shirou/gopsutil/v3/host"
)

// CompleteFeatureVector with both host and network features
type CompleteFeatureVector struct {
    Timestamp time.Time `json:"timestamp"`
    
    // ========== HOST-BASED FEATURES ==========
    // Process Features
    ProcessCount         int     `json:"process_count"`
    ProcessCreationRate  int     `json:"process_creation_rate"`
    ProcessTermRate      int     `json:"process_termination_rate"`
    HighCPUProcessCount  int     `json:"high_cpu_process_count"`
    HighMemProcessCount  int     `json:"high_mem_process_count"`
    AvgProcessCPU        float64 `json:"avg_process_cpu"`
    AvgProcessMemory     float64 `json:"avg_process_memory"`
    TotalThreads         int     `json:"total_threads"`
    ZombieProcessCount   int     `json:"zombie_process_count"`
    RootProcessCount     int     `json:"root_process_count"`
    
    // System Resources
    SystemCPU            float64 `json:"system_cpu"`
    SystemMemoryPercent  float64 `json:"system_memory_percent"`
    SystemMemoryUsed     uint64  `json:"system_memory_used"`
    SystemMemoryAvail    uint64  `json:"system_memory_available"`
    SwapUsedPercent      float64 `json:"swap_used_percent"`
    
    // Disk I/O
    DiskReadBytes   uint64  `json:"disk_read_bytes"`
    DiskWriteBytes  uint64  `json:"disk_write_bytes"`
    DiskReadRate    float64 `json:"disk_read_rate"`
    DiskWriteRate   float64 `json:"disk_write_rate"`
    DiskReadCount   uint64  `json:"disk_read_count"`
    DiskWriteCount  uint64  `json:"disk_write_count"`
    
    // User Sessions
    LoggedInUsers int    `json:"logged_in_users"`
    SystemUptime  uint64 `json:"system_uptime"`
    
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
    NetBytesSent     uint64  `json:"net_bytes_sent"`
    NetBytesRecv     uint64  `json:"net_bytes_recv"`
    NetPacketsSent   uint64  `json:"net_packets_sent"`
    NetPacketsRecv   uint64  `json:"net_packets_recv"`
    NetErrorsIn      uint64  `json:"net_errors_in"`
    NetErrorsOut     uint64  `json:"net_errors_out"`
    NetDropsIn       uint64  `json:"net_drops_in"`
    NetDropsOut      uint64  `json:"net_drops_out"`
    NetSendRate      float64 `json:"net_send_rate"`
    NetRecvRate      float64 `json:"net_recv_rate"`
    NetPacketSendRate float64 `json:"net_packet_send_rate"`
    NetPacketRecvRate float64 `json:"net_packet_recv_rate"`
    
    // IP Address Features
    UniqueSourceIPs        int            `json:"unique_source_ips"`
    UniqueDestIPs          int            `json:"unique_dest_ips"`
    NewSourceIPs           int            `json:"new_source_ips"`
    PrivateIPConnections   int            `json:"private_ip_connections"`
    PublicIPConnections    int            `json:"public_ip_connections"`
    TopSourceIPCount       int            `json:"top_source_ip_count"`
    TopSourceIP            string         `json:"top_source_ip"`
    ConnectionsPerSourceIP map[string]int `json:"connections_per_source_ip"`
    
    // Port Features
    UniqueLocalPorts       int            `json:"unique_local_ports"`
    UniqueRemotePorts      int            `json:"unique_remote_ports"`
    WellKnownPortConns     int            `json:"well_known_port_connections"`
    EphemeralPortConns     int            `json:"ephemeral_port_connections"`
    SuspiciousPortConns    int            `json:"suspicious_port_connections"`
    PortScanIndicators     int            `json:"port_scan_indicators"`
    ConnectionsPerLocalPort map[uint32]int `json:"connections_per_local_port"`
    ConnectionsPerRemotePort map[uint32]int `json:"connections_per_remote_port"`
    
    // Protocol Distribution
    TCPRatio    float64 `json:"tcp_ratio"`
    UDPRatio    float64 `json:"udp_ratio"`
    TCPUDPRatio float64 `json:"tcp_udp_ratio"`
    
    // Process Network Activity
    ProcessesWithNetActivity int `json:"processes_with_net_activity"`
    
    // Traffic Rates
    ConnectionCreationRate   int     `json:"connection_creation_rate"`
    ConnectionTerminationRate int     `json:"connection_termination_rate"`
    
    // Geographic/External
    ExternalIPCount      int `json:"external_ip_count"`
    LoopbackConnections  int `json:"loopback_connections"`
    BroadcastConnections int `json:"broadcast_connections"`
    
    // Derived Network Features
    ConnectionChurnRate    float64 `json:"connection_churn_rate"`
    ConnectionDensity      float64 `json:"connection_density"`
    PortScanningScore      float64 `json:"port_scanning_score"`
    DataExfiltrationScore  float64 `json:"data_exfiltration_score"`
    BandwidthAsymmetry     float64 `json:"bandwidth_asymmetry"`
    
    // Detailed Connection Data
    ActiveConnections []ConnectionDetail `json:"active_connections"`
    TopProcessesByConns []ProcessNetworkMetric `json:"top_processes_by_connections"`
}

type ConnectionDetail struct {
    LocalIP    string `json:"local_ip"`
    LocalPort  uint32 `json:"local_port"`
    RemoteIP   string `json:"remote_ip"`
    RemotePort uint32 `json:"remote_port"`
    State      string `json:"state"`
    PID        int32  `json:"pid"`
    Protocol   string `json:"protocol"`
}

type ProcessNetworkMetric struct {
    PID              int32    `json:"pid"`
    Name             string   `json:"name"`
    ConnectionCount  int      `json:"connection_count"`
    ListeningPorts   []uint32 `json:"listening_ports"`
    RemoteIPs        []string `json:"remote_ips"`
    UniqueRemoteIPs  int      `json:"unique_remote_ips"`
}

// Collector state for tracking changes
type CompleteCollectorState struct {
    // Host state
    LastPIDs          map[int32]bool
    LastDiskReadBytes uint64
    LastDiskWriteBytes uint64
    
    // Network state
    LastNetBytesSent   uint64
    LastNetBytesRecv   uint64
    LastNetPacketsSent uint64
    LastNetPacketsRecv uint64
    LastConnections    map[string]bool // connection key
    LastSourceIPs      map[string]bool
    
    LastTimestamp time.Time
}

func NewCompleteCollectorState() *CompleteCollectorState {
    return &CompleteCollectorState{
        LastPIDs:        make(map[int32]bool),
        LastConnections: make(map[string]bool),
        LastSourceIPs:   make(map[string]bool),
        LastTimestamp:   time.Now(),
    }
}

// List of suspicious ports commonly used by malware
var suspiciousPorts = map[uint32]bool{
    1337: true, 31337: true, // Elite/leet hacker ports
    4444: true, 5555: true,  // Metasploit default
    6667: true, 6668: true, 6669: true, // IRC (potential botnet C2)
    12345: true, 54321: true, // NetBus trojan
    1234: true,  // SubSeven trojan
    9999: true,  // Various trojans
    8866: true, 8888: true, // Various backdoors
}

func CollectCompleteFeatures(state *CompleteCollectorState) (*CompleteFeatureVector, error) {
    features := &CompleteFeatureVector{
        Timestamp: time.Now(),
        ConnectionsPerSourceIP: make(map[string]int),
        ConnectionsPerLocalPort: make(map[uint32]int),
        ConnectionsPerRemotePort: make(map[uint32]int),
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
    calculateDerivedFeatures(features)
    
    state.LastTimestamp = features.Timestamp
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
    
    var totalCPU, totalMemory float64
    var cpuCount, memCount int
    
    for _, p := range processes {
        pid := p.Pid
        currentPIDs[pid] = true
        
        cpuPercent, err := p.CPUPercent()
        if err == nil {
            totalCPU += cpuPercent
            cpuCount++
            if cpuPercent > 50.0 {
                features.HighCPUProcessCount++
            }
        }
        
        memPercent, err := p.MemoryPercent()
        if err == nil {
            totalMemory += float64(memPercent)
            memCount++
            if memPercent > 10.0 {
                features.HighMemProcessCount++
            }
        }
        
        numThreads, err := p.NumThreads()
        if err == nil {
            features.TotalThreads += int(numThreads)
        }
        
        status, err := p.Status()
        if err == nil && len(status) > 0 {
            if status[0] == "zombie" || status[0] == "Z" {
                features.ZombieProcessCount++
            }
        }
        
        username, err := p.Username()
        if err == nil && (username == "root" || username == "SYSTEM" || username == "NT AUTHORITY\\SYSTEM") {
            features.RootProcessCount++
        }
    }
    
    if cpuCount > 0 {
        features.AvgProcessCPU = totalCPU / float64(cpuCount)
    }
    if memCount > 0 {
        features.AvgProcessMemory = totalMemory / float64(memCount)
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
    
    // System resources
    cpuPercent, err := cpu.Percent(time.Second, false)
    if err == nil && len(cpuPercent) > 0 {
        features.SystemCPU = cpuPercent[0]
    }
    
    memInfo, err := mem.VirtualMemory()
    if err == nil {
        features.SystemMemoryPercent = memInfo.UsedPercent
        features.SystemMemoryUsed = memInfo.Used
        features.SystemMemoryAvail = memInfo.Available
    }
    
    swapInfo, err := mem.SwapMemory()
    if err == nil {
        features.SwapUsedPercent = swapInfo.UsedPercent
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
        
        state.LastDiskReadBytes = totalReadBytes
        state.LastDiskWriteBytes = totalWriteBytes
    }
    
    // User sessions
    users, err := host.Users()
    if err == nil {
        features.LoggedInUsers = len(users)
    }
    
    uptime, err := host.Uptime()
    if err == nil {
        features.SystemUptime = uptime
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
    
    // Process-level network tracking
    processConnections := make(map[int32]int)
    
    for _, conn := range connections {
        // Connection states
        switch conn.Status {
        case "ESTABLISHED":
            features.EstablishedConnections++
        case "LISTEN":
            features.ListenConnections++
        case "TIME_WAIT":
            features.TimeWaitConnections++
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
            features.ConnectionsPerSourceIP[conn.Raddr.IP]++
            
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
            features.ConnectionsPerLocalPort[conn.Laddr.Port]++
            
            if conn.Laddr.Port < 1024 {
                features.WellKnownPortConns++
            } else if conn.Laddr.Port > 32768 {
                features.EphemeralPortConns++
            }
        }
        
        if conn.Raddr.Port > 0 {
            remotePorts[conn.Raddr.Port] = true
            features.ConnectionsPerRemotePort[conn.Raddr.Port]++
            
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
        
        // Store connection details (limit to top N)
        if len(features.ActiveConnections) < 100 {
            features.ActiveConnections = append(features.ActiveConnections, ConnectionDetail{
                LocalIP:    conn.Laddr.IP,
                LocalPort:  conn.Laddr.Port,
                RemoteIP:   conn.Raddr.IP,
                RemotePort: conn.Raddr.Port,
                State:      conn.Status,
                PID:        conn.Pid,
                Protocol:   getProtocolName(conn.Type),
            })
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
    for ip, count := range features.ConnectionsPerSourceIP {
        if count > maxConns {
            maxConns = count
            features.TopSourceIP = ip
        }
    }
    features.TopSourceIPCount = maxConns
    
    // Port scan detection: if an IP connects to many different ports
    for ip, ports := range portsPerIP {
        if len(ports) > 10 { // Threshold for port scanning
            features.PortScanIndicators++
            fmt.Printf("Potential port scan from %s to %d ports\n", ip, len(ports))
        }
    }
    
    // Protocol ratios
    if features.TotalConnections > 0 {
        features.TCPRatio = float64(features.TCPConnections) / float64(features.TotalConnections)
        features.UDPRatio = float64(features.UDPConnections) / float64(features.TotalConnections)
    }
    if features.UDPConnections > 0 {
        features.TCPUDPRatio = float64(features.TCPConnections) / float64(features.UDPConnections)
    }
    
    // Process network activity
    features.ProcessesWithNetActivity = len(processConnections)
    
    // Get top processes by connection count
    features.TopProcessesByConns = getTopProcessesByConnections(processConnections, 5)
    
    // Connection churn
    newConns := 0
    for conn := range currentConnections {
        if !state.LastConnections[conn] {
            newConns++
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

func calculateDerivedFeatures(features *CompleteFeatureVector) {
    // Connection churn rate
    if features.TotalConnections > 0 {
        features.ConnectionChurnRate = float64(features.ConnectionCreationRate+features.ConnectionTerminationRate) / 
            float64(features.TotalConnections)
    }
    
    // Connection density (connections per process with network activity)
    if features.ProcessesWithNetActivity > 0 {
        features.ConnectionDensity = float64(features.TotalConnections) / 
            float64(features.ProcessesWithNetActivity)
    }
    
    // Port scanning score (heuristic)
    features.PortScanningScore = float64(features.PortScanIndicators) * 10.0
    if features.SynSentConnections > 50 {
        features.PortScanningScore += float64(features.SynSentConnections) / 10.0
    }
    
    // Data exfiltration score (high outbound, low inbound)
    if features.NetRecvRate > 0 {
        outboundRatio := features.NetSendRate / (features.NetSendRate + features.NetRecvRate)
        if outboundRatio > 0.8 && features.NetSendRate > 1024*1024 { // >1MB/s outbound
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
}

func getTopProcessesByConnections(processConns map[int32]int, limit int) []ProcessNetworkMetric {
    type procConn struct {
        pid   int32
        count int
    }
    
    var procs []procConn
    for pid, count := range processConns {
        procs = append(procs, procConn{pid: pid, count: count})
    }
    
    // Simple sort
    for i := 0; i < len(procs) && i < limit; i++ {
        for j := i + 1; j < len(procs); j++ {
            if procs[j].count > procs[i].count {
                procs[i], procs[j] = procs[j], procs[i]
            }
        }
    }
    
    var result []ProcessNetworkMetric
    for i := 0; i < len(procs) && i < limit; i++ {
        p, err := process.NewProcess(procs[i].pid)
        if err != nil {
            continue
        }
        
        name, _ := p.Name()
        conns, _ := p.Connections()
        
        listeningPorts := make(map[uint32]bool)
        remoteIPsMap := make(map[string]bool)
        
        for _, conn := range conns {
            if conn.Status == "LISTEN" {
                listeningPorts[conn.Laddr.Port] = true
            }
            if conn.Raddr.IP != "" {
                remoteIPsMap[conn.Raddr.IP] = true
            }
        }
        
        var portsList []uint32
        for port := range listeningPorts {
            portsList = append(portsList, port)
        }
        
        var ipsList []string
        for ip := range remoteIPsMap {
            ipsList = append(ipsList, ip)
        }
        
        result = append(result, ProcessNetworkMetric{
            PID:             procs[i].pid,
            Name:            name,
            ConnectionCount: procs[i].count,
            ListeningPorts:  portsList,
            RemoteIPs:       ipsList,
            UniqueRemoteIPs: len(remoteIPsMap),
        })
    }
    
    return result
}

func isPrivateIP(ip string) bool {
    parsedIP := net.ParseIP(ip)
    if parsedIP == nil {
        return false
    }
    
    // Check RFC1918 private ranges
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

func getProtocolName(sockType uint32) string {
    switch sockType {
    case 1:
        return "TCP"
    case 2:
        return "UDP"
    default:
        return "OTHER"
    }
}

func printCompleteFeatureSummary(f *CompleteFeatureVector) {
    fmt.Printf("\n========== Feature Collection at %s ==========\n", 
        f.Timestamp.Format("2006-01-02 15:04:05"))
    
    fmt.Println("\n--- HOST-BASED FEATURES ---")
    fmt.Printf("Processes: %d (Created: %d, Terminated: %d)\n",
        f.ProcessCount, f.ProcessCreationRate, f.ProcessTermRate)
    fmt.Printf("System CPU: %.2f%% | Memory: %.2f%% | Swap: %.2f%%\n",
        f.SystemCPU, f.SystemMemoryPercent, f.SwapUsedPercent)
    fmt.Printf("High CPU/Mem Procs: %d/%d | Zombies: %d | Root: %d\n",
        f.HighCPUProcessCount, f.HighMemProcessCount, f.ZombieProcessCount, f.RootProcessCount)
    fmt.Printf("Disk: Read %.2f KB/s | Write %.2f KB/s\n",
        f.DiskReadRate/1024, f.DiskWriteRate/1024)
    
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
    
    fmt.Println("\n--- DERIVED SECURITY SCORES ---")
    fmt.Printf("Port Scan Indicators: %d (Score: %.2f)\n",
        f.PortScanIndicators, f.PortScanningScore)
    fmt.Printf("Data Exfiltration Score: %.2f\n", f.DataExfiltrationScore)
    fmt.Printf("Bandwidth Asymmetry: %.3f\n", f.BandwidthAsymmetry)
    fmt.Printf("Connection Density: %.2f connections/process\n", f.ConnectionDensity)
    
    if len(f.TopProcessesByConns) > 0 {
        fmt.Println("\n--- TOP PROCESSES BY NETWORK ACTIVITY ---")
        for i, proc := range f.TopProcessesByConns {
            fmt.Printf("%d. PID %d (%s): %d connections, %d unique IPs\n",
                i+1, proc.PID, proc.Name, proc.ConnectionCount, proc.UniqueRemoteIPs)
        }
    }
    
    fmt.Println("\n" + strings.Repeat("=", 70))
}

func main() {
    state := NewCompleteCollectorState()
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    fmt.Println("Starting Complete Host + Network-Based IDS Feature Collection")
    fmt.Println("Collection interval: 10 seconds")
    fmt.Println(strings.Repeat("=", 70))
    
    // Initial collection
    features, err := CollectCompleteFeatures(state)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
    } else {
        printCompleteFeatureSummary(features)
    }
    
    for range ticker.C {
        features, err := CollectCompleteFeatures(state)
        if err != nil {
            fmt.Printf("Error: %v\n", err)
            continue
        }
        
        printCompleteFeatureSummary(features)
        
        // TODO: Send features to ML model for real-time inference
        // TODO: Store in time-series database (InfluxDB, Prometheus, etc.)
        // TODO: Export to CSV/JSON for training data collection
    }
}
```

## Summary

**Total Features Collected Every 10 Seconds: 80+ features**

**Breakdown:**
- **Host-Based Features:** 25 features
- **Network-Based Features:** 55+ features
- **Derived/Calculated Features:** 10+ features

**Key Network Features Added:**
- Connection state tracking (ESTABLISHED, LISTEN, SYN_SENT, etc.)
- Per-IP tracking (incoming/outgoing)
- Port analysis (well-known, ephemeral, suspicious)
- Protocol distribution (TCP/UDP ratios)
- Traffic rates (bytes/packets per second)
- Port scanning detection
- Data exfiltration scoring
- Process-level network activity

This comprehensive feature set provides excellent coverage for both host and network-based intrusion detection!