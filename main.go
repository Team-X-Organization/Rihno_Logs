package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

func main() {
	// cpu percentage
	cpuPercentAvg, err := cpu.Percent(1*time.Second, false)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(cpuPercentAvg)

	cpuPercentMulti, err := cpu.Percent(1*time.Second, true)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(cpuPercentMulti)

	// cpu temperature
	// SensorsTemperatures returns a slice of all detected sensors
	// (CPU, GPU, Battery, etc. depending on the OS)
	sensorStats, err := host.SensorsTemperatures()
	if err != nil {
		log.Fatalf("Failed to get sensor data: %v", err)
	}

	if len(sensorStats) == 0 {
		fmt.Println("No temperature sensors detected.")
		return
	}

	fmt.Println("Detected Temperatures:")
	for _, sensor := range sensorStats {
		fmt.Printf("Sensor: %-20s | Temp: %.2f°C\n", sensor.SensorKey, sensor.Temperature)
	}

	var memStats runtime.MemStats

	// Update memStats.
	runtime.ReadMemStats(&memStats)

	// Print some relevant statistics.
	fmt.Printf("Allocated memory: %d bytes\n", memStats.Alloc)
	fmt.Printf("Total allocated memory: %d bytes\n", memStats.TotalAlloc)
	fmt.Printf("Heap memory obtained from system: %d bytes\n", memStats.HeapSys)
	fmt.Printf("Heap objects: %d\n", memStats.HeapObjects)

	// memory stats
	v, err := mem.VirtualMemory()
	if err != nil {
		log.Fatalf("Failed to get memory info: %v", err)
		os.Exit(1)
	}
	fmt.Printf("Total memory: %d bytes\n", v.Total)
	fmt.Printf("Used memory: %d bytes\n", v.Used)
	fmt.Printf("Free memory: %d bytes\n", v.Free)

	checkIntegrity(CriticalFile)
}

const (
	CriticalFile  = "/etc/passwd"
	CheckInterval = 5 * time.Second
)

var fileBaseline string

// 1. File Integrity Monitor (SHA-256)
func checkIntegrity(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	hash := sha256.New()
	io.Copy(hash, file)
	currentHash := hex.EncodeToString(hash.Sum(nil))

	if fileBaseline == "" {
		fileBaseline = currentHash
		fmt.Printf("[INIT] Baseline established for %s\n", path)
	} else if currentHash != fileBaseline {
		fmt.Printf("[ALERT] FILE MALWARE: %s modified at %s\n", path, time.Now().Format(time.RFC850))
		fileBaseline = currentHash // Update to prevent alert fatigue
	}
}
