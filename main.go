package main

import (
	"fmt"
	"log"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
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
}
