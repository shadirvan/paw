package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var serverIP = flag.String("host", "", "IP address to send the knocks")
var filePath = flag.String("file", "../secrets.txt", "Path to the file containing ports") // Default to parent directory

const timeout = 2 * time.Second

func readPorts(filePath string) ([]int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", filePath, err)
	}
	defer file.Close()

	var ports []int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		port, err := strconv.Atoi(line)
		if err != nil {
			return nil, fmt.Errorf("invalid port value %q in file %s: %v", line, filePath, err)
		}
		ports = append(ports, port)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", filePath, err)
	}

	return ports, nil
}

func sendKnock(port int) error {
	address := fmt.Sprintf("%s:%d", *serverIP, port)
	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		return fmt.Errorf("failed to send knock to %s: %v", address, err)
	}
	defer conn.Close()

	// Send an empty packet as the knock
	_, err = conn.Write([]byte{})
	if err != nil {
		return fmt.Errorf("failed to send packet to %s: %v", address, err)
	}

	fmt.Printf("Knocked on port %d\n", port)
	return nil
}

func main() {
	flag.Parse()

	// Check if the host is provided
	if *serverIP == "" {
		fmt.Println("Error: --host argument is required")
		flag.Usage()
		os.Exit(1)
	}

	// Read ports from the file
	ports, err := readPorts(*filePath)
	if err != nil {
		fmt.Printf("Error reading ports from file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Sending knocks to server: %s\n", *serverIP)
	for _, port := range ports {
		err := sendKnock(port)
		if err != nil {
			fmt.Printf("Error knocking port %d: %v\n", port, err)
			continue
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Println("Port knocking sequence completed!")
}
