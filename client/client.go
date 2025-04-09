package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var serverIP = flag.String("host", "", "IP address of the server")
var filePath = flag.String("file", "../secrets.txt", "Path to the file containing ports")

const timeout = 2 * time.Second
const secretKey = "my-shared-secret" // Shared secret for HMAC

// Read ports from the file
func readPorts(filePath string) ([]int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var ports []int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		port, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
		if err != nil {
			return nil, fmt.Errorf("invalid port value: %v", err)
		}
		ports = append(ports, port)
	}
	return ports, scanner.Err()
}

// Generate HMAC for message
func generateHMAC(message string) string {
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// Send a knock with port, timestamp, and HMAC
func sendKnock(port int) error {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	message := fmt.Sprintf("%d:%s", port, timestamp)
	hmacValue := generateHMAC(message)
	packet := fmt.Sprintf("%s:%s", message, hmacValue)

	address := fmt.Sprintf("%s:%d", *serverIP, port)
	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		return fmt.Errorf("failed to send knock to %s: %v", address, err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(packet))
	if err != nil {
		return fmt.Errorf("failed to send packet to %s: %v", address, err)
	}

	fmt.Printf("✅ Knocked on port %d with HMAC\n", port)
	return nil
}

func main() {
	flag.Parse()

	if *serverIP == "" {
		fmt.Println("❌ Error: --host argument is required")
		os.Exit(1)
	}

	ports, err := readPorts(*filePath)
	if err != nil {
		fmt.Printf("❌ Error reading ports from file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🚀 Sending knocks to server: %s\n", *serverIP)
	for _, port := range ports {
		err := sendKnock(port)
		if err != nil {
			fmt.Printf("❌ Error knocking port %d: %v\n", port, err)
			continue
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Println("🎉 Port knocking sequence completed!")
}
