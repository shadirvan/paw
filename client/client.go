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

const timeout = 2 * time.Second
var secretKey = "mysecretkey" // Same as the server

// Generate HMAC for a given port
func generateHMAC(port int) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(fmt.Sprintf("%d", port)))
	return hex.EncodeToString(mac.Sum(nil))
}

// Send knock to server
func sendKnock(serverIP string, port int) error {
	address := fmt.Sprintf("%s:%d", serverIP, port)
	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	hmacValue := generateHMAC(port)
	_, err = conn.Write([]byte(hmacValue))
	if err != nil {
		return fmt.Errorf("failed to send data: %v", err)
	}

	fmt.Printf("📤 Sent knock to %s on port %d with HMAC %s\n", serverIP, port, hmacValue)
	return nil
}

// Load knock sequence from a file
func loadKnockSequence(fileName string) ([]int, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var sequence []int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		port, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
		if err != nil {
			return nil, fmt.Errorf("invalid port value: %v", err)
		}
		sequence = append(sequence, port)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(sequence) == 0 {
		return nil, fmt.Errorf("knock sequence is empty")
	}

	return sequence, nil
}

func main() {
	serverIP := flag.String("host", "", "IP address of the server")
	filePath := flag.String("file", "../secrets.txt", "Path to the file containing knock sequence")
	flag.Parse()

	if *serverIP == "" {
		fmt.Println("❌ Server IP is required")
		flag.Usage()
		os.Exit(1)
	}

	sequence, err := loadKnockSequence(*filePath)
	if err != nil {
		fmt.Printf("❌ Failed to load knock sequence: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🚀 Sending knock sequence to %s: %v\n", *serverIP, sequence)

	for _, port := range sequence {
		err := sendKnock(*serverIP, port)
		if err != nil {
			fmt.Printf("❌ Error sending knock on port %d: %v\n", port, err)
			os.Exit(1)
		}
		time.Sleep(500 * time.Millisecond) // Small delay between knocks
	}

	fmt.Println("✅ Knock sequence sent!")
}
