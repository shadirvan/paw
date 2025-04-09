package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const secretKey = "my-shared-secret"
const timeSkew = 5 // Accept timestamp within 5 seconds

var knockSequence []int
var state = make(map[string][]int)
var stateMutex = sync.Mutex{}

func loadKnockSequence(fileName string) error {
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	var ports []int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		port, err := strconv.Atoi(scanner.Text())
		if err != nil {
			return fmt.Errorf("invalid port value: %v", err)
		}
		ports = append(ports, port)
	}

	knockSequence = ports
	return scanner.Err()
}

// Generate HMAC for message
func generateHMAC(message string) string {
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// Verify HMAC and timestamp
func validateKnock(message, receivedHMAC string) (int, int64, error) {
	parts := strings.Split(message, ":")
	if len(parts) != 2 {
		return 0, 0, errors.New("invalid packet format")
	}

	port, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, errors.New("invalid port value")
	}

	timestamp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, errors.New("invalid timestamp value")
	}

	// Check timestamp validity
	if abs(time.Now().Unix()-timestamp) > timeSkew {
		return 0, 0, errors.New("timestamp out of range")
	}

	expectedHMAC := generateHMAC(message)
	if !hmac.Equal([]byte(expectedHMAC), []byte(receivedHMAC)) {
		return 0, 0, errors.New("HMAC mismatch")
	}

	return port, timestamp, nil
}
func allowIP(ip string) error {
	// Check if the rule already exists
	checkCmd := exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "ACCEPT")
	if err := checkCmd.Run(); err == nil {
		fmt.Printf("🚫 IP %s is already allowed. Skipping.\n", ip)
		return nil
	}

	// If the rule does not exist, add it
	fmt.Printf("🚪 Allowing IP %s through firewall\n", ip)
	addCmd := exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "ACCEPT")
	if err := addCmd.Run(); err != nil {
		return fmt.Errorf("failed to add iptables rule: %v", err)
	}
	return nil
}

// Track knock progress and validate sequence
func handleKnock(clientIP string, port int) {
	stateMutex.Lock()
	defer stateMutex.Unlock()

	progress, exists := state[clientIP]
	if !exists {
		state[clientIP] = []int{}
		progress = state[clientIP]
	}

	nextPortIndex := len(progress)
	if nextPortIndex < len(knockSequence) && port == knockSequence[nextPortIndex] {
		state[clientIP] = append(progress, port)
		fmt.Printf("✅ Knock %d/%d correct from %s\n", nextPortIndex+1, len(knockSequence), clientIP)

		if len(state[clientIP]) == len(knockSequence) {
			fmt.Printf("🎉 Correct knock sequence received from %s!\n", clientIP)
			allowIP(clientIP)
			delete(state, clientIP)

		}
	} else {
		fmt.Printf("❌ Incorrect knock from %s. Resetting sequence.\n", clientIP)
		delete(state, clientIP)
	}
}

// Packet capture and processing
func listenForKnocks() {
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("❌ Error opening pcap: %v\n", err)
		os.Exit(1)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				clientIP := ip.SrcIP.String()

				data := string(packet.ApplicationLayer().Payload())
				parts := strings.Split(data, ":")
				if len(parts) != 3 {
					continue
				}

				// Extract port and timestamp
				port, timestamp, err := validateKnock(fmt.Sprintf("%s:%s", parts[0], parts[1]), parts[2])
				if err != nil {
					fmt.Printf("❌ Invalid knock from %s: %v\n", clientIP, err)
					continue
				}

				fmt.Printf("📥 Knock on port %d at time %d from %s\n", port, timestamp, clientIP)

				// Pass port value to handleKnock ✅
				handleKnock(clientIP, port)
			}
		}
	}
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func main() {
	err := loadKnockSequence("../secrets.txt")
	if err != nil {
		fmt.Printf("❌ Error loading knock sequence: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("🚀 Listening for knocks...")
	listenForKnocks()
}
