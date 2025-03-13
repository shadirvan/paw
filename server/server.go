package main

import (
	"bufio"
	"flag"
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

const timeout = 5 * time.Second

var knockSequence []int
var state = make(map[string][]int) // To track client progress
var stateMutex = sync.Mutex{}

// Read knock sequence from a file
func loadKnockSequence(fileName string) error {
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		port, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
		if err != nil {
			return fmt.Errorf("invalid port value: %v", err)
		}
		knockSequence = append(knockSequence, port)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if len(knockSequence) == 0 {
		return fmt.Errorf("knock sequence is empty")
	}

	return nil
}

// Allow IP using iptables (only if it doesn't already exist)
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

// Handle port knock logic
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

		// If the sequence is complete
		if len(state[clientIP]) == len(knockSequence) {
			fmt.Printf("🎉 Correct knock sequence received from %s!\n", clientIP)
			delete(state, clientIP) // Reset the state after successful knock

			// Allow the IP through firewall
			if err := allowIP(clientIP); err != nil {
				fmt.Printf("❌ Failed to allow IP: %v\n", err)
			}
		}

		// Start timeout to reset state
		go resetAfterTimeout(clientIP)
	} else {
		fmt.Printf("❌ Incorrect knock on port %d from %s. Resetting sequence.\n", port, clientIP)
		delete(state, clientIP)
	}
}

// Reset state after timeout
func resetAfterTimeout(clientIP string) {
	time.Sleep(timeout)
	stateMutex.Lock()
	defer stateMutex.Unlock()

	if len(state[clientIP]) > 0 {
		fmt.Printf("⏳ Timeout for %s. Resetting sequence.\n", clientIP)
		delete(state, clientIP)
	}
}

// Capture UDP packets using gopacket
func listenForKnocks() {
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever) // Use "lo" for localhost or "eth0" for network interface
	if err != nil {
		fmt.Println("Error opening pcap:", err)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Extract UDP layer
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				clientIP := ip.SrcIP.String()
				port := int(udp.DstPort)
				fmt.Printf("📥 Received knock from %s on port %d\n", clientIP, port)
				handleKnock(clientIP, port)
			}
		}
	}
}

func main() {
	fileName := flag.String("file", "../secrets.txt", "File containing the port knock sequence")
	flag.Parse()

	if err := loadKnockSequence(*fileName); err != nil {
		fmt.Printf("❌ Failed to load knock sequence: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🚀 Starting packet sniffer for port knocking with sequence: %v\n", knockSequence)

	go listenForKnocks()

	select {} // Keep the program running
}
