package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

var knockSequence = []int{1256, 3333, 5656}
var serverIP = flag.String("host", "", "IP address to send the knocks") // No default value

const timeout = 2 * time.Second

func sendKnock(port int) error {
	address := fmt.Sprintf("%s:%d", *serverIP, port)
	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		return fmt.Errorf("failed to send knock to %s: %v", address, err)
	}
	defer conn.Close()

	// Just send an empty packet as the knock
	_, err = conn.Write([]byte{})
	if err != nil {
		return fmt.Errorf("failed to send packet to %s: %v", address, err)
	}

	fmt.Printf("Knocked on port %d\n", port)
	return nil
}

func main() {
	// Parse the command-line arguments
	flag.Parse()

	// Check if the host is provided
	if *serverIP == "" {
		fmt.Println("Error: -host argument is required")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Printf("Sending knock to server: %s\n", *serverIP)
	for _, port := range knockSequence {
		err := sendKnock(port)
		if err != nil {
			fmt.Printf("Error knocking port %d: %v\n", port, err)
			continue
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Println("Port knocking sequence completed!")
}
