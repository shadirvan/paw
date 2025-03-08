package main

import (
	"fmt"
	"net"
	"time"
)

var knockSequence = []int{1234, 5678, 9101}

const serverIP = "127.0.0.1"
const timeout = 2 * time.Second

func sendKnock(port int) error {
	address := fmt.Sprintf("%s:%d", serverIP, port)
	conn, err := net.DialTimeout("udp", address, timeout) // Use UDP instead of TCP
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
