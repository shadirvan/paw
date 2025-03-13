# HideP
This tool use port knocking techinque to authorize the client. Implemented in Go.

## How to Install
1. Clone the repository `git clone https://github.com/shadirvan/hidep.git`
2. Install the following Dependencies
### Dependencies
1. Install Go (version 1.20+ recommended) `sudo apt install golang-go`
2. Install Libpcap development Libraries `sudo apt install libpcap-dev`
3. Insatall the required go modules :
  ```
go get -u github.com/google/gopacket
go get -u github.com/google/gopacket/pcap
```
5. Ensure the iptables are installed: `sudo apt install iptables`

## Setup Before Running
### On Server
1. Disable existing firewall rules and drop all input packets
```
sudo iptables -F
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT ACCEPT
```
2. Modify the port sequence file with your unique pattern inside the secrets.txt
3. Enter the server directory : `cd server`
4. Build the server executable : `go build -o server`
### On Client
1. Enter the client Directory: `cd client`
2. Build the client executable :`go build -o client`

## Run the program
on server run the program with sudo : `sudo ./server`

on client run the program: `./client`
