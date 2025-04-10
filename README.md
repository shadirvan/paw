# PAW
Port Authenticator and Whitelister. This tool use port knocking techinque to authorize the client. Implemented in Go.

## Installation
1. Clone the repository `https://github.com/shadirvan/paw.git`
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

## Prerequisites
Before building the project change the shared secret key used to generate HMAC
### On Server
1. Disable existing firewall rules and drop all input packets
   - Flush out the rules if any:
     ```sudo iptables -F```
   - Set input rules to drop incoming packets:
```
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT ACCEPT
```
2. Modify the `secrets.txt` file with your unique port knocking sequence
3. Enter the server directory : `cd server`
4. Build the server executable : `go build -o server`
### On Client
1. Enter the client Directory: `cd client`
2. Build the client executable :`go build -o client`

## Usage
On server run the program with root privileges : `sudo ./server`

On client run the program with the server IP: `./client -host [server_ip]`
