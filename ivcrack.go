// COLLABORATED WITH COLM and BLAYDE
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

// Your job is to implement this function. Feel free to modify, rename, and
// re-imagine it. We have provided already-implemented helper functions you may
// use, and you may define whatever helper functions or import whatever packages
// you need.
func crack(conn net.Conn) (key []byte) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read the initial packet sent from the router and parse it.
	packet, _ := reader.ReadString('\n')
	originalIV, c := parsePacket(packet[:len(packet)-1])

	// Convert original IV to a string for easy comparison.
	originalIVHex := hex.EncodeToString(originalIV)
	fmt.Println("THIS IS THE ORIGINAL IV AND CIPHERTEXT FROM THE KEY THAT WAS SENT.")
	fmt.Printf("Original IV: %s\n", originalIVHex)
	fmt.Printf("Ciphertext: %x\n", c)

	for i := 0; i < 65536; i++ { // go through 2^16 IVs
		send(conn, c) // send the cipher text of the Key so that way it will be ran through the encyrption algo

		iv, c := recv(reader) // receive and parse the response // what we recieve is the cipher of the CIPHER OF THE KEY -- because of the Enc algorithm this will use an XOR that will give us back the Key
		// because we are using the same exact IV and the key is automatically given which is G. So now we can fully get the Key because it will be given as the "ENCRYPTION"
		ivHex := hex.EncodeToString(iv)
		// check if the current IV got from sending the plaintext is the same exact as the original router IV
		if ivHex == originalIVHex {
			// fmt.Println("Found matching IV!")
			// fmt.Printf("Matching IV: %s\n", ivHex)
			// fmt.Printf("Ciphertext: %x\n\n", c)
			return c
		}
	}

	//fmt.Println("No matching IV found after exhaustive search.")
	return nil
}

func send(conn net.Conn, data []byte) {
	fmt.Fprintf(conn, "%s\n", hex.EncodeToString(data))
}

func recv(reader *bufio.Reader) (iv []byte, c []byte) {
	packet, _ := reader.ReadString('\n')
	iv, c = parsePacket(packet[:len(packet)-1])
	return
}

func parsePacket(packet string) (iv []byte, c []byte) {
	// the hex-encoded components of a packet are space-delimited
	components := strings.Split(packet, " ")
	decoded_components := make([][]byte, 2)

	// hex-decode components
	for i, component := range components {
		decoded, err := hex.DecodeString(component)
		if err != nil {
			fmt.Printf("Could not decode message: %v\n", err)
			continue
		}
		decoded_components[i] = decoded
	}

	iv, c = decoded_components[0], decoded_components[1]
	return
}

var usage string = `Usage: %v [bind-addr]
		
Cracks the wireless communication key.

Example:
	$ %v :1234
`

func parseArgs() (bindAddr string) {
	if len(os.Args) != 2 {
		// If one argument has not been provided, print usage information and
		// quit.
		bin := os.Args[0]
		log.Fatalf(usage, bin, bin)
	}

	// The TCP bind address is the first argument.
	bindAddr = os.Args[1]

	return bindAddr
}

func main() {
	bindAddr := parseArgs()

	conn, err := net.Dial("tcp", bindAddr)

	if err != nil {
		log.Fatalf("Could not connect to %v: %v\n", bindAddr, err)
	}
	// data := []byte("Hello, world!")
	// send(conn, data)

	// reader := bufio.NewReader(conn)
	// iv, c := recv(reader)

	// fmt.Printf("IV: %x\n", iv)
	// fmt.Printf("Ciphertext: %x\n", c)

	key := crack(conn)
	fmt.Println(hex.EncodeToString(key))
}
