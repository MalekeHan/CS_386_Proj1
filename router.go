// Usage example:
// 		go run router.go ':4321' 01234567789abcdef
//
// This will start a router that listens on port 4321. It listens for
// line-delimited hex-encoded data, and produces line-delimited responses in the
// form of:
//		<hex encoded IV> <hex encoded ciphertext>

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
)

var usage string = `Usage: %v [bind-addr] [key-hex]
		
Encrypts plaintext received on bind-addr using key-hex.

Example:
	$ %v :1234 0123456789abcdef
`

// Parses the command line arguments of this application.
func parseArgs() (bindAddr string, key []byte) {
	if len(os.Args) != 3 {
		// If two arguments have not been provided, print usage information and
		// quit.
		bin := os.Args[0]
		log.Fatalf(usage, bin, bin)
	}

	// The TCP bind address is the first argument.
	bindAddr = os.Args[1]

	// The key, encoded in hex, is the second argument.
	key, err := hex.DecodeString(os.Args[2])
	if err != nil {
		log.Fatalf("bad key: %v\n", err)
	}

	return bindAddr, key
}

// Generate the next initialization vector.
func generateIV() (iv [2]byte) {
	_, err := rand.Read(iv[:])
	if err != nil {
		log.Fatalf("could not read random bytes: %v", err)
	}
	return
}

func encryptPacket(key []byte, m []byte) (iv [2]byte, c []byte) {
	// Generate a random initialization vector.
	iv = generateIV()
	// Concatenate the key and initialization vector.
	s := append(key, iv[:]...)
	// Allocate space for the ciphertext.
	c = make([]byte, len(m))
	// XOR `m` with random bytes generated from `s`, and stash in `c`.
	cipher, _ := rc4.NewCipher(s)
	cipher.XORKeyStream(c, m)
	return
}

func handleConnection(conn net.Conn, key []byte) {
	defer conn.Close()

	// Prove to the hub that the router knows the key, by encrypting the key
	// and transmitting it.
	iv, c := encryptPacket(key, key)
	fmt.Fprintf(conn, "%s %s\n",
		hex.EncodeToString(iv[:]),
		hex.EncodeToString(c[:]),
	)

	scanner := bufio.NewScanner(bufio.NewReader(conn))

	for scanner.Scan() {
		bytes := scanner.Text()
		m, err := hex.DecodeString(bytes)
		if err != nil {
			fmt.Printf("Could not decode message: %v\n", err)
			continue
		}

		iv, c = encryptPacket(key, m)

		fmt.Fprintf(conn, "%s %s\n",
			hex.EncodeToString(iv[:]),
			hex.EncodeToString(c[:]),
		)
	}
}

func main() {
	fmt.Println("test")
	bindAddr, key := parseArgs()

	server, err := net.Listen("tcp", bindAddr)

	if err != nil {
		log.Fatalf("Could not listen on %v: %v\n", bindAddr, err)
	}

	for {
		conn, err := server.Accept()
		if err != nil {
			fmt.Printf("Could not accept connection: %v\n", err)
		}
		go handleConnection(conn, key)
	}
}
