package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
)

const rounds = 64

func encrypt(k uint32, m [8]byte) (c [8]byte) {
	// Only keep the least significant 24 bits
	k &= (1 << 24) - 1

	v0, v1 := binary.BigEndian.Uint32(m[:]), binary.BigEndian.Uint32(m[4:])
	const delta = 0x9E3779B9
	sum := uint32(0)
	key := [4]uint32{k, k, k, k}
	for i := 0; i < rounds; i++ {
		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum&3])
		sum += delta
		v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11)&3])
	}
	binary.BigEndian.PutUint32(c[:], v0)
	binary.BigEndian.PutUint32(c[4:], v1)
	return
}

func decrypt(k uint32, c [8]byte) (m [8]byte) {
	// Only keep the least significant 24 bits
	k &= (1 << 24) - 1

	v0, v1 := binary.BigEndian.Uint32(c[:]), binary.BigEndian.Uint32(c[4:])
	const delta = 0x9E3779B9
	sum := uint32((delta * rounds) & math.MaxUint32)
	key := [4]uint32{k, k, k, k}
	for i := 0; i < rounds; i++ {
		v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11)&3])
		sum -= delta
		v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum&3])
	}
	binary.BigEndian.PutUint32(m[:], v0)
	binary.BigEndian.PutUint32(m[4:], v1)
	return
}

func tripleEncrypt(k1, k2, k3 uint32, m [8]byte) (c [8]byte) {
	return encrypt(k3, encrypt(k2, encrypt(k1, m)))
}

func tripleDecrypt(k1, k2, k3 uint32, c [8]byte) (m [8]byte) {
	return decrypt(k1, decrypt(k2, decrypt(k3, c)))
}

type grade uint8

const (
	A grade = iota
	B
	C
	NC
)

func (g grade) String() string {
	strs := []string{"A", "B", "C", "N"}
	return strs[int(g)]
}

func randomGrade() grade {
	n := rand.Int() % 100
	/*
		50% A
		30% B
		15% C
		5%  NC
	*/
	switch {
	case n < 50:
		return A
	case n < 80:
		return B
	case n < 95:
		return C
	default:
		return NC
	}
}

// 8 bytes for the grade
func formatGrade(g grade) string {
	return fmt.Sprintf(", grd:%v\n", g)
}

// 8 bytes for the ID
func formatID(id int) string {
	return fmt.Sprintf("id:%05v", id)
}

func formatLine(id int, g grade) string {
	return formatID(id) + formatGrade(g)
}

type cryptWriter struct {
	k1, k2, k3 uint32
	w          io.Writer
	buf        []byte
	err        error
}

func (c *cryptWriter) Write(p []byte) (n int, err error) {
	if c.err != nil {
		return 0, c.err
	}

	c.buf = append(c.buf, p...)
	for len(c.buf) >= 8 {
		var m [8]byte
		copy(m[:], c.buf)
		c.buf = c.buf[8:]
		cipher := tripleEncrypt(c.k1, c.k2, c.k3, m)

		var e2 error
		var nn int
		nn, e2 = c.w.Write(cipher[:])
		if e2 != nil {
			c.err = e2
			n += nn
			return n, e2
		}
	}

	return len(p), nil
}

type cipherblock [8]byte

type part1Answer struct {
	// The cipherblock corresponding to `A`
	ACiphertext cipherblock `json:"a_ciphertext"`
	// The cipherblock corresponding to `B`
	BCiphertext cipherblock `json:"b_ciphertext"`
	// The cipherblock corresponding to `C`
	CCiphertext cipherblock `json:"c_ciphertext"`
	// The cipherblock corresponding to `N`
	NCiphertext cipherblock `json:"n_ciphertext"`
}

type part2Answer struct {
	// The number of `A`s received by the famous student.
	NumAs int `json:"num_as"`
	// The number of `C`s received by the famous student.
	NumCs int `json:"num_cs"`
	// The number of `N`s received by the famous student.
	NumNs int `json:"num_ns"`
}

type answer struct {
	Part1 part1Answer `json:"part_1"`
	Part2 part2Answer `json:"part_2"`
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %v [--answer] <key-hex>\n", os.Args[0])
	os.Exit(1)
}

func main() {
	var args []string
	shouldAnswer := false
	switch {
	case len(os.Args) == 2:
		args = os.Args[1:]
	case len(os.Args) == 3 && os.Args[1] == "--answer":
		shouldAnswer = true
		args = os.Args[2:]
	default:
		usage()
	}

	key, err := hex.DecodeString(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not parse <key-hex>: %v\n", err)
		os.Exit(1)
	}
	if len(key) != 13 {
		fmt.Fprintf(os.Stderr, "need 13-byte key\n")
		os.Exit(1)
	}
	rand.Seed(int64(binary.BigEndian.Uint32(key[:4])))
	k1 := binary.BigEndian.Uint32(append([]byte{0}, key[4:7]...))
	k2 := binary.BigEndian.Uint32(append([]byte{0}, key[7:10]...))
	k3 := binary.BigEndian.Uint32(append([]byte{0}, key[10:]...))

	students := 10000
	classes := 30

	// random subset of {1, ..., 100,000}
	IDs := rand.Perm(1e5)[:students]
	type studentGrade struct {
		id int
		g  grade
	}
	var allGrades []studentGrade

	for i := 0; i < students-1; i++ {
		var grades []grade
		var numA, numB, numC int
		for j := 0; j < classes; j++ {
			g := randomGrade()
			grades = append(grades, g)
			switch g {
			case A:
				numA++
			case B:
				numB++
			case C:
				numC++
			}
		}
		// we only want one student to have some As,
		// some Cs, and no Bs
		if numA > 0 && numC > 0 && numB == 0 {
			grades[rand.Int()%len(grades)] = B
		}
		for _, g := range grades {
			allGrades = append(allGrades, studentGrade{IDs[i], g})
		}
	}

	// keep track of these stats
	// so we can print them if
	// the --answer flag was given
	var numA, numC, numN int
	numA, numC = 1, 1
	allGrades = append(allGrades, studentGrade{IDs[students-1], A})
	allGrades = append(allGrades, studentGrade{IDs[students-1], C})
	for j := 2; j < classes; j++ {
		g := randomGrade()
		for g == B {
			g = randomGrade()
		}
		allGrades = append(allGrades, studentGrade{IDs[students-1], g})
		switch g {
		case A:
			numA++
		case C:
			numC++
		case NC:
			numN++
		}
	}

	if shouldAnswer {
		f := func(g grade) [8]byte {
			b := []byte(formatGrade(g))
			var m [8]byte
			copy(m[:], b)
			return tripleEncrypt(k1, k2, k3, m)
		}

		answers := answer{
			Part1: part1Answer{
				ACiphertext: f(A),
				BCiphertext: f(B),
				CCiphertext: f(C),
				NCiphertext: f(NC),
			},
			Part2: part2Answer{
				NumAs: numA,
				NumCs: numC,
				NumNs: numN,
			},
		}

		answerString, err := json.MarshalIndent(answers, "", "    ")

		if err != nil {
			panic(err)
		}

		fmt.Println(string(answerString))
		return
	}

	cw := cryptWriter{k1: k1, k2: k2, k3: k3, w: os.Stdout}
	permutation := rand.Perm(len(allGrades))
	for _, i := range permutation {
		sg := allGrades[i]
		// NOTE (jliebowf): For some reason, using
		// cw.Write([]byte(formatLine(sg.id, sg.g)))
		// doesn't behave properly. It should, so
		// I'm not sure why (I didn't really dig
		// into it that far). It's probably not that
		// hard of a bug, but just make sure that if
		// you decide to change it to that, you are
		// extra careful to avoid introducing bugs.
		// In particular, the bug I ran into was that
		// the first few bytes of all lines were
		// identical.
		fmt.Fprint(&cw, formatLine(sg.id, sg.g))
	}
}
