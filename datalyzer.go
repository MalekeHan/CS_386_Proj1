// This program reads an encrypted database from stdin, analyzes it, and outputs
// its analysis as json. We've already covered the process of parsing stdin, and
// outputting the json answer. You just need to do the middle step: analyzing
// the encrypted database. Implement the functions `part1` and `part2`.

/*
 usage: go run generator.go [KEY] | go run datalyzer.go
	- [KEY] --> 0123456789abcdef0123456789
		go run generator.go --answer 0123456789abcdef0123456789
			- checks our answer
*/

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

/********************************* TYPES **************************************/

// Each block of ciphertext is eight bytes wide.
type cipherblock [8]byte

// Each encrypted row of the database consists of two cipher blocks.
type cipherrow struct {
	id    cipherblock
	grade cipherblock
}

/********************************* PART 1 *************************************/

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

func part1(database []cipherrow) (answer part1Answer) {
	gradeMap := make(map[cipherblock]int)

	// Loop through each row in the database
	for _, row := range database {
		gradeMap[row.grade]++
	}

	var cipherblocks_keys []cipherblock // create a slice to hold all the keys we got from gradeMap
	for key := range gradeMap {
		cipherblocks_keys = append(cipherblocks_keys, key)
	}

	sort.Slice(cipherblocks_keys, func(i, j int) bool {
		return gradeMap[cipherblocks_keys[i]] > gradeMap[cipherblocks_keys[j]] //look at cipher blocks at the two positions and get the counts from grademap -- whatever is greater should go first in cipher blocks
	})

	// we know because of the distr that
	answer.ACiphertext = cipherblocks_keys[0]
	answer.BCiphertext = cipherblocks_keys[1]
	answer.CCiphertext = cipherblocks_keys[2]
	answer.NCiphertext = cipherblocks_keys[3]

	//Save the identified cipher text to be used later on
	cipherToGrades.A = cipherblocks_keys[0]
	cipherToGrades.B = cipherblocks_keys[1]
	cipherToGrades.C = cipherblocks_keys[2]
	cipherToGrades.N = cipherblocks_keys[3]

	return answer
}

var cipherToGrades struct {
	A cipherblock
	B cipherblock
	C cipherblock
	N cipherblock
}

/********************************* PART 2 *************************************/

type part2Answer struct {
	// The number of `A`s received by the famous student.
	NumAs uint32 `json:"num_as"`
	// The number of `C`s received by the famous student.
	NumCs uint32 `json:"num_cs"`
	// The number of `N`s received by the famous student.
	NumNs uint32 `json:"num_ns"`
}

func part2(database []cipherrow) (answer part2Answer) {

	studentGrades := make(map[cipherblock]map[string]uint32) // create a map of maps -- this is [studentID |--> [A |--> int, B |--> int, C |--> int]]
	studentsWithB := make(map[cipherblock]bool)              // allows us to map each student to whether they have recieved a B  [studentID |--> bool]

	// go through every single line for in the data base
	for _, row := range database {

		if row.grade == cipherToGrades.B { // check to see if this grade is a b
			studentsWithB[row.id] = true // if it is a b mark it and move on
			continue
		}

		if _, exists := studentGrades[row.id]; !exists { // create the grade map here if it does not already exist for this student
			studentGrades[row.id] = make(map[string]uint32) // then we can create the inner map for them
		}

		if row.grade == cipherToGrades.A { //update the count for all non-b's
			studentGrades[row.id]["A"]++
		} else if row.grade == cipherToGrades.C {
			studentGrades[row.id]["C"]++
		} else if row.grade == cipherToGrades.N {
			studentGrades[row.id]["N"]++
		}
	}

	// go through all the student grades
	for id, grades := range studentGrades {
		if !studentsWithB[id] { // check to see if this studentID got marked as false
			answer.NumAs = grades["A"]
			answer.NumCs = grades["C"]
			answer.NumNs = grades["N"]
			break // break as soon as we finally get the student
		}
	}

	return answer

}

/***************************** Provided Code **********************************/
// To complete this assignment you should NOT have to modify any code from here
// onwards.

// Parses bytes from `reader` into a structured representation of the encrypted
// database.
func parse(reader io.Reader) (database []cipherrow) {
	// Read all bytes from the reader.
	bytes, err := io.ReadAll(os.Stdin)

	if err != nil {
		panic(err)
	}

	// Validate that we've read a valid number of bytes. (Should be a multiple
	// of 16.)

	//Each row is consists of two cipher blocks
	if len(bytes)%16 != 0 {
		panic("Excepted a multiple-of-16 number of bytes.")
	}

	// The total number of rows in the encrypted database.
	rows := len(bytes) / 16

	// Allocate a `rows`-length array of cipherrows.
	// Create a slice of cipher rows with the length equal to the amount of total rows there are in the DB
	database = make([]cipherrow, rows)

	// Parse the database bytes into a structured format.
	for row := 0; row < rows; row++ {
		b := row * 16              // loop through each set of 16 bytes
		database[row] = cipherrow{ // create a cipher row at the current row index
			id:    (cipherblock)(bytes[b:(b + 8)]),        // first 8 bytes go to ID
			grade: (cipherblock)(bytes[(b + 8):(b + 16)]), // second 8 bytes go to the grade
		}
	}

	return database // we return the slice of cipher rows
}

type answer struct {
	Part1 part1Answer `json:"part_1"`
	Part2 part2Answer `json:"part_2"`
}

func main() {
	// parse the database from stdin
	database := parse(os.Stdin)

	//fmt.Println(database)

	// analyze the database
	answers := answer{
		Part1: part1(database),
		Part2: part2(database),
	}

	// format the analysis as json
	answerString, err := json.MarshalIndent(answers, "", "    ")

	if err != nil {
		panic(err)
	}

	// print the database to stdout

	fmt.Println(string(answerString))
}
