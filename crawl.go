package main

import (
	"bufio"
	"fmt"
	"os"
	"github.com/soniah/gosnmp"
	"github.com/golang/mock/gomock"
	"log"
)

func hosts() {
	file, err := os.Open("hosts.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	// Returns a boolean based on whether there's a next instance of `\n`
	// character in the IO stream. This step also advances the internal pointer
	// to the next position (after '\n') if it did find that token.
	read := scanner.Scan()

	if read {
		fmt.Println("read byte array: ", scanner.Bytes())
		fmt.Println("read string: ", scanner.Text())
	}
}

func walk(x *GoSNMP) { Walk(rootOid 1.3.6.1.2.1.31.1.1.1.18, walkFn WalkFunc) error 
	return x.walk(GetNextRequest, rootOid, walkFn)
}

func snmpwalk() {
	for _ := range hosts()
}

func main() {
	hostparse = hosts.do()
	walk = snmpwalk.do()
}