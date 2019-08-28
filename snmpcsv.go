package main

import (
	"bufio"
	"flag"
	"fmt"
	"encoding/csv"
	"os"
	"path/filepath"
	"time"

	"github.com/soniah/gosnmp"
)

func hostLoader(path string) ([]string, error) {
	file, err := os.Open(path)

	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := csv.NewReader(bufio.NewReader(f))
	
	for scanner.Scan() {
  		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage:\n")
		fmt.Printf("   %s [-community=<community>] /n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	var community string
	flag.StringVar(&community, "community", "public", "the community string for device")

	flag.Parse()

	if len(flag.Args()) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	// Sets the value of the main() scope variable read to the return value of hostLoader
	read, read_err := hostLoader("hosts.txt")

	if read_err != nil {
		fmt.Printf("read error")
	}

	var target = ""
	// For each item in the array read, as host, do w/e
	for _, host := range read {
		fmt.Printf(host)
		target = host
	}

	var oid string = "1.3.6.1.2.1.31.1.1.1.18"

	if len(flag.Args()) > 1 {
		oid = flag.Args()[1]
	}

	gosnmp.Default.Target = target
	gosnmp.Default.Community = community
	gosnmp.Default.Timeout = time.Duration(10 * time.Second) // Timeout better suited to walking

	err := gosnmp.Default.Connect()

	if err != nil {
		fmt.Printf("Connect err: %v\n", err)
		os.Exit(1)
	}
	defer gosnmp.Default.Conn.Close()

	err = gosnmp.Default.BulkWalk(oid, printValue)

	if err != nil {
		fmt.Printf("Walk Error: %v\n", err)
		os.Exit(1)
	}
}

func printValue(pdu gosnmp.SnmpPDU) error {
	fmt.Printf("%s = ", pdu.Name)

	switch pdu.Type {
	case gosnmp.OctetString:
		b := pdu.Value.([]byte)
		fmt.Printf("STRING: %s\n", string(b))
	default:
		fmt.Printf("TYPE %d: %d\n", pdu.Type, gosnmp.ToBigInt(pdu.Value))
	}

	return nil
}
