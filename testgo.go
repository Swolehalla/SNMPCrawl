package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"github.com/fatih/color"
	"github.com/soniah/gosnmp"
)

type snmpData struct {
	op5Masterip			string
	apiUsername			string
	apiPassword			string
	hostname			string
	community			string
	if_num_curl			string
	snmp_port_alias		string
	if_num_bit			string
	postCount			int
	commit				bool
}

type Payload struct {
	HostName           string `json:"host_name"`
	ServiceDescription string `json:"service_description"`
	CheckCommandArgs   string `json:"check_command_args"`
	CheckCommand       string `json:"check_command"`
	Template           string `json:"template"`
}

func hostLoader(path string) ([]string, error) {
	file, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	var lines []string

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

var snmpRun snmpData

func main() {
	const oid string = "1.3.6.1.2.1.31.1.1.1.18"
	
	flag.Usage = func() {
		fmt.Printf("Usage:\n")
		fmt.Printf("   %s [-community=<community>] /n", filepath.Base(os.Args[0]))
		fmt.Printf("     op5Masterip      - ip of the monitor server\n")
		flag.PrintDefaults()
	}

	flag.StringVar(&snmpRun.community, "community", "public", "the community string for device")
	flag.StringVar(&snmpRun.op5Masterip, "op5Masterip", "", "Ip address of Monitor Master IP")
	flag.StringVar(&snmpRun.apiUsername, "apiUsername", "", "OP5 Username for api calls")
	flag.StringVar(&snmpRun.apiPassword, "apiPassword", "", "Password for OP5 User")

	// TODO Consider adding OPTIONAL flags for quiet and ignore empty alias

	// Feeds community CLI flag to var
	flag.Parse()

	read, read_err := hostLoader("hosts.txt")

	if read_err != nil {
		err := color.New(color.FgRed)
		err.Println("read error, panicing...")
		os.Exit(1)
	}

	// For each item in the array read, as host, do w/e
	for _, host := range read {
		if host != "" && host != " " {
			fmt.Println("Host: " + host)

			gosnmp.Default.Target = host
			gosnmp.Default.Community = snmpRun.community
			gosnmp.Default.Timeout = time.Duration(5 * time.Second) // Timeout better suited to walking

			err := gosnmp.Default.Connect()
			defer gosnmp.Default.Conn.Close()

			if err != nil {
				err_red := color.New(color.FgRed)
				err_red.Printf("Connect err: %v\n", err)
				os.Exit(1)
			}

			findHostname(&snmpRun)

			err = gosnmp.Default.BulkWalk(oid, printValue)

			if err != nil {
				err_red := color.New(color.FgRed)
				err_red.Printf("Walk Error: %v\n", err)
				os.Exit(1)
			}				
		} else {
			err := color.New(color.FgRed)
			err.Println("Empty host, skipping...")
		}
	}
}

func printValue(pdu gosnmp.SnmpPDU) error {
	switch pdu.Type {
	case gosnmp.OctetString:
		var if_num = strings.Split(pdu.Name, ".")
		snmpRun.if_num_bit = if_num[len(if_num)-1]

		var if_num_curl = "if_num " + string(snmpRun.if_num_bit)
		snmpRun.snmp_port_alias = string(pdu.Value.([]byte))
		snmpRun.if_num_curl = if_num_curl + "-" + snmpRun.snmp_port_alias		

		if snmpRun.postCount <= 30 {
			if snmpRun.snmp_port_alias != "" {
				data := generatePayload(snmpRun, "traffic", "!80", "!90")
				POST(snmpRun, data)
				snmpRun.postCount++
				data = generatePayload(snmpRun, "status", "!1.5", "!2.5")
				POST(snmpRun, data)
				snmpRun.postCount++
				data = generatePayload(snmpRun, "errors", "", "-c")
				POST(snmpRun, data)
				snmpRun.postCount++
			} else {
				err := color.New(color.FgRed)
				err.Println("!Warning! alias was empty, continuing...")
			}
		} else {
			// Run commit...
			snmpRun.commit = true
			POST(snmpRun, Payload{})
			time.Sleep(120 * time.Second)
			snmpRun.commit = false
			snmpRun.postCount = 0
			fmt.Println("Changes committed, continuing...")
		}
	}
	return nil
}

func generatePayload(snmpBlock snmpData, checkCommand string, warn string, crit string) Payload {
	var data Payload

	if checkCommand == "traffic" {
		data = Payload{
			HostName:			snmpBlock.hostname,
			ServiceDescription: snmpBlock.if_num_curl + " traffic",
			CheckCommandArgs:   snmpBlock.community + "!" + snmpRun.if_num_bit + warn + crit,
			CheckCommand:       "check_traffic_bps_v2",
			Template:           "default-service",
		}
	} else if checkCommand == "errors" {
		data = Payload{
			HostName:			snmpBlock.hostname,
			ServiceDescription: snmpBlock.if_num_curl + " Interface Errors",
			CheckCommandArgs:   snmpBlock.community + "!" + snmpRun.if_num_bit + warn + crit,
			CheckCommand:       "check_snmpif_errors_v2",
			Template:           "default-service",
		}
	} else if checkCommand == "status" {
		data = Payload{
			HostName:			snmpBlock.hostname,
			ServiceDescription: snmpBlock.if_num_curl + " Port Status",
			CheckCommandArgs:   snmpBlock.community + "!" + snmpRun.if_num_bit + warn + crit,
			CheckCommand:       "check_snmpif_status_v2",
			Template:           "default-service",
		}
	} else {
		panic("checkCommand Invalid!")
	}

	return data
}

type op5API struct {
	Name string `json:"name"`
}

func findHostname(snmpBlock *snmpData) {
	var apiURL = "https://" + snmpBlock.op5Masterip + "/api/filter/query?format=json&query=%5Bhosts%5D+address+%3D+%22" + string(gosnmp.Default.Target) + "%22&columns=name"

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	request, err := http.NewRequest("GET", apiURL, nil)
	request.SetBasicAuth(snmpBlock.apiUsername, snmpBlock.apiPassword)
	client := &http.Client{}
	response, err := client.Do(request)
	body, err := ioutil.ReadAll(response.Body)

	if err != nil {
		fmt.Println("%s", err)
		os.Exit(1)
	}

	var hostAlias []op5API

	err = json.Unmarshal([]byte(body), &hostAlias)

	if err != nil {
		fmt.Printf("There was an error decoding the json. err = %s", err)
	}

	snmpBlock.hostname = hostAlias[0].Name
}



func POST(snmpBlock snmpData, payload Payload) {
	// This disables HTTPS certificate validation
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	time.Sleep(250 * time.Millisecond)

	payloadBytes, err := json.Marshal(payload)
	
	if err != nil {
		panic(err)
	}
	
	fmt.Println(string(payloadBytes))

	body := bytes.NewReader(payloadBytes)
	
	req, err := http.NewRequest("POST", "https://" + snmpBlock.op5Masterip + "/api/config/service", body)
	
	if snmpBlock.commit {
		req, err = http.NewRequest("POST", "https://" + snmpBlock.op5Masterip + "/api/config/change", body)
	}
	
	if err != nil {
		panic(err)
	}
	
	req.SetBasicAuth(snmpBlock.apiUsername, snmpBlock.apiPassword)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)

	time.Sleep(250 * time.Millisecond)

}
