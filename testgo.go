package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"net/http"
    "io/ioutil"

	"github.com/fatih/color"
	"github.com/soniah/gosnmp"
)

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

func main() {
	// Put any global vars (barf) here
	const oid string = "1.3.6.1.2.1.31.1.1.1.18"

	flag.Usage = func() {
		fmt.Printf("Usage:\n")
		fmt.Printf("   %s [-community=<community>] /n", filepath.Base(os.Args[0]))
		fmt.Printf("     op5Masterip      - ip of the monitor server\n")
		flag.PrintDefaults()
	}

	var community string
	flag.StringVar(&community, "community", "public", "the community string for device")

	var op5Masterip string
	flag.StringVar(&op5Masterip, "op5Masterip", "", "Ip address of Monitor Master IP")

	var apiUsername string
	flag.StringVar(&apiUsername, "apiUsername", "", "OP5 Username for api calls")

	var apiPassword string
	flag.StringVar(&apiPassword, "apiPassword", "", "Password for OP5 User")

	// Consider adding OPTIONAL flags for quiet and ignore empty alias

	// Feeds community CLI flag to var
	flag.Parse()

	// Sets the value of the main() scope variable read to the return value of hostLoader
	read, read_err := hostLoader("hosts.txt")

	if read_err != nil {
		err := color.New(color.FgRed)
		err.Println("read error, panicing...")
		os.Exit(1)
	}

	// For each item in the array read, as host, do w/e
	for _, host := range read {
		if host != "" && host != " " {
			fmt.Println(host)

			gosnmp.Default.Target = host
			gosnmp.Default.Community = community
			gosnmp.Default.Timeout = time.Duration(5 * time.Second) // Timeout better suited to walking

			fmt.Println(gosnmp.Default.Community)

			err := gosnmp.Default.Connect()
			defer gosnmp.Default.Conn.Close()

			if err != nil {
				err_red := color.New(color.FgRed)
				err_red.Printf("Connect err: %v\n", err)
				os.Exit(1)
			}

			// To pass multiple arguments to a func, your call should look something like this
			// Please note that the order by which args are passed in DOES matter. To make it not matter would require some time of me
			// teaching you at a whiteboard. Also, each time findHostName() is typed, a new version of the func is run and it requires ALL
			// non-defaulted args to be passed EACH time.
			// findHostName(arg1, arg2, arg3)

			// This sets the LOCAL var hostNamecurl to the return value of findHostname
			hostNamecurl := findHostname(op5Masterip, apiUsername, apiPassword)

			// findHostname(hostNamecurl)

			// NOW hostNamecurl is in local scope, meaning this won't complain.
			postServices(apiUsername, apiPassword, hostNamecurl)

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

// FYI it's best practice for all functions to be delineated BEFORE main. Obviously, go compiler doesn't care but it's usual to at least have a prototype before main
func printValue(pdu gosnmp.SnmpPDU) error {
	switch pdu.Type {
	case gosnmp.OctetString:
		var if_num = strings.Split(pdu.Name, ".")
		var if_num_bit = if_num[len(if_num)-1]
		var if_num_curl = "if_num " + string(if_num_bit)

		fmt.Println(if_num_curl + " - ")

		snmp_port_alias := string(pdu.Value.([]byte))

		if snmp_port_alias != "" {
			fmt.Println("port_alias " + snmp_port_alias)
		} else {
			err := color.New(color.FgRed)
			err.Println("!Warning! alias was empty, continuing...")
		}
		// default:
		// 	fmt.Printf("TYPE %d: %d\n", pdu.Type, gosnmp.ToBigInt(pdu.Value))
	}

	return nil
}

// To accept multiple parameters, your func declaration should look something like this...
// func findHostName(param1name param1type, param2name param2type... paramNname, paramNtype) {
func postServices(op5Masterip string, apiUsername string, apiPassword string) string {
	var op5Master = "https://" + op5Masterip
	var hostNamecurl = "/api/filter/query?format=json&query=%5Bhosts%5D+address+%3D+%22" + string(gosnmp.Default.Target) + "%22&columns=name"

	postServices(hostNamecurl, apiUsername, apiPassword)

	fmt.Println(op5Master + hostNamecurl)

	// Adding the string at the end of the func declaration allows us to return the string hostNamecurl here at the end
	return hostNamecurl
}

func findHostname(apiUsername string, apiPassword string, hostNamecurl string) {
		auth := apiUsername + ":" + apiPassword
		url := "https://" + op5Masterip + "/api/filter/query?format=json&query= [hosts] address = 172.27.210.10&columns=name"
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Add("authorization", "Basic " + auth(apiUsername,apiPassword)
		res, _ := http.DefaultClient.Do(req)
		defer res.Body.Close()
		body, _ := ioutil.ReadAll(res.Body)
		fmt.Println(res)
		fmt.Println(string(body))
	}
	//	curl -H 'content-type: application/json' -d  '{"host_name":"rnc04-ra008","service_description":"IF 8_ gre Traffic","check_command":"check_traffic_bps_v2","check_command_args":"'n3gT1vGh057r1d3r'!8!70!90","stalking_options":["n"],"template":"default-service","register":true,"file_id":"etc\/services.cfg","is_volatile":false,"max_check_attempts":3,"check_interval":1,"retry_interval":1,"active_checks_enabled":true,"passive_checks_enabled":true,"check_period":"24x7","parallelize_check":true,"obsess":false,"check_freshness":false,"event_handler_enabled":true,"flap_detection_enabled":true,"process_perf_data":true,"retain_status_information":true,"retain_nonstatus_information":true,"notification_interval":0,"notification_period":"24x7","notification_options":["c","f","r","s","u","w"],"notifications_enabled":true,"hostgroup_name":"","display_name":"","servicegroups":[],"freshness_threshold":"","event_handler":"","event_handler_args":"","low_flap_threshold":"","high_flap_threshold":"","flap_detection_options":[],"first_notification_delay":"","contacts":[],"contact_groups":[],"notes":"","notes_url":"","action_url":"","icon_image":"","icon_image_alt":"","obsess_over_service":false}' 'https://10.128.255.4/api/config/service' -u 'administrator:OP5POC'
	//	curl -H 'content-type: application/json' -d  '{"host_name":"rnc04-ra008","service_description":"IF 8_ gre Errors","check_command":"check_snmpif_errors_v2","check_command_args":"'n3gT1vGh057r1d3r'!8!1.5!2.5","stalking_options":["n"],"template":"default-service","register":true,"file_id":"etc\/services.cfg","is_volatile":false,"max_check_attempts":3,"check_interval":1,"retry_interval":1,"active_checks_enabled":true,"passive_checks_enabled":true,"check_period":"24x7","parallelize_check":true,"obsess":false,"check_freshness":false,"event_handler_enabled":true,"flap_detection_enabled":true,"process_perf_data":true,"retain_status_information":true,"retain_nonstatus_information":true,"notification_interval":0,"notification_period":"24x7","notification_options":["c","f","r","s","u","w"],"notifications_enabled":true,"hostgroup_name":"","display_name":"","servicegroups":[],"freshness_threshold":"","event_handler":"","event_handler_args":"","low_flap_threshold":"","high_flap_threshold":"","flap_detection_options":[],"first_notification_delay":"","contacts":[],"contact_groups":[],"notes":"","notes_url":"","action_url":"","icon_image":"","icon_image_alt":"","obsess_over_service":false}' 'https://10.128.255.4/api/config/service' -u 'administrator:OP5POC'
	//	curl -H 'content-type: application/json' -d '{"host_name":"rnc04-ra008","service_description":"IF 8_ gre Status","check_command":"check_snmpif_status_v2","check_command_args":"'n3gT1vGh057r1d3r'!8!c","stalking_options":["n"],"template":"default-service","register":true,"file_id":"etc\/services.cfg","is_volatile":false,"max_check_attempts":3,"check_interval":1,"retry_interval":1,"active_checks_enabled":true,"passive_checks_enabled":true,"check_period":"24x7","parallelize_check":true,"obsess":false,"check_freshness":false,"event_handler_enabled":true,"flap_detection_enabled":true,"process_perf_data":true,"retain_status_information":true,"retain_nonstatus_information":true,"notification_interval":0,"notification_period":"24x7","notification_options":["c","f","r","s","u","w"],"notifications_enabled":true,"hostgroup_name":"","display_name":"","servicegroups":[],"freshness_threshold":"","event_handler":"","event_handler_args":"","low_flap_threshold":"","high_flap_threshold":"","flap_detection_options":[],"first_notification_delay":"","contacts":[],"contact_groups":[],"notes":"","notes_url":"","action_url":"","icon_image":"","icon_image_alt":"","obsess_over_service":false}' 'https://10.128.255.4/api/config/service' -u 'administrator:OP5POC'

	// you might consider making this function return a bool that tells you if all the data was posted correctly or not
}
