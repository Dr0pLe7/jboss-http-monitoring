package main

import (
	"flag"
	"log"
	"encoding/json"
)

var (
	configFile = flag.String("c", "", "location of configuration json file")
)

func main(){
	flag.Parse()
	logFile := initLogging()
	defer logFile.Close()
	config, err := loadConfig(*configFile)
	checkError(err)

	body, err := digestRequest("GET", config.ManagementUrl, config.Username, config.Password, []byte(config.Payload))

	checkError(err)
	jsonBody := make(map[string]interface{})

	err = json.Unmarshal(body, &jsonBody)
	checkError(err)

	log.Printf("body: %#v\n", jsonBody)
}

