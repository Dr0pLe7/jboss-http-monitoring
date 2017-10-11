package main

import (
	"flag"
	"net/http"
	"fmt"
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

	digestRequest("GET", config.ManagementUrl, config.Username, config.Password, []byte(config.Payload))
}

