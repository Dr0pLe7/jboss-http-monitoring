package main

import (
	"io/ioutil"
	"encoding/json"
	"os"
	"log"
)

type Config struct {
	Username string
	Password string
	ManagementUrl string
	ManagementRealm string
	Payload string
}

func checkError(e error) {
	if e != nil {
		log.Fatalf("Error: %s\n", e)
	}
}

func loadConfig(filename string) (Config, error) {
	var config Config
	configData, err := ioutil.ReadFile(filename)

	if err != nil {
		return config, err
	}

	if err = json.Unmarshal(configData, &config); err != nil {
		return config, err
	}

	return config, nil
}

func initLogging() *os.File {
	f, err := os.OpenFile("jboss-http-monitoring.log", os.O_CREATE|os.O_RDWR, 0666)
	checkError(err)

	// assign it to the standard logger
	log.SetOutput(f)

	return f
}
