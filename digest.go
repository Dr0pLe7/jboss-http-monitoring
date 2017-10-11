package main

import (
	url2 "net/url"
	"log"
	"crypto/md5"
	"bytes"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
	"fmt"
	"io/ioutil"
)

var (
	digestRegexp = regexp.MustCompile(`^Digest (?P<headers>.*)$`)
)

func parseUri(urlStr string) (string, error){
	url, err := url2.Parse(urlStr)
	return url.Path, err
}

func md5sum(bytes []byte) string {
	hasher := md5.New()
	hasher.Write(bytes)
	return hex.EncodeToString(hasher.Sum(nil))
}

func getAuthResponse(method string, url string, realm string, username string, password string, nonce string) string {
	uri, err := parseUri(url)
	checkError(err)

	var ha1Buffer, ha2Buffer, responseBuffer bytes.Buffer

	ha1Buffer.WriteString(username)
	ha1Buffer.WriteString(":")
	ha1Buffer.WriteString(realm)
	ha1Buffer.WriteString(":")
	ha1Buffer.WriteString(password)

	ha1 := md5sum(ha1Buffer.Bytes())
	log.Print("ha1: ", ha1)

	ha2Buffer.WriteString(method)
	ha2Buffer.WriteString(":")
	ha2Buffer.WriteString(uri)

	ha2 := md5sum(ha2Buffer.Bytes())
	log.Print("ha2: ", ha2)

	responseBuffer.WriteString(ha1)
	responseBuffer.WriteString(":")
	responseBuffer.WriteString(nonce)
	responseBuffer.WriteString(":")
	responseBuffer.WriteString(ha2)

	return md5sum(responseBuffer.Bytes())
}

func parseHeaders(headerString string) map[string]string {
	headers := strings.Split(headerString, ",")

	headerMap := make(map[string]string)

	for _, header := range headers {
		header = strings.TrimSpace(header)
		header = strings.Replace(header, "\"", "", -1)
		splitIndex := strings.Index(header, "=")

		if (splitIndex > 0){
			headerMap[header[:splitIndex]] = header[(splitIndex + 1):]
		} else {
			log.Printf("Invalid field format: %s\n", header)
		}
	}

	return headerMap
}

func getAuthHeaders(resp http.Response) map[string]string{
	if len(resp.Header["Www-Authenticate"]) > 0 {
		authHeader := resp.Header["Www-Authenticate"][0]
		matches := digestRegexp.FindStringSubmatch(authHeader)
		headersMatch := matches[1]
		headers := parseHeaders(headersMatch)

		return headers
	} else {
		return nil
	}
}

func digestRequest(method string, url string, username string, password string, payload []byte){
	log.Print("digestRequest")

	uri, err := parseUri(url)
	checkError(err)

	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	checkError(err)

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		log.Printf("Recieved status code '%v' auth skipped", resp.StatusCode)
	} else {
		authHeaders := getAuthHeaders(*resp)

		log.Printf("authHeaders: %#v\n", authHeaders)

		// We are only going to do what we know the JBoss digest implementation to be, namely MD5/auth
		authResponse := getAuthResponse(method, url, authHeaders["realm"], username, password, authHeaders["nonce"])

		authorizationHeader := fmt.Sprintf(
			"Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\" qop=\"auth\", ",
					username,
					authHeaders["realm"],
					authHeaders["nonce"],
					uri,
					authResponse)

		if authHeaders["opaque"] != "" {
			authorizationHeader += fmt.Sprintf(", opaque=\"%s\"", authHeaders["opaque"])
		}

		req, err = http.NewRequest(method, url, bytes.NewBuffer(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", authorizationHeader)

		client := &http.Client{}
		resp, err := client.Do(req)
		checkError(err)
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, err := ioutil.ReadAll(resp.Body)

			checkError(err)

			log.Printf("body: %#v\n", string(body))
		} else {
			log.Printf("Status code: %d\n", resp.StatusCode)
		}
	}
}
