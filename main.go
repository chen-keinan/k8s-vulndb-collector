package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/chen-keinan/k8s-vulndb-collector/pkg/cve"
)

const (
	k8svulnDBURL = "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"
)

func main() {
	response, err := http.Get(k8svulnDBURL)
	if err != nil {
		panic(err.Error())
	}
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		panic(err.Error())
	}
	vulnDB, err := cve.ParseVulneDB(bodyBytes)
	if err != nil {
		panic(err.Error())
	}
	vulnDBBytes, err := json.Marshal(vulnDB)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println(string(vulnDBBytes))
}
