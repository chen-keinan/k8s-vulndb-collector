package cve

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ParseVulneDB(t *testing.T) {
	b, err := os.ReadFile("./testdata/k8s-db.json")
	assert.NoError(t, err)
	kvd, err := ParseVulneDB(b)
	assert.NoError(t, err)
	gotVulnDB, err := json.Marshal(kvd)
	//os.WriteFile("expected-vulndb.json",gotVulnDB,777)
	assert.NoError(t, err)
	wantVulnDB, err := os.ReadFile("./testdata/expected-vulndb.json")
	assert.Equal(t, string(wantVulnDB), string(gotVulnDB))
}
