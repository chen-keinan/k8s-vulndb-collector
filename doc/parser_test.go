package doc

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ParseVulneDB(t *testing.T) {
	b, err := os.ReadFile("./testdata/k8s-db.json")
	assert.NoError(t, err)
	kvd, err := ParseVulneDB(b)
	assert.NoError(t, err)
	b, err = json.Marshal(kvd)
	assert.NoError(t, err)
	fmt.Println(string(b))
}
