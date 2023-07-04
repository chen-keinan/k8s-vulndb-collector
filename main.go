package main

import (
	"fmt"
	"os"

	"github.com/chen-keinan/k8s-vulndb-collector/pkg/cve"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
)

const (
	data = `CVSS Rating: [CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L) (5.1, medium)

A security issue was discovered in kube-apiserver that allows an aggregated API server to redirect client traffic to any URL.  This could lead to the client performing unexpected actions as well as forwarding the client's API server credentials to third parties.

This issue has been rated medium and assigned CVE-2022-3172

### Am I vulnerable?

All Kubernetes clusters with the following versions that are running aggregated API servers are impacted.  To identify if you have aggregated API servers configured, run the following command:

shell
kubectl get apiservices.apiregistration.k8s.io -o=jsonpath='{range .items[?(@.spec.service)]}{.metadata.name}{"\n"}{end}


#### Affected Versions

- kube-apiserver v1.25.0
- kube-apiserver v1.24.0 - v1.24.4
- kube-apiserver v1.23.0 - v1.23.10
- kube-apiserver v1.22.0 - v1.22.13
- kube-apiserver <= v1.21.14

### How do I mitigate this vulnerability?

Aside from upgrading, no direct mitigation is available.

Aggregated API servers are a trusted part of the Kubernetes control plane, and configuring them is a privileged administrative operation.  Ensure that only trusted cluster administrators are allowed to create or modify APIService configuration, and follow security best practices with any aggregated API servers that may be in use.

#### Fixed Versions

- kube-apiserver v1.25.1 - fixed by #112330
- kube-apiserver v1.24.5 - fixed by #112331
- kube-apiserver v1.23.11 - fixed by #112358
- kube-apiserver v1.22.14 - fixed by #112359

**Fix impact:** The fix blocks all 3XX responses from aggregated API servers by default.  This may disrupt an aggregated API server that relies on redirects as part of its normal function.  If all current and future aggregated API servers are considered trustworthy and redirect functionality is required, set the --aggregator-reject-forwarding-redirect Kubernetes API server flag to false to restore the previous behavior.

To upgrade, refer to the documentation: https://kubernetes.io/docs/tasks/administer-cluster/cluster-upgrade

### Detection

Kubernetes audit log events indicate the HTTP status code sent to the client via the responseStatus.code field.  This can be used to detect if an aggregated API server is redirecting clients.

If you find evidence that this vulnerability has been exploited, please contact security@kubernetes.io

#### Acknowledgements

This vulnerability was reported by Nicolas Joly & Weinong Wang @weinong from Microsoft.

The issue was fixed and coordinated by Di Jin @jindijamie @enj @liggitt @lavalamp @deads2k and @puerco.

/area security
/kind bug
/committee security-response
/label official-cve-feed
/sig api-machinery
/area apiserver
/triage accepted
`
)

func main() {
	gm := goldmark.New(
		goldmark.WithExtensions(
			extension.GFM, // GitHub flavoured markdown.
		),
		goldmark.WithParserOptions(
			parser.WithAttribute(), // Enables # headers {#custom-ids}.
		),
		goldmark.WithRenderer(cve.NewRenderer()),
	)
	amendedDoc := cve.AmendCveDoc(data)
	fmt.Println(amendedDoc)
	err := gm.Convert([]byte(amendedDoc), os.Stdout)
	if err != nil {
		panic(err.Error())
	}

}
