package main

import (
	"os"

	"github.com/chen-keinan/k8s-vulndb-collector/doc"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
)

const (
	data = `### CVE-2023-2727: Bypassing policies imposed by the ImagePolicyWebhook admission plugin
CVSS Rating: [CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N)

A security issue was discovered in Kubernetes where users may be able to launch containers using images that are restricted by ImagePolicyWebhook when using ephemeral containers. Kubernetes clusters are only affected if the ImagePolicyWebhook admission plugin is used together with ephemeral containers.

### Am I vulnerable?
Clusters are impacted by this vulnerability if all of the following are true:

1. The ImagePolicyWebhook admission plugin is used to restrict use of certain images
2. Pods are using ephemeral containers.

### Affected Versions

- kube-apiserver v1.27.0 - v1.27.2
- kube-apiserver v1.26.0 - v1.26.5
- kube-apiserver v1.25.0 - v1.25.10
- kube-apiserver <= v1.24.14

### How do I mitigate this vulnerability?
This issue can be mitigated by applying the patch provided for the kube-apiserver component. This patch prevents ephemeral containers from using an image that is restricted by ImagePolicyWebhook. 

Note: Validation webhooks (such as [Gatekeeper](https://open-policy-agent.github.io/gatekeeper-library/website/validation/allowedrepos/) and [Kyverno](https://kyverno.io/policies/other/allowed-image-repos/allowed-image-repos/)) can also be used to enforce the same restrictions.

### Fixed Versions

- kube-apiserver v1.27.3
- kube-apiserver v1.26.6
- kube-apiserver v1.25.11
- kube-apiserver v1.24.15

### Detection
Pod update requests using an ephemeral container with an image that should have been restricted by an ImagePolicyWebhook will be captured in API audit logs. You can also use kubectl get pods to find active pods with ephemeral containers running an image that should have been restricted in your cluster with this issue.

### Acknowledgements
This vulnerability was reported by Stanislav Láznička, and fixed by Rita Zhang.

### CVE-2023-2728: Bypassing enforce mountable secrets policy imposed by the ServiceAccount admission plugin
CVSS Rating: [CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N)

A security issue was discovered in Kubernetes where users may be able to launch containers that bypass the mountable secrets policy enforced by the ServiceAccount admission plugin when using ephemeral containers. The policy ensures pods running with a service account may only reference secrets specified in the service account’s secrets field. Kubernetes clusters are only affected if the ServiceAccount admission plugin and the kubernetes.io/enforce-mountable-secrets annotation are used together with ephemeral containers.

### Am I vulnerable?
Clusters are impacted by this vulnerability if all of the following are true:

1. The ServiceAccount admission plugin is used. Most cluster should have this on by default as recommended in [https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#serviceaccount](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#serviceaccount)
2. The kubernetes.io/enforce-mountable-secrets annotation is used by a service account. This annotation is not added by default.
3. Pods are using ephemeral containers.

### Affected Versions

- kube-apiserver v1.27.0 - v1.27.2
- kube-apiserver v1.26.0 - v1.26.5
- kube-apiserver v1.25.0 - v1.25.10
- kube-apiserver <= v1.24.14

### How do I mitigate this vulnerability?
This issue can be mitigated by applying the patch provided for the kube-apiserver component. The patch prevents ephemeral containers from bypassing the mountable secrets policy enforced by the ServiceAccount admission plugin.

### Fixed Versions
- kube-apiserver v1.27.3
- kube-apiserver v1.26.6
- kube-apiserver v1.25.11
- kube-apiserver v1.24.15

### Detection
Pod update requests using an ephemeral container that exploits this vulnerability with unintended secret will be captured in API audit logs. You can also use kubectl get pods to find active pods with ephemeral containers running with a secret that is not referenced by the service account in your cluster.

### Acknowledgements
This vulnerability was reported by Rita Zhang, and fixed by Rita Zhang.

If you find evidence that this vulnerability has been exploited, please contact [security@kubernetes.io](mailto:security@kubernetes.io)

/area security
/kind bug
/committee security-response
/label official-cve-feed
/sig auth
/area apiserver
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
		goldmark.WithRenderer(doc.NewRenderer()),
	)

	err := gm.Convert([]byte(data), os.Stdout)
	if err != nil {
		panic(err.Error())
	}

}
