package main

import (
	//"fmt"
	"os"

	"github.com/chen-keinan/k8s-vulndb-collector/doc"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
)

const (
	data = `### What happened?
A security issue was discovered in Kubelet that allows pods to bypass the seccomp profile enforcement. This issue has been rated LOW ([CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N)) (score: 3.4).
If you have pods in your cluster that use [localhost type](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#seccompprofile-v1-core) for seccomp profile but specify an empty profile field, then you are affected by this issue. In this scenario, this vulnerability allows the pod to run in “unconfined” (seccomp disabled) mode. This bug affects Kubelet.
### How can we reproduce it (as minimally and precisely as possible)?
This can be reproduced by creating a pod with following sample seccomp Localhost profile - 

localhostProfile: ""

https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#seccompprofile-v1-core
### Kubernetes version
#### Affected Versions
- v1.27.0 - v1.27.1
- v1.26.0 - v1.26.4
- v1.25.0 - v1.25.9
- <= v1.24.13
#### Fixed Versions
- v1.27.2
- v1.26.5
- v1.25.10
- V1.24.14
### Anything else we need to know?
How do I remediate this vulnerability?
To remediate this vulnerability you should upgrade your Kubelet to one of the below mentioned versions.
Acknowledgements
This vulnerability was reported by Tim Allclair, and fixed by Craig Ingram.
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
	//amendedDoc := doc.AmendDoc(data)
	//fmt.Println(amendedDoc)
	err := gm.Convert([]byte(data), os.Stdout)
	if err != nil {
		panic(err.Error())
	}

}
