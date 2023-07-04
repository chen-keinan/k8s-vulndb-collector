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
	data = `CVSS Rating:

In typical clusters: medium (5.4) [CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)

In clusters where API server insecure port has not been disabled: high (8.8) [CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

A security issue was discovered in kube-proxy which allows adjacent hosts to reach TCP and UDP services bound to 127.0.0.1 running on the node or in the node's network namespace. For example, if a cluster administrator runs a TCP service on a node that listens on 127.0.0.1:1234, because of this bug, that service would be potentially reachable by other hosts on the same LAN as the node, or by containers running on the same node as the service. If the example service on port 1234 required no additional authentication (because it assumed that only other localhost processes could reach it), then it could be vulnerable to attacks that make use of this bug.

The Kubernetes API Server's default insecure port setting causes the API server to listen on 127.0.0.1:8080 where it will accept requests without authentication. Many Kubernetes installers explicitly disable the API Server's insecure port, but in clusters where it is not disabled, an attacker with access to another system on the same LAN or with control of a container running on the master may be able to reach the API server and execute arbitrary API requests on the cluster. This port is deprecated, and will be removed in Kubernetes v1.20.

### Am I vulnerable?

You may be vulnerable if:

- You are running a vulnerable version (see below)
- Your cluster nodes run in an environment where untrusted hosts share the same layer 2 domain (i.e. same LAN) as nodes
- Your cluster allows untrusted pods to run containers with CAP_NET_RAW (the Kubernetes default is to allow this capability).
- Your nodes (or hostnetwork pods) run any localhost-only services which do not require any further authentication. To list services that are potentially affected, run the following commands on nodes:
    - lsof +c 15 -P -n -i4TCP@127.0.0.1 -sTCP:LISTEN
    - lsof +c 15 -P -n -i4UDP@127.0.0.1

    On a master node, an lsof entry like this indicates that the API server may be listening with an insecure port:

COMMAND        PID  USER FD   TYPE DEVICE SIZE/OFF NODE NAME
kube-apiserver 123  root  7u  IPv4  26799      0t0  TCP 127.0.0.1:8080 (LISTEN)

#### Affected Versions
- kubelet/kube-proxy v1.18.0-1.18.3
- kubelet/kube-proxy v1.17.0-1.17.6
- kubelet/kube-proxy <=1.16.10

### How do I mitigate this vulnerability?
Prior to upgrading, this vulnerability can be mitigated by manually adding an iptables rule on nodes. This rule will reject traffic to 127.0.0.1 which does not originate on the node.

 iptables -I INPUT --dst 127.0.0.0/8 ! --src 127.0.0.0/8 -m conntrack ! --ctstate RELATED,ESTABLISHED,DNAT -j DROP

Additionally, if your cluster does not already have the API Server insecure port disabled, we strongly suggest that you disable it. Add the following flag to your kubernetes API server command line: --insecure-port=0
#### Detection
Packets on the wire with an IPv4 destination in the range 127.0.0.0/8 and a layer-2 destination MAC address of a node may indicate that an attack is targeting this vulnerability.

#### Fixed Versions
Although the issue is caused by kube-proxy, the current fix for the issue is in kubelet (although future versions may have the fix in kube-proxy instead). We recommend  updating both kubelet and kube-proxy to be sure the issue is addressed.

The following versions contain the fix:
  
- kubelet/kube-proxy master - fixed by #91569
- kubelet/kube-proxy v1.18.4+ - fixed by #92038
- kubelet/kube-proxy v1.17.7+ - fixed by #92039
- kubelet/kube-proxy v1.16.11+ - fixed by #92040

To upgrade, refer to the documentation: https://kubernetes.io/docs/tasks/administer-cluster/cluster-management/#upgrading-a-cluster


## Additional Details
This issue was originally raised in issue #90259 which details how the kube-proxy sets net.ipv4.conf.all.route_localnet=1 which causes the system not to reject traffic to localhost which originates on other hosts.

IPv6-only services that bind to a localhost address are not affected. 

There may be additional attack vectors possible in addition to those fixed by #91569 and its cherry-picks. For those attacks to succeed, the target service would need to be UDP and the attack could only rely upon sending UDP datagrams since it wouldn't receive any replies. Finally, the target node would need to have reverse-path filtering disabled for an attack to have any effect. Work is ongoing to determine whether and how this issue should be fixed. See #91666 for up-to-date status on this issue.  

#### Acknowledgements
This vulnerability was reported by János Kövér, Ericsson with additional impacts reported by Rory McCune, NCC Group and Yuval Avrahami and Ariel Zelivansky, Palo Alto Networks.

/area security
/kind bug
/committee product-security
/sig network
/sig node
/area kubelet
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
