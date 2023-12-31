## k8s-vulnDB-collector

This open source project collect data from k8s Vulnerability adviository and parse it to standard vulnerability doc in json format

### Example:

```json
{
      "id": "CVE-2023-2431",
      "created_at": "2023-06-15T14:42:32Z",
      "summary": "Bypass of seccomp profile enforcement ",
      "component": "github.com/kubernetes/kubelet",
      "description": "What happened?A security issue was discovered in Kubelet that allows pods to bypass the seccomp profile enforcement. This issue has been rated LOW (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N) (score: 3.4).If you have pods in your cluster that use localhost type for seccomp profile but specify an empty profile field, then you are affected by this issue. In this scenario, this vulnerability allows the pod to run in “unconfined” (seccomp disabled) mode. This bug affects Kubelet.How can we reproduce it (as minimally and precisely as possible)?This can be reproduced by creating a pod with following sample seccomp Localhost profile -https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#seccompprofile-v1-coreKubernetes version",
      "affected_version": [
        {
          "from": "1.27.0",
          "to": "1.27.0"
        },
        {
          "from": "1.26.0",
          "to": "1.26.0"
        },
        {
          "from": "1.25.0",
          "to": "1.25.0"
        },
        {
          "from": "0.0.0",
          "to": "1.24.13"
        }
      ],
      "fixed_version": [
        {
          "fixed": "1.27.2"
        },
        {
          "fixed": "1.26.5"
        },
        {
          "fixed": "1.25.10"
        },
        {
          "fixed": "1.24.14"
        }
      ],
      "urls": [
        "https://github.com/kubernetes/kubernetes/issues/118690",
        "https://www.cve.org/cverecord?id=CVE-2023-2431"
      ],
      "cvss": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N",
      "severity": "Low",
      "score": 3.4
    }
```