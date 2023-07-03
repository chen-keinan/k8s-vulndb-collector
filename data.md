CVSS Rating: 5.6 CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N (Medium)

 In Kubernetes clusters using VSphere as a cloud provider, with a logging level set to 4 or above, VSphere cloud credentials will be leaked in the cloud controller manager's log.

 ### Am I vulnerable?
 If you are using VSphere as a cloud provider, have verbose logging enabled, and an attacker can access cluster logs, then you may be vulnerable to this.

 #### Affected Versions
 kube-controller-manager v1.19.0 - v1.19.2

 #### How do I mitigate this vulnerability?
 Do not enable verbose logging in production, limit access to cluster logs.

 #### Fixed Versions
 v1.19.3

 To upgrade, refer to the documentation: https://kubernetes.io/docs/tasks/administer-cluster/cluster-management/#upgrading-a-cluster

 ### Acknowledgements
 This vulnerability was reported by: Kaizhe Huang (derek0405)

 /area security
 /kind bug
 /committee product-security