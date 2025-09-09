# OpenShift Troubleshooting Cheatsheet

A comprehensive reference for diagnosing application outages, resource pressure, and platform-level issues in OpenShift. Designed for audit-grade workflows and semantic clarity.

---

## Application Outage Diagnostics

### Pod & Deployment Health
```bash
oc get pods -n <namespace>
oc get pods -n <namespace> -o wide
oc describe pod <pod-name> -n <namespace>
oc logs <pod-name> -n <namespace> --all-containers=true
oc logs <pod-name> -n <namespace> --previous
oc logs <pod-name> -n <namespace> -c <container>
oc get deployment -n <namespace>
oc describe deployment <deployment-name> -n <namespace>
oc rollout status deployment/<deployment-name> -n <namespace>
oc rollout history deployment/<deployment-name> -n <namespace>
oc rollout undo deployment/<deployment-name> -n <namespace>
```

### CrashLoopBackOff / Startup Failures
```bash
oc get pod <pod-name> -n <namespace> -o jsonpath='{.status.containerStatuses[*].lastState.terminated.reason}'
oc get pod <pod-name> -n <namespace> -o jsonpath='{.status.containerStatuses[*].restartCount}'
oc logs <pod-name> -n <namespace> --previous --all-containers=true
oc get events -n <namespace> --sort-by=.lastTimestamp | grep -Ei "(Liveness|Readiness|Back-off|Failed|CrashLoop)"
oc describe pod <pod-name> -n <namespace>  # Check probes, init containers
```

### Networking & Service Reachability
```bash
oc get svc -n <namespace>
oc describe svc <svc-name> -n <namespace>
oc get endpoints <svc-name> -n <namespace>
oc get endpointslice -n <namespace> | grep <svc-name>
oc get route -n <namespace>
oc describe route <route-name> -n <namespace>
oc get route <route-name> -n <namespace> -o jsonpath='{.status.ingress[*].conditions[?(@.type=="Admitted")].status}'
oc rsh <pod-name> -n <namespace>
oc exec -it <pod-name> -n <namespace> -- curl -vk http://<svc-name>:<port>
oc exec -it <pod-name> -n <namespace> -- curl -vk https://<route-host>
```

### Secrets, ConfigMaps, and Mounts
```bash
oc get secrets -n <namespace>
oc describe secret <name> -n <namespace>
oc get secret <name> -n <namespace> -o jsonpath='{.type}\n'
oc get configmap -n <namespace>
oc describe configmap <name> -n <namespace>
oc get configmap <name> -n <namespace> -o yaml
```

### Persistent Volume & Storage
```bash
oc get pvc -n <namespace>
oc describe pvc <name> -n <namespace>
oc get pv
oc describe pv <name>
```

### Resource Limits & Quotas
```bash
oc get events -n <namespace> --sort-by=.lastTimestamp
oc describe pod <pod-name> -n <namespace>
oc get resourcequota -n <namespace>
oc describe resourcequota <name> -n <namespace>
oc get limitranges -n <namespace>
oc describe limitranges <name> -n <namespace>
```

### RBAC & ServiceAccount Issues
```bash
oc get serviceaccount -n <namespace>
oc describe serviceaccount <name> -n <namespace>
oc get rolebinding -n <namespace>
oc describe rolebinding <name> -n <namespace>
oc auth can-i get pods -n <namespace>
oc adm policy who-can get pods -n <namespace>
```

## CPU & Memory Troubleshooting

### Cluster-Level Metrics
```bash
oc adm top nodes
oc adm top pods --all-namespaces
```

### Pod-Level Resource Analysis
```bash
oc get pod <pod-name> -n <namespace> -o jsonpath='{.spec.containers[*].resources}'
oc describe pod <pod-name> -n <namespace>  # Look for OOMKilled or throttling
oc adm top pods -n <namespace>
```

### Deployment & HPA Checks
```bash
oc get deployment <name> -n <namespace> -o yaml | grep -A5 resources:
oc get hpa -n <namespace>
oc describe hpa <name> -n <namespace>
```

### Node Pressure & Eviction
```bash
oc get nodes -o wide
oc describe node <node-name>  # Check MemoryPressure, DiskPressure
oc get events --all-namespaces --sort-by=.lastTimestamp | grep -i "evicted"
```

### LimitRanges & Quotas
```bash
oc get limitranges -n <namespace>
oc describe limitranges <name> -n <namespace>
oc get resourcequota -n <namespace>
oc describe resourcequota <name> -n <namespace>
```

### Debugging with Ephemeral Pods
```bash
oc run debug --image=busybox -it --rm --restart=Never -- bash
# Inside pod:
top
free -m
cat /proc/meminfo
cat /proc/cpuinfo

# Node debug (read-only host namespace)
oc debug node/<node-name> -- chroot /host
```

## Cluster-Level Diagnostics

### Cluster Operators & Version
```bash
oc get clusterversion
oc get clusteroperators
oc adm release info
```

### Must-Gather & Inspect
```bash
oc adm must-gather
oc adm inspect ns/<namespace>
oc adm inspect clusteroperator/<name>
```

### StorageClass & Volume Issues
```bash
oc get storageclass
oc describe storageclass <name>
oc get volumeattachments.storage.k8s.io
oc get csinodes.storage.k8s.io
```

### Identity & Authentication
```bash
oc whoami
oc whoami --show-context
oc auth can-i '*' '*' --all-namespaces
oc get oauth cluster
oc describe oauth cluster
oc get users
oc get groups
oc describe user <username>
```

### Network & DNS Operators
```bash
oc get network.operator cluster -o yaml | head -n 50
oc describe network.operator cluster
oc get dns.operator cluster -o yaml | head -n 50
oc describe dns.operator cluster
```

### CRDs & Operator Logs
```bash
oc get crds
oc describe crd <name>
oc logs -n openshift-ingress-operator <pod-name>
oc logs -n openshift-image-registry <pod-name>
```

## Ingress Operator Troubleshooting
```bash
# Operator status
oc get clusteroperator ingress
oc describe clusteroperator ingress

# Ingress controller
oc get ingresscontroller -n openshift-ingress-operator
oc describe ingresscontroller default -n openshift-ingress-operator
oc get ingresscontroller default -n openshift-ingress-operator -o jsonpath='{.spec.defaultCertificate.name}\n'

# Router pods and logs
oc get pods -n openshift-ingress
oc logs -n openshift-ingress -l ingresscontroller.operator.openshift.io/deployment-ingresscontroller=default --tail=200

# Services and endpoints
oc get svc -n openshift-ingress-operator
oc get endpoints -n openshift-ingress-operator

# Routes
oc get route -A -o wide | grep ingress

# Default cert secret (if set)
oc get secret router-certs-default -n openshift-ingress -o yaml

# Must-gather for ingress
oc adm must-gather -- /usr/bin/gather ingress
```

## Additional Diagnostics

### Pod Lifecycle & Force Cleanup
```bash
oc get pods -n <namespace> --field-selector=status.phase!=Running
oc get pods -n <namespace> --field-selector=status.reason=Evicted
oc delete pod <pod-name> -n <namespace> --grace-period=0 --force
```

### DNS & NetworkPolicy Checks
```bash
oc exec -it <pod-name> -n <namespace> -- nslookup <target>
oc exec -it <pod-name> -n <namespace> -- dig <target> || true
oc get networkpolicy -n <namespace>
oc describe networkpolicy <name> -n <namespace>
```

### Helm & OperatorHub
```bash
oc get helmreleases -n <namespace>
oc describe helmrelease <name> -n <namespace>
oc get operatorhub
oc describe operatorhub
```

### Image Registry & Build Failures
```bash
oc get configs.imageregistry.operator.openshift.io cluster
oc describe configs.imageregistry.operator.openshift.io cluster
oc get imagestream -n <namespace>
oc describe imagestream <name> -n <namespace>
oc get buildconfig -n <namespace>
oc describe buildconfig <name> -n <namespace>
oc get builds -n <namespace>
oc describe build <name> -n <namespace>
oc logs build/<build-name> -n <namespace> --follow
```

### ClusterRoles & RoleBindings
```bash
oc get clusterroles
oc describe clusterrole <name>
oc adm policy who-can get secrets -n <namespace>
```

### Node-Level Pod Distribution
```bash
oc get pods -A -o wide | awk '{print $1, $2, $7}' | sort | uniq -c
```

## Miscellaneous

### Project Creation & Access
```bash
oc get projects
oc describe project <name>
```

### Certificate Expiry
```bash
oc get certificates
oc describe certificate <name>
# cert-manager (if installed)
oc get certificates.cert-manager.io -A
oc get orders.acme.cert-manager.io -A
oc get challenges.acme.cert-manager.io -A
oc describe challenge <name> -n <namespace>
oc describe order <name> -n <namespace>
```

## TLS Certificate Troubleshooting in OpenShift Routes

### Inspect Route TLS Configuration
```bash
oc get route <route-name> -n <namespace> -o yaml
```
Look for:
- `.spec.tls.termination` → edge, passthrough, or reencrypt
- `.spec.tls.certificate`, `.spec.tls.key`, `.spec.tls.caCertificate`

### Validate TLS Secret Used in Route
```bash
oc get secret <secret-name> -n <namespace>
oc describe secret <secret-name> -n <namespace>
```
Ensure:
- Type is `kubernetes.io/tls`
- Contains valid `tls.crt` and `tls.key` PEM-encoded values

### Test TLS Handshake from Client
```bash
openssl s_client -connect <route-host>:443 -servername <route-host>
openssl s_client -connect <route-host>:443 -servername <route-host> -tls1_2
```
Check for:
- Certificate chain validity
- Cipher negotiation
- TLS version compatibility

### Check IngressController TLS Settings
```bash
oc get ingresscontroller default -n openshift-ingress-operator -o yaml
```
Look for:
- `spec.tlsSecurityProfile` → `Old`, `Intermediate`, `Modern`, or `custom`
- Cipher suite restrictions
- Minimum TLS version

### Must-Gather for TLS/Ingress
```bash
oc adm must-gather -- /usr/bin/gather ingress
```
This collects ingress controller logs, TLS profiles, and route configs for deep analysis.

### Common TLS Route Issues
- Misconfigured termination type: `passthrough` requires the app to handle TLS directly.
- Missing or invalid cert/key in secret: PEM format must be correct.
- Client cipher mismatch: Especially in FIPS-enabled clusters.
- Expired or mismatched CN/SAN: Use `openssl x509 -in tls.crt -text -noout` to inspect.

---

**Author:** Abdul Rahman Samy  
**Purpose:** Modular, audit-grade troubleshooting for OpenShift incidents  
**Last Updated:** $(date +"%Y-%m-%d")