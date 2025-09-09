# OpenShift Diagnostics Collector

This script is a comprehensive, expert-level troubleshooting tool designed to collect a wide range of diagnostic information from an OpenShift cluster. It's built to be self-contained and robust, making it ideal for use in hardened or air-gapped environments.

The primary goal is to **quickly** gather critical data during troubleshooting incidents, identify common configuration issues across infrastructure, applications, and security, and provide a detailed snapshot of the cluster's health that can be archived and analyzed offline.

## ✨ Features

  * **High-Performance Collection**: Utilizes bulk API calls to gather data rapidly, ensuring minimal delay during critical incidents.
  * **Advanced Storage Diagnostics**: Actively checks PersistentVolumeClaim (PVC) status and Container Storage Interface (CSI) driver health to identify storage bottlenecks and failures.
  * **Security & RBAC Auditing**: Scans for potential Security Context Constraint (SCC) violations (e.g., privileged pods) and detects RBAC integrity issues like broken role bindings.
  * **Detailed TLS/Certificate Validation**: Performs in-depth checks on OpenShift Routes, including certificate expiration, SAN/CN matching, key integrity, and chain validation.
  * **Degraded Component Detection**: Automatically scans for and exports the manifests of degraded resources across the cluster, including failing pods, deployments, PVCs, and cluster operators.
  * **Controlled Log Collection**: Gathers the last 1000 lines of pod logs to capture recent events without downloading excessively large log files.
  * **Health Tagging**: Analyzes each namespace and tags its health as `healthy`, `degraded`, or `critical`.
  * **Multiple Output Formats**:
      * Live, color-coded logging to the console.
      * A structured directory containing all collected raw data.
      * A machine-readable `summary.json` file for automation.
      * A human-readable summary report printed at the end.
  * **Best-Effort `must-gather`**: Integrates a call to `oc adm must-gather` to supplement the script's findings with the official Red Hat diagnostic tool.

-----

## 📋 prerequisites

Before running the script, ensure the following requirements are met:

1.  **`oc` CLI**: The OpenShift Command-Line Interface (`oc`) must be installed and configured to connect to the target cluster.
2.  **Permissions**: You must be logged in as a user with sufficient permissions to read resources across the cluster. The `cluster-reader` role is typically sufficient for most checks, but some security checks may benefit from higher privileges.
3.  **Required Tools**: The following command-line utilities must be present in your `PATH`:
      * `oc`
      * `openssl`
      * `awk`
      * `grep`
      * `sed`
      * `base64`
      * `tar`

-----

## 🚀 Usage

1.  Make the script executable:

    ```bash
    chmod +x openshift_diagnostics_v9.0.sh
    ```

2.  Run the script. You have two options:

      * **Scan all namespaces in the cluster:**

        ```bash
        ./openshift_diagnostics_v9.0.sh
        ```

      * **Scan a single, specific namespace:**

        ```bash
        ./openshift_diagnostics_v9.0.sh my-problem-namespace
        ```

-----

## 📁 Understanding the Output

The script creates a timestamped directory and a compressed archive (`.tar.gz`) containing all results.

### Directory Structure

The output directory contains bulk data files that are fast to generate and easy to search.

The output directory contains bulk data files that are fast to generate and easy to search. The structure for each namespace will include a `_list.txt` (for summary views) and `_describe.txt` (for detailed views) for each major resource type.

```
openshift_diagnostics_20250909_042800/
├── cluster_ingress/
├── clusteroperators.txt
├── degraded_manifests/          # YAMLs for degraded components (Pods, Deployments, PVCs, RBAC, etc.)
├── diagnostic.log               # A log of the script's own execution and findings
├── my-app-prod/                 # Directory for a specific namespace
│   ├── deployments_list.txt     # 'oc get deployment -o wide' output
│   ├── deployments_describe.txt # 'oc describe deployment' output
│   ├── pods_list.txt            # 'oc get pods -o wide' output
│   ├── pods_describe.txt        # 'oc describe pods' output
│   ├── statefulsets_list.txt
│   ├── statefulsets_describe.txt
│   ├── services_list.txt
│   ├── services_describe.txt
│   ├── rbac_summary.txt         # Summary of RoleBindings and ServiceAccounts
│   ├── events.txt
│   ├── pod_logs_my-pod-123.txt  # Logs for a specific pod (last 1000 lines)
│   ├── status.txt               # Health tag (healthy, degraded, critical)
│   └── tls_routes/              # TLS/Route validation details
├── must-gather/
└── summary.json
```

### Final Summary Report

A summary is printed to the console for a quick overview of the cluster's health.

```
======================= OpenShift Diagnostics Summary ======================
Timestamp                     : 2025-09-09 04:28:28
Output Directory              : openshift_diagnostics_20250909_042800
Archive                       : openshift_diagnostics_20250909_042800.tar.gz

Namespaces scanned            : 42
Degraded namespaces           : 3
Critical namespaces           : 1
Total WARN logs               : 18
Average namespace elapsed     : 5s
Max severity                  : 90/100
Total runtime (mm:ss)         : 03:15

Degraded Components:
  - clusteroperator_authentication
  - deployment_my-app-prod_frontend
  - pvc_storage-ns_db-claim-1
  - scc_pod_default_privileged-pod

JSON Summary                  : openshift_diagnostics_20250909_042800/summary.json
==================================================================================
```

### How to Investigate

1.  **Start with the Summary Report**: The final console output gives you the highest-level view. Note the `Degraded Components` list, which now includes storage and security issues.
2.  **Examine Degraded Manifests**: Check the `degraded_manifests/` directory to analyze the configuration of failing resources. This is your primary location for deep analysis of specific problems found by the script.
3.  **Drill Down into Namespaces**: For a problematic namespace, inspect its directory.
      * Review `pods_describe.txt` and `events.txt` for errors.
      * Check the new `rbac_summary.txt` file for a clear overview of permissions.
      * Review the relevant `pod_logs_*.txt` file for application errors.
4.  **Review the `diagnostic.log`**: This file contains all warnings generated by the script, providing a timeline of findings, including storage, RBAC, and SCC warnings.