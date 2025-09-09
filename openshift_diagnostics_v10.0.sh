#!/bin/bash

# OpenShift Troubleshooting Collector with Extended Diagnostics (Air-gapped hardened)
# Author: Abdul Rahman Samy

# ---------------------------
# Runtime & prerequisites
# ---------------------------
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="openshift_diagnostics_$TIMESTAMP"
ARCHIVE_NAME="${OUTPUT_DIR}.tar.gz"
mkdir -p "$OUTPUT_DIR"
START_TS=$(date +%s)

# ANSI color codes
RED=$'\033[0;31m'
YELLOW=$'\033[0;33m'
GREEN=$'\033[0;32m'
CYAN=$'\033[0;36m'
NC=$'\033[0m' # No Color

log() {
  local level="$1"
  local message="$2"
  local color="$NC"
  case "$level" in
    INFO)  color="$GREEN" ;;
    WARN)  color="$YELLOW" ;;
    ERROR) color="$RED" ;;
  esac
  echo -e "${color}[$(date +"%Y-%m-%d %H:%M:%S")] [$level] $message${NC}" | tee -a "$OUTPUT_DIR/diagnostic.log"
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "WARN" "Required command not found: $cmd"
    return 1
  fi
  return 0
}

# Check core tools
MISSING=0
for c in oc openssl awk grep sed base64 tar; do
  require_cmd "$c" || MISSING=1
done
if [ "$MISSING" -ne 0 ]; then
  log "WARN" "Missing required commands. Some collections may be skipped."
  log "WARN" "Continuing to gather available diagnostics. For full coverage, please install missing dependencies and re-run."

  # Continue anyway to collect whatever we can; do not exit abruptly in incidents.
fi

# Helpers
safe_file() {
  # write stdin to file; ensure directory exists
  local fpath="$1"
  mkdir -p "$(dirname "$fpath")"
  cat - > "$fpath"
}

# Portable sed -i
sed_inplace() {
  local expr="$1"
  local file="$2"
  if sed --version >/dev/null 2>&1; then
    sed -i "$expr" "$file"
  else
    sed -i '' "$expr" "$file" 2>/dev/null || {
      # Fallback: write to temp file
      tmp="${file}.tmp.$$"
      sed "$expr" "$file" > "$tmp" && mv "$tmp" "$file"
    }
  fi
}

# Bash capability: associative arrays supported?
bash_supports_assoc_arrays() {
  if [ -n "${BASH_VERSINFO:-}" ] && [ "${BASH_VERSINFO[0]}" -ge 4 ]; then
    return 0
  fi
  # Fallback probe
  (declare -A __aa_test) >/dev/null 2>&1
  return $?
}
# ---------------------------
# Health tagging (namespace)
# ---------------------------
tag_namespace_health() {
  local ns="$1"
  local ns_dir="$OUTPUT_DIR/$ns"
  local status="healthy"

  # Count failed pods (using phase and reason patterns)
  local failed_pods
  failed_pods=$(oc get pods -n "$ns" --no-headers 2>/dev/null | grep -E 'CrashLoopBackOff|Error|OOMKilled|Evicted' | wc -l || echo 0)

  # Count warnings in events
  local warning_events
  warning_events=$(oc get events -n "$ns" --no-headers 2>/dev/null | grep -i 'Warning' | wc -l || echo 0)

  if [ "$failed_pods" -gt 5 ] || [ "$warning_events" -gt 10 ]; then
    status="critical"
  elif [ "$failed_pods" -gt 0 ] || [ "$warning_events" -gt 0 ]; then
    status="degraded"
  fi

  echo "status=$status" > "$ns_dir/status.txt"
  local lvl="INFO"
  if [ "$status" = "degraded" ] || [ "$status" = "critical" ]; then
    lvl="WARN"
  fi
  log "$lvl" "Namespace [$ns] tagged as: $status"
  if [ "$lvl" = "WARN" ]; then
    log "WARN" "Namespace [$ns] details: failed_pods=$failed_pods, warning_events=$warning_events"
  fi
}

# ---------------------------
# TLS: route collection
# ---------------------------
collect_tls_route_diagnostics() {
  local ns="$1"
  local tls_dir="$OUTPUT_DIR/$ns/tls_routes"
  mkdir -p "$tls_dir"

  local routes
  routes=$(oc get route -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  for route in $routes; do
    # Single fetch per route for archival and local parsing
    local route_yaml route_json host termination policy admitted
    route_yaml=$(oc get route "$route" -n "$ns" -o yaml 2>/dev/null || true)
    printf "%s\n" "$route_yaml" > "$tls_dir/route_${route}.yaml"
    route_json=$(oc get route "$route" -n "$ns" -o json 2>/dev/null || true)

    # Parse basic fields from JSON (fall back to jsonpath only for 'admitted')
    host=$(printf "%s" "$route_json" | sed -n 's/.*"host"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
    termination=$(printf "%s" "$route_json" | sed -n 's/.*"termination"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
    policy=$(printf "%s" "$route_json" | sed -n 's/.*"insecureEdgeTerminationPolicy"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)

    # Admission status (use one jsonpath read)
    admitted=$(oc get route "$route" -n "$ns" -o jsonpath='{range .status.ingress[*].conditions[?(@.type=="Admitted")]}{.status}{"\n"}{end}' 2>/dev/null | tail -n1)
    if [ -n "$admitted" ] && [ "$admitted" != "True" ]; then
      log "WARN" "Route [$ns/$route] not admitted by router (host=$host)."
    fi

    # Insecure policy warning
    if [ "$policy" = "Allow" ]; then
      log "WARN" "Route [$ns/$route] allows insecure HTTP (policy=Allow)."
    fi

    # Handshake test only if host present and openssl available
    if [ -n "$host" ] && command -v openssl >/dev/null 2>&1; then
      log "INFO" "Testing TLS handshake for $host" 
      echo | openssl s_client -connect "$host:443" -servername "$host" > "$tls_dir/openssl_${route}.txt" 2>&1 || true
    fi
  done

  # Snapshot TLS-type secrets for forensics
  local tls_secrets
  tls_secrets=$(oc get secrets -n "$ns" -o jsonpath='{range .items[?(@.type=="kubernetes.io/tls")]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
  for secret in $tls_secrets; do
    oc describe secret "$secret" -n "$ns" > "$tls_dir/secret_${secret}.txt" 2>/dev/null || true
  done
}

# ---------------------------
# TLS: validation & warnings
# ---------------------------
validate_tls_certificates() {
  local ns="$1"
  local tls_dir="$OUTPUT_DIR/$ns/tls_routes"
  mkdir -p "$tls_dir"

  local routes
  routes=$(oc get route -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)

  for route in $routes; do
    local host termination cert key ca destCA
    # Reduce oc calls by fetching small scalars together
    read -r host termination < <(oc get route "$route" -n "$ns" -o jsonpath='{.spec.host}{"\n"}{.spec.tls.termination}' 2>/dev/null)
    # PEM materials kept as individual reads to avoid parsing issues
    cert=$(oc get route "$route" -n "$ns" -o jsonpath='{.spec.tls.certificate}' 2>/dev/null)
    key=$(oc get route "$route" -n "$ns" -o jsonpath='{.spec.tls.key}' 2>/dev/null)
    ca=$(oc get route "$route" -n "$ns" -o jsonpath='{.spec.tls.caCertificate}' 2>/dev/null)
    destCA=$(oc get route "$route" -n "$ns" -o jsonpath='{.spec.tls.destinationCACertificate}' 2>/dev/null)

    # Warn on termination requirements
    if [ "$termination" = "passthrough" ]; then
      log "WARN" "Route [$ns/$route] uses passthrough termination; application must terminate TLS."
    fi

    if [ "$termination" = "edge" ] || [ "$termination" = "reencrypt" ]; then
      # For edge/reencrypt, cert/key should be present in spec.tls OR properly managed by platform.
      if [ -z "$cert" ] || [ -z "$key" ]; then
        log "WARN" "Route [$ns/$route] termination=$termination but .spec.tls.certificate/key missing."
      fi
      # Write and validate embedded PEM if present
      if [ -n "$cert" ]; then
        printf "%s" "$cert" | safe_file "$tls_dir/route_${route}_spec_tls.crt"
        if ! openssl x509 -in "$tls_dir/route_${route}_spec_tls.crt" -noout 2>/dev/null; then
          log "WARN" "Route [$ns/$route] .spec.tls.certificate is not a valid PEM certificate."
        else
          # Expiry check (expired)
          if ! openssl x509 -checkend 0 -noout -in "$tls_dir/route_${route}_spec_tls.crt" 2>/dev/null; then
            log "WARN" "Route [$ns/$route] certificate appears expired."
          fi
          # Expiry threshold (expires within 30 days)
          if ! openssl x509 -checkend $((30*24*3600)) -noout -in "$tls_dir/route_${route}_spec_tls.crt" 2>/dev/null; then
            log "WARN" "Route [$ns/$route] certificate will expire within 30 days."
          fi
          # SAN/CN validation
          local san_ok=""
          local san_entries
          san_entries=$(openssl x509 -in "$tls_dir/route_${route}_spec_tls.crt" -noout -text 2>/dev/null | awk '/Subject Alternative Name/{flag=1;next}/X509v3/{flag=0}flag' | tr ',' '\n' | sed 's/^ *//g' | grep '^DNS:' | sed 's/^DNS://')
          if [ -n "$san_entries" ]; then
            while IFS= read -r san; do
              if [ "$san" = "$host" ]; then san_ok="yes"; break; fi
              if [[ "$san" == \*.* ]]; then
                local suffix="${san#\*.}"
                if [[ "$host" == *".$suffix" ]]; then san_ok="yes"; break; fi
              fi
            done <<< "$san_entries"
          fi
          if [ -z "$san_ok" ]; then
            local subject_cn
            subject_cn=$(openssl x509 -in "$tls_dir/route_${route}_spec_tls.crt" -noout -subject -nameopt RFC2253 2>/dev/null | sed -n 's/^subject= //p' | sed -n 's/.*CN=\([^,]*\).*/\1/p')
            if [ -n "$subject_cn" ]; then
              if [[ "$subject_cn" == \*.* ]]; then
                local suffix="${subject_cn#\*.}"
                if [[ "$host" != *"$suffix" ]]; then
                  log "WARN" "Route [$ns/$route] host [$host] does not match wildcard CN [$subject_cn]."
                fi
              elif [ "$host" != "$subject_cn" ]; then
                log "WARN" "Route [$ns/$route] host [$host] does not match certificate CN [$subject_cn]."
              fi
            else
              log "WARN" "Route [$ns/$route] certificate lacks SAN and CN entries for host validation."
            fi
          fi
        fi
      fi
      # Key validation and match (if present)
      if [ -n "$key" ] && [ -n "$cert" ]; then
        printf "%s" "$key" | safe_file "$tls_dir/route_${route}_spec_tls.key"
        if ! openssl pkey -in "$tls_dir/route_${route}_spec_tls.key" -check -noout 2>/dev/null; then
          if ! openssl rsa -in "$tls_dir/route_${route}_spec_tls.key" -check -noout 2>/dev/null; then
            log "WARN" "Route [$ns/$route] .spec.tls.key may be invalid (bad PEM or password-protected)."
          fi
        fi
        local spki_cert spki_key
        spki_cert=$(openssl x509 -in "$tls_dir/route_${route}_spec_tls.crt" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform der 2>/dev/null | openssl md5 | awk '{print $2}')
        spki_key=$(openssl pkey -in "$tls_dir/route_${route}_spec_tls.key" -pubout -outform der 2>/dev/null | openssl md5 | awk '{print $2}')
        if [ -n "$spki_cert" ] && [ -n "$spki_key" ] && [ "$spki_cert" != "$spki_key" ]; then
          log "WARN" "Route [$ns/$route] certificate public key does not match provided private key (SPKI mismatch)."
        fi
        local mod_cert mod_key
        mod_cert=$(openssl x509 -in "$tls_dir/route_${route}_spec_tls.crt" -noout -modulus 2>/dev/null | openssl md5 | awk '{print $2}')
        mod_key=$(openssl rsa -in "$tls_dir/route_${route}_spec_tls.key" -noout -modulus 2>/dev/null | openssl md5 | awk '{print $2}')
        if [ -n "$mod_cert" ] && [ -n "$mod_key" ] && [ "$mod_cert" != "$mod_key" ]; then
          log "WARN" "Route [$ns/$route] certificate modulus does not match its RSA private key."
        fi
      fi
      # CA validation and chain check (if provided)
      if [ -n "$ca" ] && [ -n "$cert" ]; then
        printf "%s" "$ca" | safe_file "$tls_dir/route_${route}_spec_tls_ca.crt"
        if ! openssl x509 -in "$tls_dir/route_${route}_spec_tls_ca.crt" -noout 2>/dev/null; then
          if ! (openssl crl2pkcs7 -nocrl -certfile "$tls_dir/route_${route}_spec_tls_ca.crt" | openssl pkcs7 -print_certs -noout >/dev/null 2>&1); then
            log "WARN" "Route [$ns/$route] .spec.tls.caCertificate is not a valid PEM certificate or bundle."
          fi
        fi
        if ! openssl verify -CAfile "$tls_dir/route_${route}_spec_tls_ca.crt" "$tls_dir/route_${route}_spec_tls.crt" >/dev/null 2>&1; then
          log "WARN" "Route [$ns/$route] certificate failed verification against provided caCertificate."
        fi
      fi
      # For reencrypt, verify destination CA format
      if [ "$termination" = "reencrypt" ]; then
        if [ -z "$destCA" ]; then
          log "WARN" "Route [$ns/$route] reencrypt termination without destinationCACertificate."
        else
          printf "%s" "$destCA" | safe_file "$tls_dir/route_${route}_destination_ca.crt"
          if ! openssl x509 -in "$tls_dir/route_${route}_destination_ca.crt" -noout 2>/dev/null; then
            if ! (openssl crl2pkcs7 -nocrl -certfile "$tls_dir/route_${route}_destination_ca.crt" | openssl pkcs7 -print_certs -noout >/dev/null 2>&1); then
              log "WARN" "Route [$ns/$route] .spec.tls.destinationCACertificate is not a valid PEM certificate or bundle."
            fi
          fi
        fi
      fi
    fi

    # Handshake validation (if openssl and host available)
    if command -v openssl >/dev/null 2>&1 && [ -n "$host" ]; then
      local hs_file="$tls_dir/openssl_${route}.txt"
      if [ -f "$hs_file" ]; then
        if ! grep -q "Verify return code: 0" "$hs_file"; then
          log "WARN" "TLS handshake verification failed for [$ns/$route] (host=$host)."
        fi
        if grep -q "Cipher is (NONE)" "$hs_file"; then
          log "WARN" "No cipher negotiated for [$ns/$route] (host=$host)."
        fi
        if grep -Eq "Protocol\s+:\s+TLSv1(\.0|\.1)" "$hs_file"; then
          log "WARN" "Weak TLS version negotiated for [$ns/$route] (host=$host)."
        fi
      fi
    fi
  done

  # Ingress TLS profile(s)
  local ics
  ics=$(oc get ingresscontroller -n openshift-ingress-operator -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  for ic in $ics; do
    local profile
    profile=$(oc get ingresscontroller "$ic" -n openshift-ingress-operator -o jsonpath='{.spec.tlsSecurityProfile.type}' 2>/dev/null)
    if [ "$profile" = "Old" ]; then
      log "WARN" "IngressController [$ic] uses 'Old' TLS profile (weak ciphers)."
    fi
  done
}

# ---------------------------
# Ingress default certificate validation (cluster scope)
# ---------------------------
validate_default_router_certs() {
  local out_dir="$OUTPUT_DIR/cluster_ingress"
  mkdir -p "$out_dir"

  # Collect default ingresscontroller spec
  oc get ingresscontroller -n openshift-ingress-operator -o yaml > "$out_dir/ingresscontrollers.yaml" 2>/dev/null || true

  # Attempt to read the default router cert (if accessible)
  local default_secret
  default_secret=$(oc get ingresscontroller default -n openshift-ingress-operator -o jsonpath='{.spec.defaultCertificate.name}' 2>/dev/null)
  if [ -z "$default_secret" ]; then
    default_secret="router-certs-default"
  fi
  if oc get secret "$default_secret" -n openshift-ingress >/dev/null 2>&1; then
    local crt
    crt=$(oc get secret "$default_secret" -n openshift-ingress -o jsonpath='{.data.tls\.crt}' 2>/dev/null)
    if [ -n "$crt" ]; then
      echo "$crt" | base64 -d > "$out_dir/${default_secret}.crt" 2>/dev/null || true
      if openssl x509 -in "$out_dir/${default_secret}.crt" -noout >/dev/null 2>&1; then
        if ! openssl x509 -checkend $((30*24*3600)) -noout -in "$out_dir/${default_secret}.crt"; then
          log "WARN" "Default router certificate in secret [$default_secret] expires within 30 days."
        fi
      else
        log "WARN" "Default router certificate in secret [$default_secret] is not a valid PEM."
      fi
    fi
  fi
}

# ---------------------------
# Degraded manifest extraction
# ---------------------------
extract_degraded_manifests() {
  local degraded_dir="$OUTPUT_DIR/degraded_manifests"
  mkdir -p "$degraded_dir"

  # ClusterOperators degraded
  local cos
  cos=$(oc get clusteroperators -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  for co in $cos; do
    local status
    status=$(oc get clusteroperator "$co" -o jsonpath='{.status.conditions[?(@.type=="Degraded")].status}' 2>/dev/null)
    if [ "$status" = "True" ]; then
      log "WARN" "Degraded ClusterOperator detected: $co"
      # Detail reason/message
      local co_reason co_msg
      co_reason=$(oc get clusteroperator "$co" -o jsonpath='{.status.conditions[?(@.type=="Degraded")].reason}' 2>/dev/null)
      co_msg=$(oc get clusteroperator "$co" -o jsonpath='{.status.conditions[?(@.type=="Degraded")].message}' 2>/dev/null | sed -e 's/\r//g' -e 's/\n/ /g' -e 's/  */ /g')
      [ -n "$co_reason$co_msg" ] && log "WARN" "ClusterOperator [$co] Degraded reason=$co_reason message=${co_msg:0:300}"
      oc get clusteroperator "$co" -o yaml > "$degraded_dir/clusteroperator_$co.yaml" 2>/dev/null || true
    fi
  done

  # Deployments with unavailable replicas
  local namespaces
  namespaces=$(oc get ns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  for ns in $namespaces; do
    local deploys
    deploys=$(oc get deployment -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    for deploy in $deploys; do
      local unavailable
      unavailable=$(oc get deployment "$deploy" -n "$ns" -o jsonpath='{.status.unavailableReplicas}' 2>/dev/null)
      if [ -n "$unavailable" ] && [ "$unavailable" != "0" ]; then
        log "WARN" "Degraded Deployment detected: $ns/$deploy"
        # Detail replica counts and conditions
        local desired ready available conds
        desired=$(oc get deployment "$deploy" -n "$ns" -o jsonpath='{.spec.replicas}' 2>/dev/null); desired=${desired:-0}
        ready=$(oc get deployment "$deploy" -n "$ns" -o jsonpath='{.status.readyReplicas}' 2>/dev/null); ready=${ready:-0}
        available=$(oc get deployment "$deploy" -n "$ns" -o jsonpath='{.status.availableReplicas}' 2>/dev/null); available=${available:-0}
        conds=$(oc get deployment "$deploy" -n "$ns" -o jsonpath='{range .status.conditions[*]}{.type}={.status}({.reason}) {"|"} {end}' 2>/dev/null)
        [ -n "$conds" ] && log "WARN" "Deployment [$ns/$deploy] replicas desired=$desired ready=$ready available=$available unavailable=$unavailable conditions=${conds}"
        oc get deployment "$deploy" -n "$ns" -o yaml > "$degraded_dir/deployment_${ns}_${deploy}.yaml" 2>/dev/null || true
      fi
    done
  done

  # Pods in failure states
  for ns in $namespaces; do
    local badpods
    badpods=$(oc get pods -n "$ns" --no-headers 2>/dev/null | grep -E 'CrashLoopBackOff|Error|OOMKilled|Evicted' | awk '{print $1}')
    for pod in $badpods; do
      log "WARN" "Degraded Pod detected: $ns/$pod"
      # Detail pod status, container restarts and reasons, latest event
      local phase csum last_event
      phase=$(oc get pod "$pod" -n "$ns" -o jsonpath='{.status.phase}' 2>/dev/null)
      csum=$(oc get pod "$pod" -n "$ns" -o jsonpath='{range .status.containerStatuses[*]}{.name}:{.restartCount}x,{.state.waiting.reason}{";"}{end}' 2>/dev/null)
      [ -z "$csum" ] && csum=$(oc get pod "$pod" -n "$ns" -o jsonpath='{range .status.containerStatuses[*]}{.name}:{.restartCount}x,{.lastState.terminated.reason}{";"}{end}' 2>/dev/null)
      [ -n "$phase$csum" ] && log "WARN" "Pod [$ns/$pod] phase=$phase containers=${csum:-n/a}"
      last_event=$(oc get events -n "$ns" --field-selector involvedObject.kind=Pod,involvedObject.name="$pod" --sort-by=.lastTimestamp 2>/dev/null | tail -n1)
      [ -n "$last_event" ] && log "WARN" "Pod [$ns/$pod] last event: ${last_event}"
      oc get pod "$pod" -n "$ns" -o yaml > "$degraded_dir/pod_${ns}_${pod}.yaml" 2>/dev/null || true
    done
  done

  # Probe and readiness diagnostics
  local probe_dir="$degraded_dir/probe_issues"
  mkdir -p "$probe_dir"
  for ns in $namespaces; do
    local pods
    pods=$(oc get pods -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    for pod in $pods; do
      local misconfig=0
      local containers_count readiness_count liveness_count
      containers_count=$(oc get pod "$pod" -n "$ns" -o jsonpath='{.spec.containers[*].name}' 2>/dev/null | wc -w | tr -d ' ')
      readiness_count=$(oc get pod "$pod" -n "$ns" -o yaml 2>/dev/null | grep -c 'readinessProbe:' || echo 0)
      liveness_count=$(oc get pod "$pod" -n "$ns" -o yaml 2>/dev/null | grep -c 'livenessProbe:' || echo 0)

      if [ "$containers_count" -gt 0 ] && [ "$readiness_count" -lt "$containers_count" ]; then
        log "WARN" "Pod [$ns/$pod] missing readinessProbe for one or more containers."
        misconfig=1
      fi
      if [ "$containers_count" -gt 0 ] && [ "$liveness_count" -lt "$containers_count" ]; then
        log "WARN" "Pod [$ns/$pod] missing livenessProbe for one or more containers."
        misconfig=1
      fi

      # Containers not ready
      local ready_vals
      ready_vals=$(oc get pod "$pod" -n "$ns" -o jsonpath='{.status.containerStatuses[*].ready}' 2>/dev/null)
      if echo "$ready_vals" | grep -q "false"; then
        log "WARN" "Pod [$ns/$pod] has containers not Ready."
        misconfig=1
      fi

      # Init containers terminated with non-Completed
      local init_terms
      init_terms=$(oc get pod "$pod" -n "$ns" -o jsonpath='{.status.initContainerStatuses[*].state.terminated.reason}' 2>/dev/null)
      if [ -n "$init_terms" ]; then
        for r in $init_terms; do
          if [ -n "$r" ] && [ "$r" != "Completed" ]; then
            log "WARN" "Pod [$ns/$pod] init container terminated with reason=$r."
            misconfig=1
            break
          fi
        done
      fi

      # Probe failure events
      if oc get events -n "$ns" --field-selector involvedObject.kind=Pod,involvedObject.name="$pod" 2>/dev/null | grep -Ei "(Liveness|Readiness) probe failed" >/dev/null; then
        log "WARN" "Pod [$ns/$pod] has readiness/liveness probe failures in events."
        misconfig=1
      fi

      # Dump full pod manifest if any issue detected
      if [ "$misconfig" -eq 1 ]; then
        oc get pod "$pod" -n "$ns" -o yaml > "$probe_dir/pod_${ns}_${pod}.yaml" 2>/dev/null || true
      fi
    done
  done

  # ---------- Workload readiness/availability checks ----------
  for ns in $namespaces; do
    # StatefulSets
    for sfs in $(oc get statefulset -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
      local spec replicas ready
      replicas=$(oc get statefulset "$sfs" -n "$ns" -o jsonpath='{.spec.replicas}' 2>/dev/null); replicas=${replicas:-0}
      ready=$(oc get statefulset "$sfs" -n "$ns" -o jsonpath='{.status.readyReplicas}' 2>/dev/null); ready=${ready:-0}
      if [ "$ready" -lt "$replicas" ]; then
        log "WARN" "Degraded StatefulSet: $ns/$sfs (ready=$ready < desired=$replicas)"
        oc get statefulset "$sfs" -n "$ns" -o yaml > "$degraded_dir/statefulset_${ns}_${sfs}.yaml" 2>/dev/null || true
      fi
    done

    # ReplicaSets
    for rs in $(oc get replicaset -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
      local replicas ready
      replicas=$(oc get replicaset "$rs" -n "$ns" -o jsonpath='{.spec.replicas}' 2>/dev/null); replicas=${replicas:-0}
      ready=$(oc get replicaset "$rs" -n "$ns" -o jsonpath='{.status.readyReplicas}' 2>/dev/null); ready=${ready:-0}
      if [ "$ready" -lt "$replicas" ]; then
        log "WARN" "Degraded ReplicaSet: $ns/$rs (ready=$ready < desired=$replicas)"
        oc get replicaset "$rs" -n "$ns" -o yaml > "$degraded_dir/replicaset_${ns}_${rs}.yaml" 2>/dev/null || true
      fi
    done

    # DeploymentConfigs (OpenShift)
    if oc api-resources 2>/dev/null | grep -q '^deploymentconfigs[[:space:]]'; then
      for dc in $(oc get deploymentconfig -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        local replicas avail
        replicas=$(oc get deploymentconfig "$dc" -n "$ns" -o jsonpath='{.spec.replicas}' 2>/dev/null); replicas=${replicas:-0}
        avail=$(oc get deploymentconfig "$dc" -n "$ns" -o jsonpath='{.status.availableReplicas}' 2>/dev/null); avail=${avail:-0}
        if [ "$avail" -lt "$replicas" ]; then
          log "WARN" "Degraded DeploymentConfig: $ns/$dc (available=$avail < desired=$replicas)"
          oc get deploymentconfig "$dc" -n "$ns" -o yaml > "$degraded_dir/deploymentconfig_${ns}_${dc}.yaml" 2>/dev/null || true
        fi
      done
    fi

    # ReplicationControllers
    for rc in $(oc get rc -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
      local replicas ready
      replicas=$(oc get rc "$rc" -n "$ns" -o jsonpath='{.spec.replicas}' 2>/dev/null); replicas=${replicas:-0}
      ready=$(oc get rc "$rc" -n "$ns" -o jsonpath='{.status.readyReplicas}' 2>/dev/null); ready=${ready:-0}
      if [ "$ready" -lt "$replicas" ]; then
        log "WARN" "Degraded ReplicationController: $ns/$rc (ready=$ready < desired=$replicas)"
        oc get rc "$rc" -n "$ns" -o yaml > "$degraded_dir/replicationcontroller_${ns}_${rc}.yaml" 2>/dev/null || true
      fi
    done

    # BuildConfigs: detect recent failed build
    if oc api-resources 2>/dev/null | grep -q '^buildconfigs[[:space:]]'; then
      for bc in $(oc get buildconfig -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        local last_phase
        last_phase=$(oc get build -n "$ns" -l buildconfig="$bc" --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].status.phase}' 2>/dev/null)
        if [ "$last_phase" = "Failed" ] || [ "$last_phase" = "Error" ]; then
          log "WARN" "BuildConfig failing builds: $ns/$bc (last build phase=$last_phase)"
          oc get buildconfig "$bc" -n "$ns" -o yaml > "$degraded_dir/buildconfig_${ns}_${bc}.yaml" 2>/dev/null || true
          # Also dump last build
          local last_build
          last_build=$(oc get build -n "$ns" -l buildconfig="$bc" --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}' 2>/dev/null)
          [ -n "$last_build" ] && oc get build "$last_build" -n "$ns" -o yaml > "$degraded_dir/build_${ns}_${last_build}.yaml" 2>/dev/null || true
        fi
      done
    fi

    # Jobs
    if oc api-resources 2>/dev/null | grep -q '^jobs[[:space:]]'; then
      for job in $(oc get job -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        local comps succ fail
        comps=$(oc get job "$job" -n "$ns" -o jsonpath='{.spec.completions}' 2>/dev/null); comps=${comps:-1}
        succ=$(oc get job "$job" -n "$ns" -o jsonpath='{.status.succeeded}' 2>/dev/null); succ=${succ:-0}
        fail=$(oc get job "$job" -n "$ns" -o jsonpath='{.status.failed}' 2>/dev/null); fail=${fail:-0}
        if [ "$fail" -gt 0 ] || [ "$succ" -lt "$comps" ]; then
          log "WARN" "Degraded Job: $ns/$job (succeeded=$succ, completions=$comps, failed=$fail)"
          oc get job "$job" -n "$ns" -o yaml > "$degraded_dir/job_${ns}_${job}.yaml" 2>/dev/null || true
        fi
      done
    fi

    # DaemonSets
    if oc api-resources 2>/dev/null | grep -q '^daemonsets[[:space:]]'; then
      for ds in $(oc get ds -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        local desired available unavailable
        desired=$(oc get ds "$ds" -n "$ns" -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null); desired=${desired:-0}
        available=$(oc get ds "$ds" -n "$ns" -o jsonpath='{.status.numberAvailable}' 2>/dev/null); available=${available:-0}
        unavailable=$(oc get ds "$ds" -n "$ns" -o jsonpath='{.status.numberUnavailable}' 2>/dev/null); unavailable=${unavailable:-0}
        if [ "$unavailable" -gt 0 ] || [ "$available" -lt "$desired" ]; then
          log "WARN" "Degraded DaemonSet: $ns/$ds (available=$available, desired=$desired, unavailable=$unavailable)"
          oc get ds "$ds" -n "$ns" -o yaml > "$degraded_dir/daemonset_${ns}_${ds}.yaml" 2>/dev/null || true
        fi
      done
    fi

    # VirtualMachineInstances
    if oc api-resources 2>/dev/null | grep -q '^virtualmachineinstances[[:space:]]'; then
      for vmi in $(oc get virtualmachineinstance -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        local phase
        phase=$(oc get virtualmachineinstance "$vmi" -n "$ns" -o jsonpath='{.status.phase}' 2>/dev/null)
        if [ "$phase" != "Running" ]; then
          log "WARN" "Degraded VirtualMachineInstance: $ns/$vmi (phase=$phase)"
          oc get virtualmachineinstance "$vmi" -n "$ns" -o yaml > "$degraded_dir/virtualmachineinstance_${ns}_${vmi}.yaml" 2>/dev/null || true
        fi
      done
    fi

    # cert-manager Certificates
    if oc api-resources 2>/dev/null | grep -q '^certificates\.cert-manager\.io[[:space:]]'; then
      for cert in $(oc get certificates.cert-manager.io -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        local readycond
        readycond=$(oc get certificates.cert-manager.io "$cert" -n "$ns" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
        if [ "$readycond" != "True" ]; then
          log "WARN" "Degraded Certificate: $ns/$cert (Ready=$readycond)"
          oc get certificates.cert-manager.io "$cert" -n "$ns" -o yaml > "$degraded_dir/certificate_${ns}_${cert}.yaml" 2>/dev/null || true
        fi
      done
    fi
  done
}

# ---------------------------
# PVC & Storage Diagnostics
# ---------------------------
check_pvc_health() {
  local degraded_dir="$OUTPUT_DIR/degraded_manifests"
  mkdir -p "$degraded_dir"
  local namespaces pvcs pvc phase events
  namespaces=$(oc get ns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  for ns in $namespaces; do
    pvcs=$(oc get pvc -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    for pvc in $pvcs; do
      phase=$(oc get pvc "$pvc" -n "$ns" -o jsonpath='{.status.phase}' 2>/dev/null)
      if [ -n "$phase" ] && [ "$phase" != "Bound" ]; then
        log "WARN" "PVC [$ns/$pvc] phase=$phase"
        oc get pvc "$pvc" -n "$ns" -o yaml > "$degraded_dir/pvc_${ns}_${pvc}.yaml" 2>/dev/null || true
      fi
      events=$(oc get events -n "$ns" --field-selector involvedObject.kind=PersistentVolumeClaim,involvedObject.name="$pvc" 2>/dev/null | grep -Ei 'timeout|fail|error|provision' | wc -l || echo 0)
      if [ "$events" -gt 0 ]; then
        log "WARN" "PVC [$ns/$pvc] has provisioning-related warnings ($events)"
      fi
    done
  done
}

# ---------------------------
# RBAC Drift Detection
# ---------------------------
check_rbac_integrity() {
  local degraded_dir="$OUTPUT_DIR/degraded_manifests"
  mkdir -p "$degraded_dir"
  local bindings b subjects ns rbs rn rkind rname
  bindings=$(oc get clusterrolebinding -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  for b in $bindings; do
    subjects=$(oc get clusterrolebinding "$b" -o jsonpath='{.subjects[*].name}' 2>/dev/null)
    if [ -z "$subjects" ]; then
      log "WARN" "ClusterRoleBinding [$b] has no subjects (possible orphan)"
      oc get clusterrolebinding "$b" -o yaml > "$degraded_dir/clusterrolebinding_${b}.yaml" 2>/dev/null || true
    fi
  done
  for ns in $(oc get ns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    rbs=$(oc get rolebinding -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    for rn in $rbs; do
      rkind=$(oc get rolebinding "$rn" -n "$ns" -o jsonpath='{.roleRef.kind}' 2>/dev/null)
      rname=$(oc get rolebinding "$rn" -n "$ns" -o jsonpath='{.roleRef.name}' 2>/dev/null)
      if [ "$rkind" = "Role" ]; then
        oc get role "$rname" -n "$ns" >/dev/null 2>&1 || { log "WARN" "RoleBinding [$ns/$rn] references missing Role [$rname]"; oc get rolebinding "$rn" -n "$ns" -o yaml > "$degraded_dir/rolebinding_${ns}_${rn}.yaml" 2>/dev/null || true; }
      elif [ "$rkind" = "ClusterRole" ]; then
        oc get clusterrole "$rname" >/dev/null 2>&1 || { log "WARN" "RoleBinding [$ns/$rn] references missing ClusterRole [$rname]"; oc get rolebinding "$rn" -n "$ns" -o yaml > "$degraded_dir/rolebinding_${ns}_${rn}.yaml" 2>/dev/null || true; }
      fi
    done
  done
}

# ---------------------------
# CSI Driver Health & Socket Checks
# ---------------------------
check_csi_health() {
  local degraded_dir="$OUTPUT_DIR/degraded_manifests"
  mkdir -p "$degraded_dir"
  local ns badpods ds deploy desired available first_pod
  for ns in $(oc get ns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | tr ' ' '\n' | grep -E '(^openshift-storage$|csi|storage)' || true); do
    badpods=$(oc get pods -n "$ns" --no-headers 2>/dev/null | grep -E 'CrashLoopBackOff|Error|ImagePullBackOff|CreateContainerError' | awk '{print $1}')
    for pod in $badpods; do
      log "WARN" "CSI pod degraded: $ns/$pod"
      oc get pod "$pod" -n "$ns" -o yaml > "$degraded_dir/csi_pod_${ns}_${pod}.yaml" 2>/dev/null || true
    done
    for ds in $(oc get ds -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
      desired=$(oc get ds "$ds" -n "$ns" -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null); desired=${desired:-0}
      available=$(oc get ds "$ds" -n "$ns" -o jsonpath='{.status.numberAvailable}' 2>/dev/null); available=${available:-0}
      if [ "$available" -lt "$desired" ]; then
        log "WARN" "CSI DaemonSet degraded: $ns/$ds (available=$available < desired=$desired)"
        oc get ds "$ds" -n "$ns" -o yaml > "$degraded_dir/csi_daemonset_${ns}_${ds}.yaml" 2>/dev/null || true
      fi
    done
    for deploy in $(oc get deploy -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
      local unavail
      unavail=$(oc get deploy "$deploy" -n "$ns" -o jsonpath='{.status.unavailableReplicas}' 2>/dev/null)
      if [ -n "$unavail" ] && [ "$unavail" != "0" ]; then
        log "WARN" "CSI Deployment degraded: $ns/$deploy (unavailableReplicas=$unavail)"
        oc get deploy "$deploy" -n "$ns" -o yaml > "$degraded_dir/csi_deployment_${ns}_${deploy}.yaml" 2>/dev/null || true
      fi
    done
    first_pod=$(oc get pods -n "$ns" --no-headers 2>/dev/null | awk 'NR==1{print $1}')
    if [ -n "$first_pod" ]; then
      oc exec "$first_pod" -n "$ns" -- sh -c 'ls -d /var/lib/csi/sockets/pluginproxy >/dev/null 2>&1' || \
        log "WARN" "CSI socket path missing/inaccessible in pod [$ns/$first_pod]"
    fi
  done
}

# ---------------------------
# Namespace RBAC Summary
# ---------------------------
rbac_namespace_summary() {
  local ns out
  for ns in $(oc get ns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    out="$OUTPUT_DIR/$ns/rbac_summary.txt"
    mkdir -p "$(dirname "$out")"
    echo "RoleBindings (NAME, ROLE-KIND, ROLE, SUBJECTS)" > "$out"
    oc get rolebinding -n "$ns" -o custom-columns=NAME:.metadata.name,ROLE-KIND:.roleRef.kind,ROLE:.roleRef.name,SUBJECTS:.subjects[*].name --no-headers 2>/dev/null >> "$out" || true
    echo "" >> "$out"
    echo "ServiceAccounts (NAME, SECRETS)" >> "$out"
    oc get serviceaccount -n "$ns" -o custom-columns=NAME:.metadata.name,SECRETS:.secrets[*].name --no-headers 2>/dev/null >> "$out" || true
  done
}

# ---------------------------
# SCC Violation Scan
# ---------------------------
check_scc_violations() {
  local degraded_dir="$OUTPUT_DIR/degraded_manifests"
  mkdir -p "$degraded_dir"
  local namespaces pods ns pod priv ape hostnet hostpid nonroot
  namespaces=$(oc get ns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  for ns in $namespaces; do
    pods=$(oc get pods -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    for pod in $pods; do
      priv=$(oc get pod "$pod" -n "$ns" -o jsonpath='{.spec.containers[*].securityContext.privileged}' 2>/dev/null)
      ape=$(oc get pod "$pod" -n "$ns" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}' 2>/dev/null)
      hostnet=$(oc get pod "$pod" -n "$ns" -o jsonpath='{.spec.hostNetwork}' 2>/dev/null)
      hostpid=$(oc get pod "$pod" -n "$ns" -o jsonpath='{.spec.hostPID}' 2>/dev/null)
      nonroot=$(oc get pod "$pod" -n "$ns" -o jsonpath='{.spec.securityContext.runAsNonRoot}' 2>/dev/null)
      if echo "$priv" | grep -q '\btrue\b'; then
        log "WARN" "Pod [$ns/$pod] privileged containers detected."
        oc get pod "$pod" -n "$ns" -o yaml > "$degraded_dir/scc_pod_${ns}_${pod}.yaml" 2>/dev/null || true
      fi
      if echo "$ape" | grep -q '\btrue\b'; then
        log "WARN" "Pod [$ns/$pod] allowPrivilegeEscalation=true containers detected."
      fi
      if [ "$hostnet" = "true" ] || [ "$hostpid" = "true" ]; then
        log "WARN" "Pod [$ns/$pod] uses hostNetwork/hostPID."
      fi
      if [ "$nonroot" = "false" ]; then
        log "WARN" "Pod [$ns/$pod] runAsNonRoot=false."
      fi
    done
  done
}

# ---------------------------
# Summary statistics collection
# ---------------------------
collect_summary_stats() {
  NAMESPACE_LIST=$(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | grep -v must-gather | grep -v degraded_manifests | grep -v cluster_ingress)

  NS_COUNT=0
  TOTAL_WARN=0
  TOTAL_ERROR=0
  TLS_WARN=0
  DEGRADED_COUNT=0
  CRITICAL_COUNT=0
  MAX_SEVERITY=0
  ELAPSED_SUM=0
  AVG_ELAPSED=0
  USE_SIMPLE_STATS=0

  if bash_supports_assoc_arrays; then
    declare -gA WARN_COUNT ERROR_COUNT STATUS ELAPSED SEVERITY
    for ns in $NAMESPACE_LIST; do
      NS_COUNT=$((NS_COUNT + 1))
      local status_file="$OUTPUT_DIR/$ns/status.txt"
      local st="unknown"
      [ -f "$status_file" ] && st=$(grep status= "$status_file" | cut -d= -f2)
      STATUS[$ns]="$st"
      [ "$st" = "degraded" ] && DEGRADED_COUNT=$((DEGRADED_COUNT + 1))
      [ "$st" = "critical" ] && CRITICAL_COUNT=$((CRITICAL_COUNT + 1))

      local warns errors tlsw elapsed
      warns=$(grep "\[WARN\]" "$OUTPUT_DIR/diagnostic.log" 2>/dev/null | grep "\[$ns/" -c 2>/dev/null); warns=${warns:-0}
      errors=$(grep "\[ERROR\]" "$OUTPUT_DIR/diagnostic.log" 2>/dev/null | grep "\[$ns/" -c 2>/dev/null); errors=${errors:-0}
      tlsw=$(grep "\[WARN\]" "$OUTPUT_DIR/diagnostic.log" 2>/dev/null | grep "\[$ns/" | grep -i "tls" -c 2>/dev/null); tlsw=${tlsw:-0}
      WARN_COUNT[$ns]=$warns
      ERROR_COUNT[$ns]=$errors
      TLS_WARN=$((TLS_WARN + tlsw))
      TOTAL_WARN=$((TOTAL_WARN + warns))
      TOTAL_ERROR=$((TOTAL_ERROR + errors))

      elapsed=0
      [ -f "$OUTPUT_DIR/$ns/elapsed_seconds.txt" ] && elapsed=$(cat "$OUTPUT_DIR/$ns/elapsed_seconds.txt" 2>/dev/null || echo 0)
      ELAPSED[$ns]=$elapsed
      ELAPSED_SUM=$((ELAPSED_SUM + elapsed))

      local status_weight=0
      [ "$st" = "degraded" ] && status_weight=10
      [ "$st" = "critical" ] && status_weight=30
      local sev=$(( errors*8 + warns*4 + status_weight ))
      [ "$sev" -gt 100 ] && sev=100
      SEVERITY[$ns]=$sev
      [ "$sev" -gt "$MAX_SEVERITY" ] && MAX_SEVERITY=$sev
    done
  else
    USE_SIMPLE_STATS=1
    for ns in $NAMESPACE_LIST; do
      NS_COUNT=$((NS_COUNT + 1))
      local status_file="$OUTPUT_DIR/$ns/status.txt"
      local st="unknown"
      [ -f "$status_file" ] && st=$(grep status= "$status_file" | cut -d= -f2)
      [ "$st" = "degraded" ] && DEGRADED_COUNT=$((DEGRADED_COUNT + 1))
      [ "$st" = "critical" ] && CRITICAL_COUNT=$((CRITICAL_COUNT + 1))

      local warns errors tlsw elapsed
      warns=$(grep "\[WARN\]" "$OUTPUT_DIR/diagnostic.log" 2>/dev/null | grep "\[$ns/" -c 2>/dev/null); warns=${warns:-0}
      errors=$(grep "\[ERROR\]" "$OUTPUT_DIR/diagnostic.log" 2>/dev/null | grep "\[$ns/" -c 2>/dev/null); errors=${errors:-0}
      tlsw=$(grep "\[WARN\]" "$OUTPUT_DIR/diagnostic.log" 2>/dev/null | grep "\[$ns/" | grep -i "tls" -c 2>/dev/null); tlsw=${tlsw:-0}
      TLS_WARN=$((TLS_WARN + tlsw))
      TOTAL_WARN=$((TOTAL_WARN + warns))
      TOTAL_ERROR=$((TOTAL_ERROR + errors))

      elapsed=0
      [ -f "$OUTPUT_DIR/$ns/elapsed_seconds.txt" ] && elapsed=$(cat "$OUTPUT_DIR/$ns/elapsed_seconds.txt" 2>/dev/null || echo 0)
      ELAPSED_SUM=$((ELAPSED_SUM + elapsed))

      local status_weight=0
      [ "$st" = "degraded" ] && status_weight=10
      [ "$st" = "critical" ] && status_weight=30
      local sev=$(( errors*8 + warns*4 + status_weight ))
      [ "$sev" -gt 100 ] && sev=100
      [ "$sev" -gt "$MAX_SEVERITY" ] && MAX_SEVERITY=$sev
    done
  fi

  [ "$NS_COUNT" -gt 0 ] && AVG_ELAPSED=$((ELAPSED_SUM / NS_COUNT))
}

# ---------------------------
# JSON summary generation
# ---------------------------
generate_json_summary() {
  local summary_file="$OUTPUT_DIR/summary.json"
  collect_summary_stats

  echo "{" > "$summary_file"
  echo "  \"namespaces\": {" >> "$summary_file"

  local severity_sum=0
  for ns in $NAMESPACE_LIST; do
    local status warn_count error_count elapsed severity
    if [ "${USE_SIMPLE_STATS:-0}" -eq 1 ]; then
      local status_file="$OUTPUT_DIR/$ns/status.txt"
      status="unknown"; [ -f "$status_file" ] && status=$(grep status= "$status_file" | cut -d= -f2)
      warn_count=$(grep "\[WARN\]" "$OUTPUT_DIR/diagnostic.log" 2>/dev/null | grep "\[$ns/" -c 2>/dev/null); warn_count=${warn_count:-0}
      error_count=$(grep "\[ERROR\]" "$OUTPUT_DIR/diagnostic.log" 2>/dev/null | grep "\[$ns/" -c 2>/dev/null); error_count=${error_count:-0}
      elapsed=0; [ -f "$OUTPUT_DIR/$ns/elapsed_seconds.txt" ] && elapsed=$(cat "$OUTPUT_DIR/$ns/elapsed_seconds.txt" 2>/dev/null || echo 0)
      local status_weight=0; [ "$status" = "degraded" ] && status_weight=10; [ "$status" = "critical" ] && status_weight=30
      severity=$(( error_count*8 + warn_count*4 + status_weight )); [ "$severity" -gt 100 ] && severity=100
    else
      status="${STATUS[$ns]}"
      warn_count="${WARN_COUNT[$ns]:-0}"
      error_count="${ERROR_COUNT[$ns]:-0}"
      elapsed="${ELAPSED[$ns]:-0}"
      severity="${SEVERITY[$ns]:-0}"
    fi

    severity_sum=$((severity_sum + severity))

    echo "    \"$ns\": {" >> "$summary_file"
    echo "      \"status\": \"$status\"," >> "$summary_file"
    echo "      \"warns\": $warn_count," >> "$summary_file"
    echo "      \"errors\": $error_count," >> "$summary_file"
    echo "      \"elapsed_seconds\": $elapsed," >> "$summary_file"
    echo "      \"severity\": $severity" >> "$summary_file"
    echo "    }," >> "$summary_file"
  done

  sed_inplace '$ s/,$//' "$summary_file"
  echo "  }," >> "$summary_file"

  local now_ts=$(date +%s)
  local total_runtime=$((now_ts - START_TS))
  local avg_severity=0
  [ "${NS_COUNT:-0}" -gt 0 ] && avg_severity=$((severity_sum / NS_COUNT))

  echo "  \"global_summary\": {" >> "$summary_file"
  echo "    \"namespaces_scanned\": $NS_COUNT," >> "$summary_file"
  echo "    \"total_warns\": $TOTAL_WARN," >> "$summary_file"
  echo "    \"total_errors\": $TOTAL_ERROR," >> "$summary_file"
  echo "    \"average_severity\": $avg_severity," >> "$summary_file"
  echo "    \"max_severity\": $MAX_SEVERITY," >> "$summary_file"
  echo "    \"average_namespace_elapsed\": $AVG_ELAPSED," >> "$summary_file"
  echo "    \"total_runtime_seconds\": $total_runtime," >> "$summary_file"
  echo "    \"degraded_components\": [" >> "$summary_file"
  if [ -d "$OUTPUT_DIR/degraded_manifests" ]; then
    for f in "$OUTPUT_DIR/degraded_manifests"/*.yaml; do
      [ -f "$f" ] && echo "      \"$(basename "$f" .yaml)\"," >> "$summary_file"
    done
    sed_inplace '$ s/,$//' "$summary_file"
  fi
  echo "    ]" >> "$summary_file"
  echo "  }" >> "$summary_file"
  echo "}" >> "$summary_file"

  log "INFO" "JSON summary generated at: $summary_file"
}

# ---------------------------
# Print summary report (console)
# ---------------------------
print_summary_report() {
  echo ""
  echo -e "${GREEN}======================= OpenShift Diagnostics Summary ======================${NC}"
  local KFMT="%b%-30s%b: %s"
  local KEYCOLOR="$CYAN"

  printf "$KFMT\n" "$KEYCOLOR" "Timestamp" "$NC" "$(date +"%Y-%m-%d %H:%M:%S")"
  printf "$KFMT\n" "$KEYCOLOR" "Output Directory" "$NC" "$OUTPUT_DIR"
  printf "$KFMT\n" "$KEYCOLOR" "Archive" "$NC" "$ARCHIVE_NAME"
  echo ""

  collect_summary_stats

  local runtime_now=$(date +%s)
  local runtime_sec=$((runtime_now - START_TS))
  local runtime_min=$((runtime_sec/60))
  local runtime_rem=$((runtime_sec%60))

  local v_ns_scanned="$NS_COUNT"
  local v_degraded="${GREEN}${DEGRADED_COUNT}${NC}"; [ "${DEGRADED_COUNT:-0}" -gt 0 ] && v_degraded="${YELLOW}${DEGRADED_COUNT}${NC}"
  local v_critical="${GREEN}${CRITICAL_COUNT}${NC}"; [ "${CRITICAL_COUNT:-0}" -gt 0 ] && v_critical="${RED}${CRITICAL_COUNT}${NC}"
  local v_tls="${GREEN}${TLS_WARN:-0}${NC}"; [ "${TLS_WARN:-0}" -gt 0 ] && v_tls="${YELLOW}${TLS_WARN}${NC}"
  local v_warns="${GREEN}${TOTAL_WARN:-0}${NC}"; [ "${TOTAL_WARN:-0}" -gt 0 ] && v_warns="${YELLOW}${TOTAL_WARN}${NC}"
  local v_errors="${GREEN}${TOTAL_ERROR:-0}${NC}"; [ "${TOTAL_ERROR:-0}" -gt 0 ] && v_errors="${RED}${TOTAL_ERROR}${NC}"
  local v_avg="${AVG_ELAPSED:-0}s"
  local v_max_raw="${MAX_SEVERITY:-0}/100"
  local v_max="${GREEN}${v_max_raw}${NC}"
  if [ "${MAX_SEVERITY:-0}" -ge 80 ]; then
    v_max="${RED}${v_max_raw}${NC}"
  elif [ "${MAX_SEVERITY:-0}" -ge 40 ]; then
    v_max="${YELLOW}${v_max_raw}${NC}"
  fi
  local v_runtime=$(printf "%02d:%02d" "$runtime_min" "$runtime_rem")

  printf "$KFMT\n" "$KEYCOLOR" "Namespaces scanned" "$NC" "$v_ns_scanned"
  printf "$KFMT\n" "$KEYCOLOR" "Degraded namespaces" "$NC" "$v_degraded"
  printf "$KFMT\n" "$KEYCOLOR" "Critical namespaces" "$NC" "$v_critical"
  printf "$KFMT\n" "$KEYCOLOR" "TLS-related warnings" "$NC" "$v_tls"
  printf "$KFMT\n" "$KEYCOLOR" "Total WARN logs" "$NC" "$v_warns"
  printf "$KFMT\n" "$KEYCOLOR" "Total ERROR logs" "$NC" "$v_errors"
  printf "$KFMT\n" "$KEYCOLOR" "Average namespace elapsed" "$NC" "$v_avg"
  printf "$KFMT\n" "$KEYCOLOR" "Max severity" "$NC" "$v_max"
  printf "$KFMT\n" "$KEYCOLOR" "Total runtime (mm:ss)" "$NC" "$v_runtime"

  if [ -d "$OUTPUT_DIR/degraded_manifests" ]; then
    echo ""
    echo -e "${KEYCOLOR}Degraded Components:${NC}"
    for f in "$OUTPUT_DIR/degraded_manifests"/*.yaml; do
      [ -f "$f" ] && echo "  - $(basename "$f" .yaml)"
    done
  fi

  echo ""
  printf "$KFMT\n" "$KEYCOLOR" "JSON Summary" "$NC" "${GREEN}$OUTPUT_DIR/summary.json${NC}"
  echo -e "${GREEN}==================================================================================${NC}"
  echo ""
}

# ---------------------------
# Namespace data collection (High-Performance)
# ---------------------------
collect_namespace_data() {
  local ns="$1"
  local ns_dir="$OUTPUT_DIR/$ns"
  mkdir -p "$ns_dir"
  log "INFO" "Collecting diagnostics for namespace: $ns"
  local ns_start=$(date +%s)

  # --- Bulk Data Collection (Fast) ---
  # Get core resource summaries and full descriptions in bulk.
  # This is much faster than one 'oc' call per resource.

  oc get pods -n "$ns" -o wide > "$ns_dir/pods_list.txt" 2>/dev/null || true
  oc describe pods -n "$ns" > "$ns_dir/pods_describe.txt" 2>/dev/null || true

  oc get events -n "$ns" --sort-by='.lastTimestamp' > "$ns_dir/events.txt" 2>/dev/null || true
  
  oc get deployment -n "$ns" -o wide > "$ns_dir/deployments_list.txt" 2>/dev/null || true
  oc describe deployment -n "$ns" > "$ns_dir/deployments_describe.txt" 2>/dev/null || true

  oc get statefulset -n "$ns" -o wide > "$ns_dir/statefulsets_list.txt" 2>/dev/null || true
  oc describe statefulset -n "$ns" > "$ns_dir/statefulsets_describe.txt" 2>/dev/null || true

  oc get daemonset -n "$ns" -o wide > "$ns_dir/daemonsets_list.txt" 2>/dev/null || true
  oc describe daemonset -n "$ns" > "$ns_dir/daemonsets_describe.txt" 2>/dev/null || true

  oc get svc -n "$ns" -o wide > "$ns_dir/services_list.txt" 2>/dev/null || true
  oc describe svc -n "$ns" > "$ns_dir/services_describe.txt" 2>/dev/null || true

  oc get endpoints -n "$ns" > "$ns_dir/endpoints.txt" 2>/dev/null || true
  
  oc get routes -n "$ns" -o wide > "$ns_dir/routes_list.txt" 2>/dev/null || true
  oc describe route -n "$ns" > "$ns_dir/routes_describe.txt" 2>/dev/null || true

  oc get pvc -n "$ns" -o wide > "$ns_dir/pvc_list.txt" 2>/dev/null || true
  oc describe pvc -n "$ns" > "$ns_dir/pvc_describe.txt" 2>/dev/null || true

  oc get configmap -n "$ns" > "$ns_dir/configmaps_list.txt" 2>/dev/null || true
  oc get secrets -n "$ns" > "$ns_dir/secrets_list.txt" 2>/dev/null || true
  oc get serviceaccount -n "$ns" > "$ns_dir/serviceaccounts_list.txt" 2>/dev/null || true
  oc get rolebinding -n "$ns" > "$ns_dir/rolebindings_list.txt" 2>/dev/null || true
  
  oc get resourcequota -n "$ns" > "$ns_dir/resourcequota.txt" 2>/dev/null || true
  oc describe resourcequota -n "$ns" > "$ns_dir/resourcequota_describe.txt" 2>/dev/null || true
  
  oc get limitranges -n "$ns" > "$ns_dir/limitranges.txt" 2>/dev/null || true
  oc describe limitranges -n "$ns" > "$ns_dir/limitranges_describe.txt" 2>/dev/null || true

  # --- Optional API Resources (Check before collecting) ---
  if oc api-resources 2>/dev/null | grep -q "^networkpolicies[[:space:]]"; then
    oc get networkpolicy -n "$ns" > "$ns_dir/networkpolicies.txt" 2>/dev/null || true
    oc describe networkpolicy -n "$ns" > "$ns_dir/networkpolicies_describe.txt" 2>/dev/null || true
  fi

  if oc api-resources 2>/dev/null | grep -q "^buildconfigs[[:space:]]"; then
    oc get buildconfig -n "$ns" > "$ns_dir/buildconfigs.txt" 2>/dev/null || true
    oc describe buildconfig -n "$ns" > "$ns_dir/buildconfigs_describe.txt" 2>/dev/null || true
    oc get builds -n "$ns" > "$ns_dir/builds.txt" 2>/dev/null || true
  fi

  if oc api-resources 2>/dev/null | grep -q "^imagestreams[[:space:]]"; then
    oc get imagestream -n "$ns" > "$ns_dir/imagestreams.txt" 2>/dev/null || true
    oc describe imagestream -n "$ns" > "$ns_dir/imagestreams_describe.txt" 2>/dev/null || true
  fi

  # --- Pod Logs (Targeted Loop) ---
  # Only loop for logs, which is an acceptable performance trade-off.
  # We add --tail=1000 to avoid dumping multi-gigabyte logs.
  local pods
  pods=$(oc get pods -n "$ns" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  for pod in $pods; do
    local log_file="$ns_dir/pod_logs_${pod}.txt"
    oc logs "$pod" -n "$ns" --all-containers=true --tail=1000 > "$log_file" 2>/dev/null || true
    oc logs "$pod" -n "$ns" --all-containers=true --previous --tail=1000 >> "$log_file" 2>/dev/null || true
  done

  # --- Run detailed analysis functions ---
  collect_tls_route_diagnostics "$ns"
  validate_tls_certificates "$ns"
  tag_namespace_health "$ns"

  # --- Correct Timing (Fix Bug) ---
  local ns_end=$(date +%s)
  local elapsed=$((ns_end - ns_start))
  echo "$elapsed" > "$ns_dir/elapsed_seconds.txt"
  log "INFO" "Namespace [$ns] collection time: ${elapsed}s"
}

# ---------------------------
# Cluster-wide collection
# ---------------------------
log "INFO" "Starting OpenShift diagnostics collection..."

if command -v oc >/dev/null 2>&1; then
  log "INFO" "Collecting cluster version and operator status..."
  oc get clusterversion > "$OUTPUT_DIR/clusterversion.txt" 2>/dev/null || true
  oc get clusteroperators > "$OUTPUT_DIR/clusteroperators.txt" 2>/dev/null || true
  oc adm top nodes > "$OUTPUT_DIR/top_nodes.txt" 2>/dev/null || true
  oc describe nodes > "$OUTPUT_DIR/nodes_describe.txt" 2>/dev/null || true

  # Cluster-wide extras (guard optional APIs where appropriate)
  oc get clusterroles > "$OUTPUT_DIR/clusterroles.txt" 2>/dev/null || true
  oc get operatorhub > "$OUTPUT_DIR/operatorhub.txt" 2>/dev/null || true
  oc describe operatorhub cluster > "$OUTPUT_DIR/operatorhub_describe.txt" 2>/dev/null || true
  oc get configs.imageregistry.operator.openshift.io cluster > "$OUTPUT_DIR/image_registry.txt" 2>/dev/null || true
  oc describe configs.imageregistry.operator.openshift.io cluster > "$OUTPUT_DIR/image_registry_describe.txt" 2>/dev/null || true
  oc get pods -A --no-headers -o wide 2>/dev/null | awk '{print $1, $2, $7}' | sort | uniq -c > "$OUTPUT_DIR/node_pod_distribution.txt"

  # Ingress default certs and controllers
  validate_default_router_certs

  # Namespace loop
  if [ -z "$1" ]; then
    log "INFO" "No namespace provided. Collecting diagnostics for all namespaces..."
    namespaces=$(oc get ns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
    for ns in $namespaces; do
      collect_namespace_data "$ns"
    done
  else
    collect_namespace_data "$1"
  fi

  # Degraded components scan
  log "INFO" "Scanning for degraded components..."
  extract_degraded_manifests

  # Additional diagnostics: PVC/CSI/RBAC/SCC
  log "INFO" "Running PVC health diagnostics..."; check_pvc_health
  log "INFO" "Checking CSI driver health..."; check_csi_health
  log "INFO" "Checking RBAC integrity..."; check_rbac_integrity
  log "INFO" "Building RBAC summaries per namespace..."; rbac_namespace_summary
  log "INFO" "Scanning for SCC violations..."; check_scc_violations

  # Must-gather (best effort)
  log "INFO" "Running oc adm must-gather..."
  oc adm must-gather --dest-dir="$OUTPUT_DIR/must-gather" >> "$OUTPUT_DIR/must-gather.log" 2>&1
  rc=$?
  if [ $? -eq 0 ]; then
    log "INFO" "Must-gather completed successfully."
  else
    log "WARN" "Could not collect must-gather: see must-gather.log for details."
  fi
else
  log "WARN" "oc CLI not available; skipping OpenShift data collection."
fi

# ---------------------------
# JSON summary generation and report
# ---------------------------
generate_json_summary
print_summary_report