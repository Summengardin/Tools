#!/usr/bin/env bash
set -euo pipefail

# Configuration
SCRIPT_VERSION="2.0"
CONTROLLER_DB="$HOME/.ssh/controller_registry"
KNOWN_HOSTS_DIR="$HOME/.ssh/known_hosts_controllers"
PASSWORD_DIR="$HOME/.ssh/controller_passwords"
VERBOSE=0
DRY_RUN=0
STRICT_MODE=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Utilities
die() { 
  echo -e "${RED}ERROR: $*${NC}" >&2
  exit 1
}

log() { 
  echo -e "${GREEN}==>${NC} $*"
}

warn() {
  echo -e "${YELLOW}WARNING: $*${NC}" >&2
}

debug() { 
  [[ $VERBOSE -eq 1 ]] && echo -e "${BLUE}[DEBUG]${NC} $*" >&2 || true
}

info() {
  echo -e "${BLUE}[INFO]${NC} $*"
}

usage() {
  cat <<'EOF'
Usage:
  pair-controller.sh [OPTIONS] <controller_ip> <user> [host_alias] [pubkey_path]

Options:
  -v, --verbose              Enable verbose output
  -n, --dry-run             Show what would be done without doing it
  -s, --strict              Use strict host key checking (accept-new instead of no)
  -l, --list                List all registered controllers
  -d, --delete ALIAS        Remove a controller registration
  -i, --info ALIAS          Show detailed info about a controller
  -h, --help                Show this help message

Examples:
  # Basic pairing (default: no host key checking, per-controller tracking)
  ./pair-controller.sh 192.168.1.50 root

  # With custom alias
  ./pair-controller.sh 192.168.1.50 admin controller-main

  # With specific public key
  ./pair-controller.sh 192.168.1.50 admin controller-main ~/.ssh/id_ed25519.pub

  # Strict mode (for production controllers with stable keys)
  ./pair-controller.sh --strict 192.168.1.50 root controller-prod

  # Using password from environment (with sshpass)
  SSH_PASSWORD='yourpass' ./pair-controller.sh 192.168.1.50 admin

  # Verbose mode
  ./pair-controller.sh -v 192.168.1.50 root

  # List all registered controllers
  ./pair-controller.sh --list

  # Show info about a controller
  ./pair-controller.sh --info controller-50

  # Remove a controller
  ./pair-controller.sh --delete controller-50

Notes:
  - Default behavior uses StrictHostKeyChecking=no (for dev workflow with same IP,
    different physical controllers)
  - Each controller gets its own known_hosts file and metadata
  - Use --strict for production controllers where host keys shouldn't change
  - If sshpass is installed and SSH_PASSWORD is set, password auth will be non-interactive
EOF
}

# Validate IPv4 address
validate_ipv4() {
  local ip=$1
  local IFS='.'
  local -a octets
  read -ra octets <<< "$ip"
  
  [[ ${#octets[@]} -eq 4 ]] || return 1
  
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]+$ ]] || return 1
    ((octet >= 0 && octet <= 255)) || return 1
  done
  return 0
}

# Test network connectivity
test_connection() {
  local ip=$1
  local port=${2:-22}
  local timeout=${3:-5}
  
  debug "Testing connection to ${ip}:${port} with timeout ${timeout}s"
  
  if timeout "$timeout" bash -c "cat < /dev/null > /dev/tcp/${ip}/${port}" 2>/dev/null; then
    return 0
  else
    return 1
  fi
}

# Setup directories
setup_directories() {
  mkdir -p "$CONTROLLER_DB"
  mkdir -p "$KNOWN_HOSTS_DIR"
  mkdir -p "$PASSWORD_DIR"
  mkdir -p "$HOME/.ssh"
  chmod 700 "$HOME/.ssh"
  chmod 700 "$CONTROLLER_DB"
  chmod 700 "$KNOWN_HOSTS_DIR"
  chmod 700 "$PASSWORD_DIR"
}

# List all registered controllers
list_controllers() {
  if [[ ! -d "$CONTROLLER_DB" ]] || [[ -z "$(ls -A "$CONTROLLER_DB" 2>/dev/null)" ]]; then
    info "No controllers registered yet."
    exit 0
  fi

  echo ""
  echo "Registered Controllers:"
  echo "======================"
  
  for file in "$CONTROLLER_DB"/*.json; do
    [[ -f "$file" ]] || continue
    
    if command -v jq >/dev/null 2>&1; then
      local alias=$(jq -r '.alias' "$file")
      local ip=$(jq -r '.ip' "$file")
      local user=$(jq -r '.user' "$file")
      local hostname=$(jq -r '.hostname // "unknown"' "$file")
      local paired_date=$(jq -r '.paired_date' "$file")
      
      echo ""
      echo "  Alias:    $alias"
      echo "  IP:       $ip"
      echo "  User:     $user"
      echo "  Hostname: $hostname"
      echo "  Paired:   $paired_date"
      echo "  Connect:  ssh $alias"
    else
      echo "  ${file##*/} (install jq for detailed info)"
    fi
  done
  echo ""
}

# Show detailed info about a controller
show_controller_info() {
  local alias=$1
  local metadata_file="${CONTROLLER_DB}/${alias}.json"
  
  if [[ ! -f "$metadata_file" ]]; then
    die "Controller '${alias}' not found in registry"
  fi
  
  echo ""
  echo "Controller Information: ${alias}"
  echo "========================================"
  
  if command -v jq >/dev/null 2>&1; then
    jq -r 'to_entries | .[] | "  \(.key | ascii_upcase): \(.value)"' "$metadata_file"
  else
    cat "$metadata_file"
  fi
  
  echo ""
  
  # Check if we can connect
  local ip=$(jq -r '.ip' "$metadata_file" 2>/dev/null || echo "unknown")
  if [[ "$ip" != "unknown" ]]; then
    echo "Testing connection..."
    if test_connection "$ip" 22 3; then
      echo -e "  ${GREEN}✓${NC} Port 22 is reachable"
    else
      echo -e "  ${RED}✗${NC} Port 22 is NOT reachable"
    fi
  fi
  echo ""
}

# Delete a controller registration
delete_controller() {
  local alias=$1
  local metadata_file="${CONTROLLER_DB}/${alias}.json"
  local known_hosts_file="${KNOWN_HOSTS_DIR}/${alias}"
  local ssh_config="$HOME/.ssh/config"
  
  if [[ ! -f "$metadata_file" ]]; then
    die "Controller '${alias}' not found in registry"
  fi
  
  warn "This will remove:"
  echo "  - Metadata: ${metadata_file}"
  echo "  - Known hosts: ${known_hosts_file}"
  echo "  - SSH config entry for: ${alias}"
  echo ""
  
  read -p "Are you sure you want to delete '${alias}'? (y/N) " -n 1 -r
  echo
  
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
  fi
  
  # Remove metadata
  [[ -f "$metadata_file" ]] && rm -f "$metadata_file" && log "Removed metadata"
  
  # Remove known_hosts
  [[ -f "$known_hosts_file" ]] && rm -f "$known_hosts_file" && log "Removed known_hosts"
  
  # Remove from SSH config
  if [[ -f "$ssh_config" ]]; then
    local tmpfile=$(mktemp)
    awk -v alias="$alias" '
      /^Host[[:space:]]+/ {
        in_target = ($0 ~ "^Host[[:space:]]+" alias "([[:space:]]|$)")
        if (!in_target) print
        next
      }
      /^Match[[:space:]]+/ {
        in_target = 0
        print
        next
      }
      /^[^[:space:]]/ && in_target {
        in_target = 0
      }
      !in_target {
        print
      }
    ' "$ssh_config" > "$tmpfile"
    mv "$tmpfile" "$ssh_config"
    log "Removed SSH config entry"
  fi
  
  log "Controller '${alias}' deleted successfully"
}

# Check for alias collision
check_alias_collision() {
  local alias=$1
  local ip=$2
  local metadata_file="${CONTROLLER_DB}/${alias}.json"
  
  if [[ -f "$metadata_file" ]]; then
    if command -v jq >/dev/null 2>&1; then
      local existing_ip=$(jq -r '.ip' "$metadata_file")
      local existing_hostname=$(jq -r '.hostname // "unknown"' "$metadata_file")
      
      if [[ "$existing_ip" == "$ip" ]]; then
        info "Alias '${alias}' already exists for this IP. Will update/re-pair."
      else
        warn "Alias '${alias}' already used for different IP: ${existing_ip} (hostname: ${existing_hostname})"
        read -p "Continue and overwrite? (y/N) " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] || exit 1
      fi
    fi
  fi
}

# Helper: run ssh commands with optional sshpass
run_ssh() {
  local cmd=("$@")
  
  if [[ $DRY_RUN -eq 1 ]]; then
    echo -e "${BLUE}[DRY-RUN]${NC} Would execute: ${cmd[*]}" >&2
    return 0
  fi
  
  debug "Executing: ${cmd[*]}"
  
  # Check for password file first, then environment variable
  local password_file="${PASSWORD_DIR}/${ALIAS}.pass"
  
  if command -v sshpass >/dev/null 2>&1; then
    if [[ -n "${SSH_PASSWORD:-}" ]]; then
      debug "Using password from SSH_PASSWORD environment variable"
      sshpass -p "$SSH_PASSWORD" "${cmd[@]}"
    elif [[ -f "$password_file" ]]; then
      debug "Using password from file: ${password_file}"
      sshpass -f "$password_file" "${cmd[@]}"
    else
      "${cmd[@]}"
    fi
  else
    "${cmd[@]}"
  fi
}

# Generate default alias
generate_alias() {
  local ip=$1
  
  if validate_ipv4 "$ip"; then
    echo "controller-${ip##*.}"
  elif [[ "$ip" =~ : ]]; then
    # IPv6
    local sanitized="${ip//[^a-fA-F0-9]/-}"
    echo "controller-${sanitized}"
  else
    # Hostname or other
    local sanitized="${ip//[^a-zA-Z0-9._-]/-}"
    echo "controller-${sanitized}"
  fi
}

# Find default public key
find_default_pubkey() {
  local key_types=(ed25519 ecdsa rsa)
  
  for keytype in "${key_types[@]}"; do
    if [[ -f "$HOME/.ssh/id_${keytype}.pub" ]]; then
      echo "$HOME/.ssh/id_${keytype}.pub"
      return 0
    fi
  done
  
  return 1
}

# Store controller metadata
store_metadata() {
  local alias=$1
  local ip=$2
  local user=$3
  local pubkey_path=$4
  local hostname=${5:-unknown}
  
  local metadata_file="${CONTROLLER_DB}/${alias}.json"
  
  debug "Storing metadata to: ${metadata_file}"
  
  cat > "$metadata_file" <<EOF
{
  "alias": "${alias}",
  "ip": "${ip}",
  "user": "${user}",
  "pubkey": "${pubkey_path}",
  "hostname": "${hostname}",
  "paired_date": "$(date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S%z)",
  "script_version": "${SCRIPT_VERSION}"
}
EOF
  
  chmod 600 "$metadata_file"
}

# Main pairing function
pair_controller() {
  local ip=$1
  local user=$2
  local alias=$3
  local pubkey_path=$4
  
  # Generate alias if not provided
  if [[ -z "$alias" ]]; then
    alias=$(generate_alias "$ip")
    debug "Generated alias: ${alias}"
  fi
  
  # Find default pubkey if not provided
  if [[ -z "$pubkey_path" ]]; then
    if ! pubkey_path=$(find_default_pubkey); then
      die "No default public key found (~/.ssh/id_ed25519.pub, id_ecdsa.pub, or id_rsa.pub).\nGenerate one with: ssh-keygen -t ed25519"
    fi
    debug "Using default public key: ${pubkey_path}"
  fi
  
  # Validate inputs
  [[ -f "$pubkey_path" ]] || die "Public key not found: ${pubkey_path}"
  
  local identity_file="${pubkey_path%.pub}"
  [[ -f "$identity_file" ]] || die "Private key not found (expected: ${identity_file})"
  
  # Validate IP format
  if validate_ipv4 "$ip"; then
    debug "Valid IPv4 address: ${ip}"
  else
    debug "Not IPv4, assuming hostname or IPv6: ${ip}"
  fi
  
  # Check for alias collision
  check_alias_collision "$alias" "$ip"
  
  # Test network connectivity
  log "Testing network connectivity to ${ip}:22..."
  if ! test_connection "$ip" 22 5; then
    die "Cannot reach ${ip}:22. Check network connectivity and ensure SSH is running."
  fi
  log "Connection test successful"
  
  # Setup SSH options
  local known_hosts_file="${KNOWN_HOSTS_DIR}/${alias}"
  local ssh_target="${user}@${ip}"
  
  local -a ssh_opts_common
  if [[ $STRICT_MODE -eq 1 ]]; then
    info "Using STRICT mode (StrictHostKeyChecking=accept-new)"
    ssh_opts_common=(
      -o StrictHostKeyChecking=accept-new
      -o UserKnownHostsFile="$known_hosts_file"
      -o LogLevel=ERROR
    )
  else
    info "Using PERMISSIVE mode (StrictHostKeyChecking=no) - suitable for dev with same IP, different controllers"
    ssh_opts_common=(
      -o StrictHostKeyChecking=no
      -o UserKnownHostsFile="$known_hosts_file"
      -o LogLevel=ERROR
    )
  fi
  
  log "Pairing controller at ${ssh_target}"
  log "Using public key: ${pubkey_path}"
  log "Using private key: ${identity_file}"
  log "SSH config alias: ${alias}"
  log "Known hosts file: ${known_hosts_file}"
  
  # Pre-flight check: are we already paired?
  log "Checking if already paired by attempting key-only auth..."
  local already_paired=0
  if ssh \
    -i "$identity_file" \
    -o IdentitiesOnly=yes \
    -o PreferredAuthentications=publickey \
    -o PubkeyAuthentication=yes \
    -o PasswordAuthentication=no \
    -o BatchMode=yes \
    -o ConnectTimeout=6 \
    "${ssh_opts_common[@]}" \
    "$ssh_target" "true" >/dev/null 2>&1
  then
    log "Already paired (key auth works). Skipping key installation."
    already_paired=1
  else
    debug "Key auth failed, will install key"
    already_paired=0
  fi
  
  # Prepare remote ~/.ssh (using password auth)
  log "Preparing remote ~/.ssh and permissions (password auth)..."
  run_ssh ssh \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o PasswordAuthentication=yes \
    "${ssh_opts_common[@]}" \
    "$ssh_target" \
    "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
  
  # Install key if not already paired
  if [[ $already_paired -eq 0 ]]; then
    log "Installing SSH key on controller..."
    
    if command -v ssh-copy-id >/dev/null 2>&1; then
      debug "Using ssh-copy-id"
      run_ssh ssh-copy-id \
        -i "$pubkey_path" \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o PasswordAuthentication=yes \
        "${ssh_opts_common[@]}" \
        "$ssh_target"
    else
      debug "ssh-copy-id not found, using manual method"
      local pubkey_contents
      pubkey_contents=$(<"$pubkey_path")
      run_ssh ssh \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o PasswordAuthentication=yes \
        "${ssh_opts_common[@]}" \
        "$ssh_target" \
        "grep -qxF '$pubkey_contents' ~/.ssh/authorized_keys || echo '$pubkey_contents' >> ~/.ssh/authorized_keys"
    fi
  fi
  
  # Get remote hostname for metadata
  log "Retrieving remote hostname..."
  local remote_hostname="unknown"
  if remote_hostname=$(ssh \
    -i "$identity_file" \
    -o IdentitiesOnly=yes \
    -o PreferredAuthentications=publickey \
    -o PubkeyAuthentication=yes \
    -o PasswordAuthentication=no \
    -o BatchMode=yes \
    -o ConnectTimeout=8 \
    "${ssh_opts_common[@]}" \
    "$ssh_target" "hostname" 2>/dev/null); then
    debug "Remote hostname: ${remote_hostname}"
  else
    debug "Could not retrieve hostname, using 'unknown'"
  fi
  
  # Update SSH config
  local ssh_config="$HOME/.ssh/config"
  touch "$ssh_config"
  chmod 600 "$ssh_config"
  
  local backup="${ssh_config}.bak.$(date +%Y%m%d-%H%M%S)"
  cp "$ssh_config" "$backup"
  log "Backed up SSH config to: ${backup}"
  
  # Remove existing block for this Host alias
  log "Updating SSH config..."
  local tmpfile
  tmpfile=$(mktemp)
  awk -v alias="$alias" '
    /^Host[[:space:]]+/ {
      in_target = ($0 ~ "^Host[[:space:]]+" alias "([[:space:]]|$)")
      if (!in_target) print
      next
    }
    /^Match[[:space:]]+/ {
      in_target = 0
      print
      next
    }
    /^[^[:space:]]/ && in_target {
      in_target = 0
    }
    !in_target {
      print
    }
  ' "$ssh_config" > "$tmpfile"
  mv "$tmpfile" "$ssh_config"
  
  # Add new entry
  local host_key_checking="no"
  [[ $STRICT_MODE -eq 1 ]] && host_key_checking="accept-new"
  
  cat >> "$ssh_config" <<EOF

Host ${alias}
  HostName ${ip}
  User ${user}
  IdentityFile ${identity_file}
  IdentitiesOnly yes
  PreferredAuthentications publickey
  StrictHostKeyChecking ${host_key_checking}
  UserKnownHostsFile ${known_hosts_file}
  LogLevel ERROR
EOF
  
  log "Added/updated SSH config entry: Host ${alias}"
  
  # Store metadata
  store_metadata "$alias" "$ip" "$user" "$pubkey_path" "$remote_hostname"
  log "Stored controller metadata"
  
  # Verify key auth works
  log "Testing key-only login via alias..."
  if ssh \
    -o BatchMode=yes \
    -o ConnectTimeout=8 \
    "$alias" "echo 'Key auth verified on' \"\$(hostname)\"" >/dev/null 2>&1
  then
    log "✓ Key auth verified successfully!"
    echo ""
    echo -e "${GREEN}SUCCESS!${NC} Controller paired successfully."
    echo ""
    echo "Connect with: ${GREEN}ssh ${alias}${NC}"
    echo "Controller: ${remote_hostname} (${ip})"
    echo ""
  else
    warn "Key-auth test failed."
    echo ""
    echo "Try manual connection with verbose output:"
    echo "  ssh -vvv ${alias}"
    echo ""
    echo "Or test directly:"
    echo "  ssh -vvv -i '${identity_file}' -o IdentitiesOnly=yes ${ssh_opts_common[*]} ${ssh_target}"
    exit 1
  fi
}

# Parse command line arguments
parse_args() {
  local -a positional_args=()
  
  while [[ $# -gt 0 ]]; do
    case $1 in
      -h|--help)
        usage
        exit 0
        ;;
      -v|--verbose)
        VERBOSE=1
        shift
        ;;
      -n|--dry-run)
        DRY_RUN=1
        shift
        ;;
      -s|--strict)
        STRICT_MODE=1
        shift
        ;;
      -l|--list)
        list_controllers
        exit 0
        ;;
      -d|--delete)
        [[ -z "${2:-}" ]] && die "Option --delete requires an alias argument"
        delete_controller "$2"
        exit 0
        ;;
      -i|--info)
        [[ -z "${2:-}" ]] && die "Option --info requires an alias argument"
        show_controller_info "$2"
        exit 0
        ;;
      -*)
        die "Unknown option: $1\nUse --help for usage information"
        ;;
      *)
        positional_args+=("$1")
        shift
        ;;
    esac
  done
  
  # Restore positional arguments
  set -- "${positional_args[@]}"
  
  # Export for use in main
  export PARSED_IP="${1:-}"
  export PARSED_USER="${2:-}"
  export PARSED_ALIAS="${3:-}"
  export PARSED_PUBKEY="${4:-}"
}

# Main entry point
main() {
  # Setup
  setup_directories
  
  # Parse arguments
  parse_args "$@"
  
  # Validate required arguments
  if [[ -z "$PARSED_IP" || -z "$PARSED_USER" ]]; then
    usage
    exit 1
  fi
  
  # Set alias global for run_ssh function
  ALIAS="$PARSED_ALIAS"
  if [[ -z "$ALIAS" ]]; then
    ALIAS=$(generate_alias "$PARSED_IP")
  fi
  
  # Execute pairing
  pair_controller "$PARSED_IP" "$PARSED_USER" "$PARSED_ALIAS" "$PARSED_PUBKEY"
}

# Run main
main "$@"