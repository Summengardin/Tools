#!/usr/bin/env bash
set -euo pipefail

# pair-controller.sh
# Version 4.0
#
# Model:
#   - Controllers are named by an ALIAS (e.g., GWA, GWB, Lift).
#   - Controllers belong to a PROJECT (e.g., 102156).
#   - The stable SSH host entries are:  <ALIAS>-<PROJECT>[-<CONTROLLER_ID>]
#       Examples: GWA-102156, GWB-102156, Lift-102156, GWA-102156-spare
#   - You can set a CURRENT PROJECT. Then bare aliases resolve within that project:
#       ssh GWA  (=> connects to GWA-<current_project>)
#
# This script:
#   - installs your SSH public key onto the controller (password auth once),
#   - registers metadata per host alias,
#   - writes SSH config host entries,
#   - manages a "CURRENT-PROJECT" block in ~/.ssh/config that rewrites bare aliases.

SCRIPT_VERSION="4.2"

# Storage
REG_DIR="$HOME/.ssh/controller_registry"
KNOWN_HOSTS_DIR="$HOME/.ssh/known_hosts_controllers"
PROJECT_DB="$REG_DIR/projects"
CURRENT_PROJECT_FILE="$REG_DIR/.current_project"

# Managed block markers for ~/.ssh/config
CURRENT_BLOCK_BEGIN="# BEGIN pair-controller CURRENT-PROJECT"
CURRENT_BLOCK_END="# END pair-controller CURRENT-PROJECT"

# Runtime flags
VERBOSE=0
DRY_RUN=0
STRICT_MODE=0
FORCE_REPAIR=0
ASK_PASSWORD=0
PASSWORD=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

die() { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }
log() { echo -e "${GREEN}==>${NC} $*"; }
warn(){ echo -e "${YELLOW}WARNING:${NC} $*" >&2; }
info(){ echo -e "${BLUE}[INFO]${NC} $*"; }
debug(){ [[ $VERBOSE -eq 1 ]] && echo -e "${BLUE}[DEBUG]${NC} $*" >&2 || true; }

usage() {
  cat <<'EOF'
Usage:
  pair-controller.sh [OPTIONS] <controller_ip_or_host> <user> [pubkey_path]

Core model:
  - Controllers are identified by an ALIAS (e.g., GWA, GWB, Lift).
  - Controllers belong to a PROJECT (e.g., 102156).
  - Stable SSH hosts are: <ALIAS>-<PROJECT>[-<CONTROLLER_ID>]
  - If you set a current project, bare aliases resolve within that project:
      ssh GWA   -> connects to GWA-<current_project>

Pairing:
  ./pair-controller.sh --project 102156 --alias GWA 10.1.2.1 root
  ./pair-controller.sh --project 102156 --alias GWB 10.2.1.3 root
  ./pair-controller.sh --project 102156 --alias Lift 10.5.6.3 root

Workflow:
  ./pair-controller.sh --set-current-project 102156
  ssh GWA
  ssh GWB
  ssh Lift

Temporary jump (without switching current project):
  ssh GWA-204400

Options:
  -v, --verbose                    Verbose output
  -n, --dry-run                    Show what would be done without doing it
  -s, --strict                     Strict host key checking (accept-new instead of no)

Identity:
  -p, --project PROJECT            Project identifier (required for pairing)
  -a, --alias ALIAS                Controller alias base (required for pairing, e.g. GWA, GWB, Lift)
  --controller ID                  Optional controller identifier (only for duplicates, e.g. spare)
  --ask-password                   Prompt for controller password (safer than --password)
  --password PASSWORD              Provide password via CLI (insecure; avoid if possible)

Registry:
  -l, --list                       List registered controllers
  -i, --info HOSTALIAS             Show info for a specific host alias (e.g., GWA-102156)
  -d, --delete HOSTALIAS           Delete registration + host config entry for that alias
  -r, --repair HOSTALIAS           Re-pair to an existing host alias (force key installation)

Current project:
  --set-current-project PROJECT    Set current project (rewrites bare alias hosts)
  --show-current-project           Show current project and available bare aliases

Compatibility (older versions):
  --unique-id ID                   Treated as --project ID (deprecated)
  --set-current HOSTALIAS          Sets current project to HOSTALIAS's project (deprecated)

EOF
}

# ---------- helpers ----------

setup_directories() {
  mkdir -p "$REG_DIR" "$KNOWN_HOSTS_DIR" "$PROJECT_DB" "$HOME/.ssh"
  chmod 700 "$HOME/.ssh" "$REG_DIR" "$KNOWN_HOSTS_DIR" "$PROJECT_DB"
}

require_jq() {
  command -v jq >/dev/null 2>&1 || die "jq is required. Install with: sudo apt install jq"
}

run_cmd() {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "+ $*"
    return 0
  fi
  "$@"
}

ensure_password() {
  # Only used for initial password-auth bootstrap (mkdir ~/.ssh, ssh-copy-id).
  # --ask-password prompts securely; --password is supported but insecure.
  local target_hint="${1:-controller}"
  if [[ $ASK_PASSWORD -eq 1 && -z "$PASSWORD" ]]; then
    read -rsp "Password for ${target_hint}: " PASSWORD
    echo ""
  fi
  if [[ -n "$PASSWORD" ]]; then
    command -v sshpass >/dev/null 2>&1 || die "sshpass is required when using --ask-password/--password. Install with: sudo apt install sshpass"
  fi
}

# Validate IPv4 address (best-effort; hostnames/IPv6 are allowed)
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

test_connection() {
  local host=$1
  local port=${2:-22}
  local timeout_s=${3:-5}
  debug "Testing connectivity to ${host}:${port} ..."
  if timeout "$timeout_s" bash -c "cat < /dev/null > /dev/tcp/${host}/${port}" 2>/dev/null; then
    return 0
  fi
  return 1
}

sanitize_token() {
  # SSH Host patterns are flexible, but keep registry filenames safe/predictable.
  local s=$1
  s="${s//[^a-zA-Z0-9-]/-}"
  echo "${s:0:40}"
}

find_default_pubkey() {
  local candidates=("$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_ecdsa.pub" "$HOME/.ssh/id_rsa.pub")
  for c in "${candidates[@]}"; do
    [[ -f "$c" ]] && { echo "$c"; return 0; }
  done
  return 1
}

project_metadata_file() {
  local project_id="$1"
  echo "$PROJECT_DB/$(sanitize_token "$project_id").json"
}

host_metadata_file() {
  local host_alias="$1"
  echo "$REG_DIR/$(sanitize_token "$host_alias").json"
}

known_hosts_file_for() {
  local host_alias="$1"
  echo "$KNOWN_HOSTS_DIR/$(sanitize_token "$host_alias")"
}

remove_stale_hostkey() {
  local ip="$1"

  if [[ -n "$ip" ]]; then
    log "Removing stale SSH host key for $ip (if any)"
    ssh-keygen -R "$ip" >/dev/null 2>&1 || true
    ssh-keygen -R "[$ip]:22" >/dev/null 2>&1 || true
  fi
}


# ---------- metadata ----------

store_host_metadata() {
  require_jq
  local host_alias="$1" ip="$2" user="$3" pubkey_path="$4" hostname="$5" project_id="$6" alias_base="$7" controller_id="$8"

  local f; f=$(host_metadata_file "$host_alias")
  local now; now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local json
  json="$(jq -n \
    --arg alias "$host_alias" \
    --arg ip "$ip" \
    --arg user "$user" \
    --arg pubkey_path "$pubkey_path" \
    --arg hostname "$hostname" \
    --arg project_id "$project_id" \
    --arg alias_base "$alias_base" \
    --arg controller_id "${controller_id:-}" \
    --arg paired_date "$now" \
    '{
      alias: $alias,
      ip: $ip,
      user: $user,
      pubkey_path: $pubkey_path,
      hostname: $hostname,
      project_id: $project_id,
      alias_base: $alias_base,
      controller_id: ($controller_id | select(length>0)),
      paired_date: $paired_date
    }')"
  echo "$json" > "$f"
  chmod 600 "$f"
}

load_host_field() {
  require_jq
  local host_alias="$1" field="$2"
  local f; f=$(host_metadata_file "$host_alias")
  [[ -f "$f" ]] || return 1
  jq -r --arg field "$field" '.[$field] // empty' "$f"
}

# ---------- ssh config writing ----------

ssh_config_path() { echo "$HOME/.ssh/config"; }

backup_ssh_config() {
  local ssh_config; ssh_config="$(ssh_config_path)"
  touch "$ssh_config"
  chmod 600 "$ssh_config"
  local backup="${ssh_config}.bak.$(date +%Y%m%d-%H%M%S)"
  cp "$ssh_config" "$backup"
  debug "Backed up SSH config to: $backup"
}

remove_host_block() {
  # Remove any "Host <alias>" block (best-effort).
  local alias="$1"
  local ssh_config; ssh_config="$(ssh_config_path)"
  touch "$ssh_config"
  local tmp; tmp="$(mktemp)"

  awk -v alias="$alias" '
    BEGIN{in_target=0}
    /^Host[[:space:]]+/ {
      in_target = ($0 ~ ("^Host[[:space:]]+" alias "([[:space:]]|$)"))
      if (!in_target) print
      next
    }
    /^Match[[:space:]]+/ { in_target=0; print; next }
    /^[^[:space:]]/ && in_target { in_target=0 }
    !in_target { print }
  ' "$ssh_config" > "$tmp"
  mv "$tmp" "$ssh_config"
}

upsert_host_entry() {
  local host_alias="$1" host="$2" user="$3" identity_file="$4" known_hosts_file="$5" comment="${6:-}"

  local ssh_config; ssh_config="$(ssh_config_path)"
  touch "$ssh_config"
  chmod 600 "$ssh_config"

  backup_ssh_config
  remove_host_block "$host_alias"

  local host_key_checking="no"
  [[ $STRICT_MODE -eq 1 ]] && host_key_checking="accept-new"

  {
    echo ""
    [[ -n "$comment" ]] && echo "# ${comment}"
    cat <<EOF
Host ${host_alias}
  HostName ${host}
  User ${user}
  IdentityFile ${identity_file}
  IdentitiesOnly yes
  PreferredAuthentications publickey
  StrictHostKeyChecking ${host_key_checking}
  UserKnownHostsFile ${known_hosts_file}
  LogLevel ERROR
EOF
  } >> "$ssh_config"
}

remove_current_project_block() {
  local ssh_config; ssh_config="$(ssh_config_path)"
  touch "$ssh_config"
  local tmp; tmp="$(mktemp)"
  awk -v b="$CURRENT_BLOCK_BEGIN" -v e="$CURRENT_BLOCK_END" '
    BEGIN{skip=0}
    $0==b {skip=1; next}
    $0==e {skip=0; next}
    skip==0 {print}
  ' "$ssh_config" > "$tmp"
  mv "$tmp" "$ssh_config"
}

remove_legacy_gwb_block() {
  # Best-effort cleanup of older v2/v3 "Host GWB" muscle-memory alias so it doesn't surprise users.
  local ssh_config; ssh_config="$(ssh_config_path)"
  touch "$ssh_config"
  local tmp; tmp="$(mktemp)"
  awk '
    BEGIN{in_target=0}
    /^# Current active controller:/ { in_target=1; next }
    /^Host[[:space:]]+GWB([[:space:]]|$)/ { in_target=1; next }
    /^Match[[:space:]]+/ { in_target=0; print; next }
    /^Host[[:space:]]+/ && in_target { in_target=0; print; next }
    !in_target { print }
  ' "$ssh_config" > "$tmp"
  mv "$tmp" "$ssh_config"
}

rebuild_current_project_aliases() {
  require_jq
  local project_id="$1"
  local ssh_config; ssh_config="$(ssh_config_path)"
  touch "$ssh_config"
  chmod 600 "$ssh_config"

  backup_ssh_config
  remove_current_project_block
  remove_legacy_gwb_block

  {
    echo ""
    echo "$CURRENT_BLOCK_BEGIN"
    echo "# project: $project_id"
  } >> "$ssh_config"

  # Build one bare Host per alias_base in the current project.
  # If duplicates exist, first one wins; use --controller to create distinct full aliases.
  local files=("$REG_DIR"/*.json)
  if [[ ! -e "${files[0]}" ]]; then
    # no registry entries
    echo "$CURRENT_BLOCK_END" >> "$ssh_config"
    return 0
  fi

  jq -r --arg p "$project_id" '
    select(.project_id==$p) |
    select((.alias_base // "") != "") |
    [
      .alias_base,
      .ip,
      .user,
      .pubkey_path,
      .alias
    ] | @tsv
  ' "$REG_DIR"/*.json 2>/dev/null \
  | awk -F'\t' '!seen[$1]++' \
  | while IFS=$'\t' read -r abase ip user pubkey_path full_alias; do
      local identity_file="${pubkey_path%.pub}"
      local kh_file; kh_file="$(known_hosts_file_for "$full_alias")"
      local host_key_checking="no"
      [[ $STRICT_MODE -eq 1 ]] && host_key_checking="accept-new"
      cat >> "$ssh_config" <<EOF
Host ${abase}
  HostName ${ip}
  User ${user}
  IdentityFile ${identity_file}
  IdentitiesOnly yes
  PreferredAuthentications publickey
  StrictHostKeyChecking ${host_key_checking}
  UserKnownHostsFile ${kh_file}
  LogLevel ERROR

EOF
    done

  echo "$CURRENT_BLOCK_END" >> "$ssh_config"
}

# ---------- registry operations ----------

list_controllers() {
  require_jq
  local current_project=""
  [[ -f "$CURRENT_PROJECT_FILE" ]] && current_project="$(<"$CURRENT_PROJECT_FILE")"

  local files=("$REG_DIR"/*.json)
  if [[ ! -e "${files[0]}" ]]; then
    info "No controllers registered yet."
    exit 0
  fi

  echo ""
  echo "Registered Controllers"
  echo "====================="
  [[ -n "$current_project" ]] && echo "Current project: ${GREEN}${current_project}${NC}" || echo "Current project: (none)"
  echo ""

  # Group by project (best-effort with jq)
  jq -s '
    group_by(.project_id) |
    map({project_id: .[0].project_id, entries: .})
  ' "$REG_DIR"/*.json \
  | jq -r --arg cp "$current_project" '
    .[] |
    (
      "Project " + .project_id +
      (if .project_id==$cp then "  ★ CURRENT" else "" end) +
      "\n" +
      ( .entries
        | sort_by(.alias_base, .alias)
        | map(
            "  - " + .alias +
            "  (" + .alias_base + " -> " + .ip + " user=" + .user + ")"
          )
        | join("\n")
      ) +
      "\n"
    )
  '
}

show_controller_info() {
  require_jq
  local host_alias="$1"
  local f; f=$(host_metadata_file "$host_alias")
  [[ -f "$f" ]] || die "Host alias '${host_alias}' not found."
  echo ""
  echo "Host: $host_alias"
  echo "=============================="
  jq -r 'to_entries | .[] | "  \(.key): \(.value)"' "$f"
  echo ""
  local ip; ip="$(jq -r '.ip' "$f")"
  echo "Connectivity:"
  if test_connection "$ip" 22 3; then
    echo -e "  ${GREEN}✓${NC} ${ip}:22 reachable"
  else
    echo -e "  ${RED}✗${NC} ${ip}:22 NOT reachable"
  fi
  echo ""
}

delete_controller() {
  require_jq
  local host_alias="$1"
  local f; f=$(host_metadata_file "$host_alias")
  [[ -f "$f" ]] || die "Host alias '${host_alias}' not found."

  local ssh_config; ssh_config="$(ssh_config_path)"
  backup_ssh_config
  remove_host_block "$host_alias"

  local kh; kh="$(known_hosts_file_for "$host_alias")"
  run_cmd rm -f "$f" "$kh"

  # If this alias participates in current project bare hosts, rebuild that block.
  local current_project=""
  [[ -f "$CURRENT_PROJECT_FILE" ]] && current_project="$(<"$CURRENT_PROJECT_FILE")"
  if [[ -n "$current_project" ]]; then
    rebuild_current_project_aliases "$current_project"
  fi

  log "Deleted: $host_alias"
}

# ---------- project operations ----------

set_current_project() {
  local project_id="$1"
  [[ -n "$project_id" ]] || die "--set-current-project requires a project id"

  echo "$project_id" > "$CURRENT_PROJECT_FILE"
  chmod 600 "$CURRENT_PROJECT_FILE"

  rebuild_current_project_aliases "$project_id"

  log "Current project set to: ${project_id}"
  echo "Now you can use bare aliases, e.g.:"
  echo "  ssh GWA"
  echo "  ssh GWB"
}

show_current_project() {
  require_jq
  local project_id=""
  [[ -f "$CURRENT_PROJECT_FILE" ]] && project_id="$(<"$CURRENT_PROJECT_FILE")"
  if [[ -z "$project_id" ]]; then
    echo "No current project set."
    echo "Set one with: ./pair-controller.sh --set-current-project <project>"
    return 0
  fi

  echo "Current project: ${project_id}"
  echo "Bare aliases available (from this project):"
  jq -r --arg p "$project_id" '
    select(.project_id==$p) |
    .alias_base
  ' "$REG_DIR"/*.json 2>/dev/null | sort -u | sed 's/^/  - /'
}

set_current_from_hostalias() {
  # Deprecated compatibility: --set-current <full_alias>
  require_jq
  local host_alias="$1"
  local f; f=$(host_metadata_file "$host_alias")
  [[ -f "$f" ]] || die "Host alias '${host_alias}' not found."
  local project_id; project_id="$(jq -r '.project_id' "$f")"
  warn "--set-current is deprecated; setting current project to '${project_id}' from host '${host_alias}'."
  set_current_project "$project_id"
}

# ---------- pairing logic ----------

generate_host_alias() {
  local alias_base="$1" project_id="$2" controller_id="${3:-}"
  local a; a="$(sanitize_token "$alias_base")"
  local p; p="$(sanitize_token "$project_id")"
  [[ -n "$controller_id" ]] && echo "${a}-${p}-$(sanitize_token "$controller_id")" || echo "${a}-${p}"
}

check_alias_collision() {
  require_jq
  local host_alias="$1" ip="$2"
  local f; f=$(host_metadata_file "$host_alias")
  if [[ -f "$f" ]]; then
    local existing_ip; existing_ip="$(jq -r '.ip' "$f")"
    if [[ "$existing_ip" != "$ip" ]]; then
      die "Alias collision: '${host_alias}' already exists for IP ${existing_ip}. Use --repair ${host_alias} or choose different identifiers."
    fi
  fi
}

pair_controller() {
  require_jq
  local host="$1" user="$2" pubkey_path="${3:-}" project_id="$4" alias_base="$5" controller_id="${6:-}"

  [[ -n "$project_id" ]] || die "--project is required for pairing"
  [[ -n "$alias_base" ]] || die "--alias is required for pairing (e.g. GWA, GWB, Lift)"

  local host_alias
  host_alias="$(generate_host_alias "$alias_base" "$project_id" "$controller_id")"

  if [[ -z "$pubkey_path" ]]; then
    pubkey_path="$(find_default_pubkey)" || die "No default public key found. Generate one with: ssh-keygen -t ed25519"
  fi
  [[ -f "$pubkey_path" ]] || die "Public key not found: $pubkey_path"
  local identity_file="${pubkey_path%.pub}"
  [[ -f "$identity_file" ]] || die "Private key not found: $identity_file"

  check_alias_collision "$host_alias" "$host"

  log "Testing network connectivity to ${host}:22..."
  test_connection "$host" 22 5 || die "Cannot reach ${host}:22"

  local known_hosts_file; known_hosts_file="$(known_hosts_file_for "$host_alias")"
  local ssh_target="${user}@${host}"

  local -a ssh_opts_common
  if [[ $STRICT_MODE -eq 1 ]]; then
    info "STRICT mode (StrictHostKeyChecking=accept-new)"
    ssh_opts_common=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$known_hosts_file" -o LogLevel=ERROR)
  else
    info "PERMISSIVE mode (StrictHostKeyChecking=no)"
    ssh_opts_common=(-o StrictHostKeyChecking=no -o UserKnownHostsFile="$known_hosts_file" -o LogLevel=ERROR)
  fi

  echo ""
  log "Pairing: ${ssh_target}"
  echo "  Project:     $project_id"
  echo "  Alias base:  $alias_base"
  [[ -n "$controller_id" ]] && echo "  Controller:  $controller_id"
  echo "  Host alias:  $host_alias"
  echo "  Pubkey:      $pubkey_path"
  echo ""

  # Key-only preflight (skip if repair)
  local already_paired=0
  if [[ $FORCE_REPAIR -eq 1 ]]; then
    info "REPAIR mode: forcing key installation"
  else
    if ssh \
      -i "$identity_file" \
      -o IdentitiesOnly=yes \
      -o PreferredAuthentications=publickey \
      -o PubkeyAuthentication=yes \
      -o PasswordAuthentication=no \
      -o BatchMode=yes \
      -o ConnectTimeout=6 \
      "${ssh_opts_common[@]}" \
      "$ssh_target" "true" >/dev/null 2>&1; then
      already_paired=1
      log "Already paired (key auth works)."
    fi
  fi

  # Ensure remote ~/.ssh exists (password auth)
  log "Preparing remote ~/.ssh (password auth)..."
  run_cmd ssh \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o PasswordAuthentication=yes \
    -o ConnectTimeout=10 \
    "${ssh_opts_common[@]}" \
    "$ssh_target" \
    "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"

  if [[ $already_paired -eq 0 ]]; then
    log "Removing stale SSH host key (if any)..."
    remove_stale_hostkey "$ip"
    log "Installing SSH key..."
    if command -v ssh-copy-id >/dev/null 2>&1; then
      if [[ -n "$PASSWORD" || $ASK_PASSWORD -eq 1 ]]; then
        ensure_password "$ssh_target"
        run_cmd env SSHPASS="$PASSWORD" sshpass -e ssh-copy-id \
          -i "$pubkey_path" \
          -o PreferredAuthentications=password \
          -o PubkeyAuthentication=no \
          -o PasswordAuthentication=yes \
          "${ssh_opts_common[@]}" \
          "$ssh_target"
      else
        run_cmd ssh-copy-id \
          -i "$pubkey_path" \
          -o PreferredAuthentications=password \
          -o PubkeyAuthentication=no \
          -o PasswordAuthentication=yes \
          "${ssh_opts_common[@]}" \
          "$ssh_target"
      fi
    else
      local pubkey_contents
      pubkey_contents="$(<"$pubkey_path")"
      if [[ -n "$PASSWORD" || $ASK_PASSWORD -eq 1 ]]; then
        ensure_password "$ssh_target"
        run_cmd env SSHPASS="$PASSWORD" sshpass -e ssh \
          -o PreferredAuthentications=password \
          -o PubkeyAuthentication=no \
          -o PasswordAuthentication=yes \
          -o ConnectTimeout=10 \
          "${ssh_opts_common[@]}" \
          "$ssh_target" \
          "grep -qxF '$pubkey_contents' ~/.ssh/authorized_keys || echo '$pubkey_contents' >> ~/.ssh/authorized_keys"
      else
        run_cmd ssh \
          -o PreferredAuthentications=password \
          -o PubkeyAuthentication=no \
          -o PasswordAuthentication=yes \
          -o ConnectTimeout=10 \
          "${ssh_opts_common[@]}" \
          "$ssh_target" \
          "grep -qxF '$pubkey_contents' ~/.ssh/authorized_keys || echo '$pubkey_contents' >> ~/.ssh/authorized_keys"
      fi
    fi
  fi

  # Retrieve hostname (best-effort) using key auth
  local remote_hostname="unknown"
  if remote_hostname="$(ssh \
    -i "$identity_file" \
    -o IdentitiesOnly=yes \
    -o PreferredAuthentications=publickey \
    -o PubkeyAuthentication=yes \
    -o PasswordAuthentication=no \
    -o BatchMode=yes \
    -o ConnectTimeout=8 \
    "${ssh_opts_common[@]}" \
    "$ssh_target" "hostname" 2>/dev/null)"; then
    remote_hostname="${remote_hostname//$'\r'/}"
  else
    remote_hostname="unknown"
  fi

  # Upsert SSH host entry for the stable alias
  local comment="Project: ${project_id} (alias ${alias_base}${controller_id:+/${controller_id}}) (${host})"
  upsert_host_entry "$host_alias" "$host" "$user" "$identity_file" "$known_hosts_file" "$comment"
  log "SSH config updated: Host ${host_alias}"

  # Store metadata
  store_host_metadata "$host_alias" "$host" "$user" "$pubkey_path" "$remote_hostname" "$project_id" "$alias_base" "${controller_id:-}"
  log "Registered: ${host_alias}"

  # If current project matches, refresh bare aliases
  local current_project=""
  [[ -f "$CURRENT_PROJECT_FILE" ]] && current_project="$(<"$CURRENT_PROJECT_FILE")"
  if [[ -n "$current_project" && "$current_project" == "$project_id" ]]; then
    rebuild_current_project_aliases "$project_id"
    log "Refreshed bare aliases for current project: $project_id"
  fi

  echo ""
  echo -e "Connect now:"
  echo -e "  ${GREEN}ssh ${host_alias}${NC}"
  if [[ -f "$CURRENT_PROJECT_FILE" && "$(<"$CURRENT_PROJECT_FILE")" == "$project_id" ]]; then
    echo -e "  ${GREEN}ssh ${alias_base}${NC}  (because current project is ${project_id})"
  fi
  echo ""
}

repair_controller() {
  require_jq
  local host_alias="$1"
  local f; f=$(host_metadata_file "$host_alias")
  [[ -f "$f" ]] || die "Host alias '${host_alias}' not found."

  local host user pubkey_path project_id alias_base controller_id
  host="$(jq -r '.ip' "$f")"
  user="$(jq -r '.user' "$f")"
  pubkey_path="$(jq -r '.pubkey_path' "$f")"
  project_id="$(jq -r '.project_id' "$f")"
  alias_base="$(jq -r '.alias_base' "$f")"
  controller_id="$(jq -r '.controller_id // empty' "$f")"

  FORCE_REPAIR=1
  info "Repairing: ${host_alias} (reinstall key + rewrite ssh config entry)"
  pair_controller "$host" "$user" "$pubkey_path" "$project_id" "$alias_base" "${controller_id:-}"
}

# ---------- argument parsing ----------

ACTION="pair"
LIST=0
SHOW_INFO=""
DELETE_ALIAS=""
REPAIR_ALIAS=""
SET_CURRENT_PROJECT=""
SHOW_CURRENT_PROJECT=0
COMPAT_SET_CURRENT=""

PROJECT_ID=""
ALIAS_BASE=""
CONTROLLER_ID=""
COMPAT_UNIQUE_ID=""

POSITIONALS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -v|--verbose) VERBOSE=1; shift ;;
    -n|--dry-run) DRY_RUN=1; shift ;;
    -s|--strict) STRICT_MODE=1; shift ;;

    -p|--project) PROJECT_ID="${2:-}"; shift 2 ;;
    --unique-id) COMPAT_UNIQUE_ID="${2:-}"; shift 2 ;;
    -a|--alias) ALIAS_BASE="${2:-}"; shift 2 ;;
    --controller) CONTROLLER_ID="${2:-}"; shift 2 ;;

    --ask-password) ASK_PASSWORD=1; shift ;;
    --password) PASSWORD="${2:-}"; warn "--password is insecure (shell history/process list). Prefer --ask-password."; shift 2 ;;

    -l|--list) LIST=1; ACTION="list"; shift ;;
    -i|--info) SHOW_INFO="${2:-}"; ACTION="info"; shift 2 ;;
    -d|--delete) DELETE_ALIAS="${2:-}"; ACTION="delete"; shift 2 ;;
    -r|--repair) REPAIR_ALIAS="${2:-}"; ACTION="repair"; shift 2 ;;

    --set-current-project) SET_CURRENT_PROJECT="${2:-}"; ACTION="set-current-project"; shift 2 ;;
    --show-current-project) SHOW_CURRENT_PROJECT=1; ACTION="show-current-project"; shift ;;

    --set-current) COMPAT_SET_CURRENT="${2:-}"; ACTION="compat-set-current"; shift 2 ;;

    --) shift; break ;;
    -*)
      die "Unknown option: $1"
      ;;
    *)
      POSITIONALS+=("$1"); shift ;;
  esac
done

# Append remaining args (after --)
while [[ $# -gt 0 ]]; do POSITIONALS+=("$1"); shift; done

setup_directories

# Compatibility: unique-id -> project
if [[ -n "$COMPAT_UNIQUE_ID" && -z "$PROJECT_ID" ]]; then
  warn "--unique-id is deprecated; treating as --project."
  PROJECT_ID="$COMPAT_UNIQUE_ID"
fi

case "$ACTION" in
  list)
    list_controllers
    ;;
  info)
    [[ -n "$SHOW_INFO" ]] || die "--info requires a host alias"
    show_controller_info "$SHOW_INFO"
    ;;
  delete)
    [[ -n "$DELETE_ALIAS" ]] || die "--delete requires a host alias"
    delete_controller "$DELETE_ALIAS"
    ;;
  repair)
    [[ -n "$REPAIR_ALIAS" ]] || die "--repair requires a host alias"
    repair_controller "$REPAIR_ALIAS"
    ;;
  set-current-project)
    set_current_project "$SET_CURRENT_PROJECT"
    ;;
  show-current-project)
    show_current_project
    ;;
  compat-set-current)
    [[ -n "$COMPAT_SET_CURRENT" ]] || die "--set-current requires a host alias"
    set_current_from_hostalias "$COMPAT_SET_CURRENT"
    ;;
  pair)
    # Expect: <host> <user> [pubkey]
    [[ ${#POSITIONALS[@]} -ge 2 ]] || { usage; exit 1; }
    host="${POSITIONALS[0]}"
    user="${POSITIONALS[1]}"
    pubkey="${POSITIONALS[2]:-}"
    pair_controller "$host" "$user" "$pubkey" "$PROJECT_ID" "$ALIAS_BASE" "$CONTROLLER_ID"
    ;;
  *)
    die "Internal error: unknown action '$ACTION'"
    ;;
esac
