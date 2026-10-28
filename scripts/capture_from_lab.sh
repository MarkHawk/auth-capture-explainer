#!/usr/bin/env bash
# Capture identity-lab traffic for auth-capture-explainer's lab samples, from outside
# the lab, then sanitise it into samples/lab/<label>.pcap.
#
#   scripts/capture_from_lab.sh <label> [<label> ...]     or     all
#
# Labels and how each is made (samples/lab/README.md has the full story):
#   radius-accept       real lab traffic: dave logs in through the lab NAS
#   radius-reject       real lab traffic: dave with a wrong password
#   radius-05-broken    real lab traffic: scenario 05 broken, dave logs in
#   radius-05-fixed     real lab traffic: scenario 05 fixed again, dave logs in
#   ldap-good           repeated: Keycloak's two binds (service account, then
#                       dave), sent to the lab directory through a relay
#   ldap-04-broken      repeated: one good login, then the service account
#                       with the wrong value scenario 04 stores in Keycloak
#   ldap-04-fixed       repeated: as ldap-good, after scenario 04 is fixed
#   ldaps-04-encrypted  real lab traffic: Keycloak's own LDAPS bind while 04 is
#                       broken, encrypted, as anyone capturing it would see it
#
# Nothing in identity-lab is changed. The script runs the lab's own scripts
# (break.sh, fix.sh, status.sh) and logins, and leaves each scenario as it
# found it. Capture runs in throwaway containers: tcpdump sharing a lab
# container's network namespace, or, for the repeated LDAP binds, a container
# on the lab network that relays plain LDAP on its own loopback to the lab's
# LDAPS and records the plain side (the lab directory speaks LDAPS only).
#
# The lab's LDAP service account and demo user passwords are read from
# $LAB_DIR/.env by this script. They reach the containers through the
# environment and files inside them, never a command line, and are never
# printed. Raw captures go to scratch/lab/ (gitignored) and are deleted once
# sanitised, as they hold those passwords and packets keyed with the lab's
# real RADIUS secret. Keep them with KEEP_RAW=1.
set -euo pipefail

cd "$(dirname "$0")/.."
LAB_DIR="${LAB_DIR:-$HOME/identity-lab}"
IMAGE=auth-capture-explainer-capture:local
RAW=scratch/lab
PY=venv/bin/python
NAME="auth-capture-explainer-capture-$$"
LABELS=(radius-accept radius-reject radius-05-broken radius-05-fixed ldap-good ldap-04-broken ldap-04-fixed
        ldaps-04-encrypted)
SVC_DN="cn=keycloak-svc,ou=services,dc=idlab,dc=example"
DAVE_DN="uid=dave,ou=people,dc=idlab,dc=example"
WRONG_BIND="not-the-bind-password"  # scenario 04's value, published in identity-lab
WAIT=7  # seconds before and after each login: longer than the lab's 5 s RADIUS health check

die() { echo "capture_from_lab: $*" >&2; exit 2; }
say() { echo "capture_from_lab: $*"; }

[[ $# -ge 1 ]] || die "usage: $0 <label> ... | all   (labels: ${LABELS[*]})"
[[ -x "$PY" ]] || die "no venv; run: python3 -m venv venv && venv/bin/pip install -r requirements-dev.txt"
[[ -r "$LAB_DIR/.env" ]] || die "cannot read $LAB_DIR/.env (set LAB_DIR to the identity-lab checkout)"
[[ -r "$LAB_DIR/certs/ca.crt" ]] || die "cannot read the lab CA certificate in $LAB_DIR/certs"
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker build -q -t "$IMAGE" scripts/capture >/dev/null

# lab_env NAME: a value from the lab's .env, never echoed.
lab_env() {
  local line
  line="$(grep -E "^$1=" "$LAB_DIR/.env" | tail -n 1)" || die "$1 is not in the lab's .env"
  line="${line#*=}"
  line="${line%\"}"; line="${line#\"}"
  printf '%s' "$line"
}

lab() { (cd "$LAB_DIR" && "$@"); }

# Read once, up front, so a missing value stops the script here rather than
# reaching a login as an empty string.
SVC_PASSWORD="$(lab_env LDAP_BIND_PASSWORD)"
DEMO_PASSWORD="$(lab_env DEMO_PASSWORD)"
[[ -n "$SVC_PASSWORD" && -n "$DEMO_PASSWORD" ]] || die "the lab's .env has an empty password"

# state <scenario>: healthy or broken, from the lab's own status script.
state() { lab scripts/status.sh 2>/dev/null | awk -v s="$1" '$1 == s {print $2}'; }

ensure() { # <scenario> <healthy|broken>
  local now
  now="$(state "$1")"
  [[ "$now" == "$2" ]] && return
  if [[ "$2" == broken ]]; then lab scripts/break.sh "$1" >/dev/null; else lab scripts/fix.sh "$1" >/dev/null; fi
  [[ "$(state "$1")" == "$2" ]] || die "$1 did not become $2"
}

restore() { # put scenarios back as they were when the script started
  [[ -n "${START_04:-}" ]] && ensure ldap-bind-failure "$START_04"
  [[ -n "${START_05:-}" ]] && ensure radius-shared-secret-mismatch "$START_05"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
START_04="$(state ldap-bind-failure)"
START_05="$(state radius-shared-secret-mismatch)"
trap restore EXIT

# --- capturing in a lab container's network namespace ------------------------------------

start_tcpdump() { # <lab container> <interface> <filter> <raw file name>
  mkdir -p "$RAW"
  docker run -d --rm --name "$NAME" --net "container:$1" -v "$PWD/$RAW:/out" "$IMAGE" \
    tcpdump -i "$2" -U -Z root -w "/out/$4" "$3" >/dev/null
  sleep 1
}

stop_tcpdump() { # <raw file name>
  docker exec "$NAME" chown "$(id -u):$(id -g)" "/out/$1"
  docker stop -t 2 "$NAME" >/dev/null
}

nas_login() { # <password>: dave logs in through the lab NAS; the password goes in on stdin
  printf '%s' "$1" | lab docker compose exec -T nas nas-auth dave || true
}

radius_capture() { # <label> <05 state> <password>
  ensure radius-shared-secret-mismatch "$2"
  start_tcpdump identity-lab-radius-1 any "udp port 1812 or udp port 1813" "$1.pcap"
  sleep "$WAIT"
  nas_login "$3"
  sleep "$WAIT"
  stop_tcpdump "$1.pcap"
}

# --- repeating Keycloak's binds through a relay ---------------------------------------------

# The container records loopback port 389, where the relay listens, while the
# client tools bind through it. Its argument is the sequence of binds to make.
relay_capture() { # <label> <sequence: good, broken-after-good>
  mkdir -p "$RAW"
  SVC_PW="$SVC_PASSWORD" DAVE_PW="$DEMO_PASSWORD" \
  docker run --rm --name "$NAME" --network identity-lab_default \
    -e SVC_PW -e DAVE_PW -e SVC_DN="$SVC_DN" -e DAVE_DN="$DAVE_DN" -e WRONG_BIND="$WRONG_BIND" -e SEQ="$2" \
    -e OWNER="$(id -u):$(id -g)" -e OUT="/out/$1.pcap" \
    -v "$PWD/$RAW:/out" -v "$LAB_DIR/certs/ca.crt:/etc/idlab/ca.crt:ro" "$IMAGE" sh -c '
set -e
umask 077
printf "%s" "$SVC_PW" > /run/svc; printf "%s" "$DAVE_PW" > /run/dave; unset SVC_PW DAVE_PW
tcpdump -i lo -U -Z root -w "$OUT" "tcp port 389" 2>/dev/null &
TD=$!
socat TCP-LISTEN:389,bind=127.0.0.1,reuseaddr,fork OPENSSL:ldap:1636,cafile=/etc/idlab/ca.crt,verify=1 2>/dev/null &
sleep 1
H=ldap://127.0.0.1:389
login() {  # what Keycloak does: bind as its account and find the user, then bind as the user
  ldapsearch -x -LLL -H $H -D "$SVC_DN" -y /run/svc -b ou=people,dc=idlab,dc=example -s one \
    "(&(objectClass=inetOrgPerson)(uid=dave))" dn >/dev/null
  ldapwhoami -x -H $H -D "$DAVE_DN" -y /run/dave >/dev/null
}
login
if [ "$SEQ" = broken-after-good ]; then
  sleep 1
  ldapwhoami -x -H $H -D "$SVC_DN" -w "$WRONG_BIND" >/dev/null 2>&1 || true
fi
sleep 1; kill $TD; wait $TD 2>/dev/null || true
chown "$OWNER" "$OUT"
'
}

ldaps_capture() { # <label>: Keycloak's own LDAPS bind, while 04 is broken
  ensure ldap-bind-failure broken
  start_tcpdump identity-lab-ldap-1 eth0 "tcp port 1636" "$1.pcap"
  sleep 2
  lab scripts/status.sh >/dev/null 2>&1 || true  # asks Keycloak to test its LDAP bind
  sleep 3
  stop_tcpdump "$1.pcap"
}

capture() {
  case "$1" in
    radius-accept)      radius_capture "$1" healthy "$DEMO_PASSWORD" ;;
    radius-reject)      radius_capture "$1" healthy "wrong-password" ;;
    radius-05-broken)   radius_capture "$1" broken "$DEMO_PASSWORD" ;;
    radius-05-fixed)    ensure radius-shared-secret-mismatch broken
                        radius_capture "$1" healthy "$DEMO_PASSWORD" ;;
    ldap-good)          relay_capture "$1" good ;;
    ldap-04-broken)     ensure ldap-bind-failure broken; relay_capture "$1" broken-after-good ;;
    ldap-04-fixed)      ensure ldap-bind-failure broken; ensure ldap-bind-failure healthy
                        relay_capture "$1" good ;;
    ldaps-04-encrypted) ldaps_capture "$1" ;;
    *) die "unknown label $1 (labels: ${LABELS[*]})" ;;
  esac
}

[[ "$1" == all ]] && set -- "${LABELS[@]}"
for label in "$@"; do
  say "capturing $label"
  capture "$label"
  "$PY" scripts/sanitise_capture.py "$label" "$RAW/$label.pcap" --lab-env "$LAB_DIR/.env"
  [[ "${KEEP_RAW:-}" == 1 ]] || rm -f "$RAW/$label.pcap"
done
"$PY" scripts/sanitise_capture.py --check samples/lab --lab-env "$LAB_DIR/.env"
say "done. Review samples/lab, then run the tests before committing."
