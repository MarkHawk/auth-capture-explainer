# Throwaway capture tools for scripts/capture_from_lab.sh: tcpdump to record,
# socat to relay plain LDAP to the lab's LDAPS, and the OpenLDAP client tools
# to repeat the binds. Nothing here runs inside identity-lab's own containers.
# The base image is pinned by digest (Alpine 3.24).
FROM alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache tcpdump socat openldap-clients
