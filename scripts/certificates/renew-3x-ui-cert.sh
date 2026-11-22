#!/usr/bin/env bash
set -euo pipefail
umask 077

domain="servicevps.shamberservice.com"
expected_lineage="/etc/letsencrypt/live/$domain"
lineage="${RENEWED_LINEAGE:-$expected_lineage}"
destination="/root/3x-ui/cert/$domain"
copy_only=false

if [ "${1:-}" = "--copy-only" ] && [ "$#" -eq 1 ]; then
    copy_only=true
elif [ "$#" -ne 0 ]; then
    printf '%s\n' 'Usage: renew-3x-ui-cert.sh [--copy-only]' >&2
    exit 2
fi

if [ "$lineage" != "$expected_lineage" ]; then
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' 'Run this certificate hook as root.' >&2
    exit 1
fi

openssl x509 -in "$lineage/fullchain.pem" -noout -checkend 0 >/dev/null
openssl verify -verify_hostname "$domain" -untrusted "$lineage/chain.pem" "$lineage/cert.pem" >/dev/null
certificate_public_key_hash=$(openssl x509 -in "$lineage/fullchain.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d ' ' -f 1)
private_key_public_hash=$(openssl pkey -in "$lineage/privkey.pem" -pubout -outform DER | sha256sum | cut -d ' ' -f 1)

if [ "$certificate_public_key_hash" != "$private_key_public_hash" ]; then
    printf '%s\n' 'Certificate and private key do not match.' >&2
    exit 1
fi

if cmp -s "$lineage/fullchain.pem" "$destination/fullchain.pem" && cmp -s "$lineage/privkey.pem" "$destination/privkey.pem"; then
    exit 0
fi

install -d -m 700 "$destination"
temporary_directory=$(mktemp -d "$destination/.renew.XXXXXX")
trap 'rm -f -- "$temporary_directory/fullchain.pem" "$temporary_directory/privkey.pem"; rmdir -- "$temporary_directory"' EXIT
install -m 644 "$lineage/fullchain.pem" "$temporary_directory/fullchain.pem"
install -m 600 "$lineage/privkey.pem" "$temporary_directory/privkey.pem"
mv -f -- "$temporary_directory/fullchain.pem" "$destination/fullchain.pem"
mv -f -- "$temporary_directory/privkey.pem" "$destination/privkey.pem"

if [ "$copy_only" = false ] && [ "$(docker inspect --format '{{.State.Running}}' 3x-ui)" = true ]; then
    docker restart --time 30 3x-ui >/dev/null
fi
