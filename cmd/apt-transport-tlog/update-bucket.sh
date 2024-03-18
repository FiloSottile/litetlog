#!/bin/bash
set -xeuo pipefail

cd "$(mktemp -d)"

rclone -v sync "$BUCKET" .

cd debian

while true; do
    sleep 60; date

    updated=$(rsync debian.csail.mit.edu::debian/dists/ ./ \
        --include '*/' --include InRelease --exclude '*' \
        --prune-empty-dirs --copy-links \
        --out-format='%n' --recursive --times | grep 'InRelease$') || \
        continue

    while IFS= read -r f; do
        rm "$f.spicy"
    done <<< "$updated"

    xargs spicy -assets ../log -key "$TLOG_KEY_PATH" <<< "$updated"

    rclone -v sync .. "$BUCKET"
done
