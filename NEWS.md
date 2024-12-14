## v0.3.0

### litewitness

- Reduced Info log level verbosity, increased Debug log level verbosity.

- `-key` is now an SSH fingerprint (with `SHA256:` prefix) as printed by
  `ssh-add -l`. The old format is still accepted for compatibility.

- The verifier key of the witness is logged on startup.

### witnessctl

- New `add-key` and `del-key` commands.

- `add-log -key` was removed. The key is now added with `add-key`.

## v0.2.1

### litewitness

- Fix cosignature endianness. https://github.com/FiloSottile/litetlog/issues/12
