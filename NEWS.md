## v0.4.0

### litebastion

- Backend connection lifecycle events (including new details about errors) are
  now logged at the INFO level (the default). Client-side errors and HTTP/2
  debug logs are now logged at the DEBUG level.

- `Config.Log` is now a `log/slog.Logger` instead of a `log.Logger`.

- `/logz` now exposes the debug logs in a simple public web console. At most ten
  clients can connect to it at a time.

- New `-home-redirect` flag redirects the root to the given URL.

### litewitness

- `/logz` now exposes the debug logs in a simple public web console. At most ten
  clients can connect to it at a time.

## v0.3.0

### litewitness

- Reduced Info log level verbosity, increased Debug log level verbosity.

- Sending SIGUSR1 (`killall -USR1 litewitness`) will toggle log level between
  Info and Debug.

- `-key` is now an SSH fingerprint (with `SHA256:` prefix) as printed by
  `ssh-add -l`. The old format is still accepted for compatibility.

- The verifier key of the witness is logged on startup.

- A small homepage listing the verifier key and the known logs is served at /.

### witnessctl

- New `add-key` and `del-key` commands.

- `add-log -key` was removed. The key is now added with `add-key`.

## v0.2.1

### litewitness

- Fix cosignature endianness. https://github.com/FiloSottile/litetlog/issues/12
