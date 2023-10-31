# litetlog

The litetlog repository is a collection of open-source tooling for transparency
logs designed to be simple and lightweight.

## litewitness

litewitness is a synchronous low-latency cosigning witness. (A witness is a
service that accepts a new signed tree head, checks its consistency with the
previous latest tree head, and returns a signature over it.)

It's backed by a SQLite database for storage, and by an ssh-agent for private
key operations.

To install it, use `go install`.

```
# from anywhere
go install filippo.io/litetlog/cmd/{litewitness,witnessctl}@latest

# from within a source tree
go install filippo.io/litetlog/cmd/{litewitness,witnessctl}
```

litewitness has no config file. All configuration is done via command line flags
or `witnessctl` (see below).

    -db string
            path to sqlite database (default "litewitness.db")

The SQLite database is where known trees and tree heads are stored. It needs to
be on a filesystem that supports locking (not a network file system). It will be
created if it does not exist.

    -name string
            URL-like (e.g. example.com/foo) name of this witness

The name of the witness is a URL-like value that will appear in cosignature
lines. It does not need to be where the witness is reachable but should be
recognizable.

    -key string
            hex-encoded SHA-256 hash of the witness key
    -ssh-agent string
            path to ssh-agent socket (default "litewitness.sock")

The witness Ed25519 private key is provided by a ssh-agent instance. The socket
is specified explicitly because it's recommended that a dedicated instance is
run for litewitness. The use of the ssh-agent protocol allows the key to be
provided by a key file, a PKCS#11 module, or custom hardware agents.

Example of starting a dedicated ssh-agent and loading a key:

```
ssh-agent -a litewitness.sock
SSH_AUTH_SOCK=litewitness.sock ssh-add litewitness.pem
```

    -bastion string
            address of the bastion(s) to reverse proxy through, comma separated, the first online one is selected
    -listen string
            address to listen for HTTP requests (default "localhost:7380")

Only one of `-bastion` or `-listen` must be specified. The former will cause
litewitness to serve requests through a bastion reverse proxy (see below). The
latter will listen for HTTP requests on the specified port. (HTTPS needs to be
terminated outside of litewitness.) The bastion flag is an optionally
comma-separated list of bastions to try in order until one connects
successfully. If the connection drops after establishing, litewitness exits.

### witnessctl

witnessctl is a CLI tool to operate on the litewitness database. It can be used
while litewitness is running.

    witnessctl add-log -db <path> -origin <origin> -key <base64-encoded Ed25519 key>
    witnessctl add-sigsum-log -db <path> -key <hex-encoded key>

The `add-log` and `add-sigsum-log` commands add a new known log starting at a
size of zero.

    witnessctl list-logs -db <path>

The `list-logs` command lists known logs, in JSON lines like the following.

    {"origin":"sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562","size":5,"root_hash":"QrtXrQZCCvpIgsSmOsah7HdICzMLLyDfxToMql9WTjY=","keys":["sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562+5202289b+Af/cLU2Y5BJNP+r3iMDC+av9eWCD0fBJVDfzAux5zxAP"]}

    witnessctl list-tree-heads -db <path> [-only-failed]

The `list-tree-heads` command prints litewitness's audit log. Each unique
checkpoint with a valid signature is logged exactly once, the first time it is
seen. The whole note is recorded, as well as the time it was first observed and
any error that occurred while processing it the first time. Note that if the
same checkpoint is resubmitted successfully after an error, it is not logged
again.

Errors are recorded because they might indicate misbehavior from a log. Users
are protected from such misbehavior because litewitness does not produce a
cosignature on errors, but the audit record might be useful in an investigation.

    {"note":"sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562\n1\nKgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIom7fPZTqpxWWhyjWduBvTvGVqsokMbqTArsQilegKoFBJQjUFAmQ0+YeSPM3wfUQMFSzVnnNuWRTYrajXpNUbIQY=\n","origin":"sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562","time":"2023-10-31T12:33:57+01:00"}
    {"error":"known tree size doesn't match provided old size","note":"sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562\n3\nRcCI1Nk56ZcSmIEfIn0SleqtV7uvrlXNccFx595Iwl0=\n\n— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIom2VbtIcdFbwFAy1n7s6IkAxIY6J/GQOTuZF2ORV39d75cbAj2aQYwyJre36kezNobZs4SUUdrcawfAB8WVrx6go=\n","origin":"sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562","time":"2023-10-31T12:33:57+01:00"}

## litebastion

litebastion is a public-service reverse proxy for witnesses that can't be
exposed directly to the internet.

In short, a witness connects to a bastion over TLS with a Ed25519 client
certificate, "reverses" the direction of the connection, and serves HTTP/2
requests over that connection. The bastion then proxies requests received at
`/<hex-encoded hash of Ed25519 key>/*` to that witness.

    -backends string
            file of accepted key hashes, one per line, reloaded on SIGHUP

The only configuration file of litebastion is the backends file, which lists the
acceptable client/witness key hashes.

    -listen string
            host and port to listen at (default "localhost:8443")
    -cache string
            directory to cache ACME certificates at
    -email string
            email address to register the ACME account with
    -host string
            host to obtain ACME certificate for

Since litebastion needs to operate at a lower level than HTTPS on the witness
side, it can't be behind a reverse proxy, and needs to configure its own TLS
certificate. Use the `-cache`, `-email`, and `-host` flags to configure the ACME
client. The ALPN ACME challenge is used, so as long as the `-listen` port
receives connections to the `-host` name at port 443, everything should just
work.

### bastion as a library

It mgiht be desirable to integrate bastion functionality in an existing binary,
for example because there is only one IP address and hence only one port 443 to
listen on.

In that case, you can use the `filippo.io/litetlog/bastion` package.

See [pkg.go.dev](https://pkg.go.dev/filippo.io/litetlog/bastion) for the
documentation and in particular the [package
example](https://pkg.go.dev/filippo.io/litetlog/bastion#example-package).
