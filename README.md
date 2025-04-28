# Torchwood

The Torchwood repository is a collection of open-source tooling for tlogs.

  - [litewitness][] is a cosigning witness backed by SQLite and ssh-agent.
    
    It implements [c2sp.org/tlog-witness][].

  - [litebastion][] (and [filippo.io/torchwood/bastion][]) is a public-service
    reverse proxy.
    
    It implements [c2sp.org/https-bastion][].

  - [filippo.io/torchwood][] implements various [c2sp.org/signed-note][],
    [c2sp.org/tlog-cosignature][], [c2sp.org/tlog-checkpoint][], and
    [c2sp.org/tlog-tiles][] functions, including extensions to the
    [golang.org/x/mod/sumdb/tlog][] and [golang.org/x/mod/sumdb/note][]
    packages.

[filippo.io/torchwood/bastion]: https://pkg.go.dev/filippo.io/torchwood/bastion
[filippo.io/torchwood]: https://pkg.go.dev/filippo.io/torchwood
[litebastion]: /cmd/litebastion/README.md
[litewitness]: /cmd/litewitness/README.md
[c2sp.org/tlog-witness]: https://c2sp.org/tlog-witness
[c2sp.org/https-bastion]: https://c2sp.org/https-bastion
[c2sp.org/signed-note]: https://c2sp.org/signed-note
[c2sp.org/tlog-cosignature]: https://c2sp.org/tlog-cosignature
[c2sp.org/tlog-checkpoint]: https://c2sp.org/tlog-checkpoint
[c2sp.org/tlog-tiles]: https://c2sp.org/tlog-tiles
[golang.org/x/mod/sumdb/tlog]: https://pkg.go.dev/golang.org/x/mod/sumdb/tlog
[golang.org/x/mod/sumdb/note]: https://pkg.go.dev/golang.org/x/mod/sumdb/note
