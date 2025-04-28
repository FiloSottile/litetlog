This is an **extremely early** prototype of a transparency log for APT
repositories, and specifically for the Debian archive.

The design is simple: offline-verifiable proofs of tlog inclusion ("spicy
signatures") are generated for each InRelease file (which is the file signed
with OpenPGP, and which contains the hashes of everything else in the
repository) and hosted at a public URL; an apt transport plugin downloads and
verifies the proof each time an InRelease file is being downloaded from the
mirror.

The proofs are generated with
[`spicy`](https://github.com/FiloSottile/torchwood/blob/main/cmd/spicy/spicy.go)
(also a prototype) by the `update-bucket.sh` script. It fetches the latest
InRelease files every minute, and if any changes are detected it generates and
uploads new proofs.

The entries of the log are the whole InRelease files. An auditor would ensure
they are all available on snapshot.debian.org, and that the repositories are
consistent (e.g. that contents of a package version did not change from one
iteration to another).

In the future, the [checkpoint](https://c2sp.org/tlog-checkpoint) in the spicy
signature would be [cosigned](https://c2sp.org/tlog-cosignature) by witnesses to
prevent split-view attacks.

This is designed to be easy to integrate upstream by any apt repository: `spicy`
would be even easier to run at repository update time (same as `gpg -s`), proofs
can be stored and distributed along with the InRelease files (as if they were
regular detached signatures), and proof verification can be integrated in APT
clients regardless of transport (it requires just simple parsing of a textual
format, a few SHA-256 hashes, and Ed25519 signature verification).

Even if the upstream keys were compromised, this system would ensure that any
malfeasance could be detected, and that individual APT users could not be
targeted with modified versions of the repository.
