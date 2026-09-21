# Controlled Linux runtime releases

This fork publishes opt-in Linux runtime bundles from tags shaped like
`controlled-v0.155.1-rc.1`. The workflow refuses to run outside
`iryzhkov/codex`, and every release is marked as a prerelease. These assets do
not replace a system, npm, Homebrew, or other default Codex installation.

The workflow creates a draft, uploads the complete asset set, and publishes it
only after validation, tests, both native builds, receipt verification, and
checksum verification succeed. It refuses to update an existing release and
rechecks the tag target immediately before publication. Consumers retain the
independently authored source commit, tree and content digests in their release
manifest and reject changed bytes. Repository-wide hosting policy is separate;
these checks establish pinned content identity, not a claim that GitHub has
locked the tag or assets.

Create a distinct annotated tag for each candidate and never reuse it:

```text
git tag -a controlled-v0.155.1-rc.1 <full-commit> -m "Controlled Codex 0.155.1 rc.1"
git push https://github.com/iryzhkov/codex.git controlled-v0.155.1-rc.1
```

The workflow produces these release assets:

- `codex-controlled-0.155.1-rc.1-x86_64-unknown-linux-musl.tar.zst`
- `codex-controlled-0.155.1-rc.1-aarch64-unknown-linux-musl.tar.zst`
- one matching `.receipt.json` for each archive
- `SHA256SUMS`

The target names are a closed set. The x86_64 bundle builds on
`ubuntu-24.04`; the aarch64 bundle builds natively on GitHub's supported
`ubuntu-24.04-arm` runner. Cross-compiling the Rust entrypoint alone would be
insufficient because the bundle also contains a native GNU Linux voice host and
its GStreamer runtime.

The main Codex entrypoint is MUSL-linked and checked for the expected ELF
machine and absence of dynamic `NEEDED` entries. The bundle is assembled with
the repository's release packaging script and also carries bwrap, the code-mode
host, ripgrep, the pinned zsh manifest, and the native voice runtime. The voice
host and GStreamer libraries are GNU Linux components, so
the complete bundle requires a glibc-based Linux userspace even though the
Codex entrypoint itself is static. Building on Arch Linux and copying that
native binary is not an accepted release path.

Each receipt records the repository, release tag, exact source commit and
tree, Cargo package version, target, runner architecture, full `rustc -vV`
output, Cargo version, archive digest, every packaged file digest, the native
voice target and resolved `ldd` dependency report, and the verified rusty_v8
archive and binding digests. `codex --version` remains `0.155.1`; it is a product
version and does not prove source identity. Consumers must verify the archive
digest and receipt commit against their independently pinned manifest, the
release tag, and `SHA256SUMS`; checksums fetched alongside an artifact alone do
not supply an independent trust anchor.

A release is gated by tag/source validation, Rust formatting, packaging-script
syntax checks, the full workspace test suite on the exact tagged commit, both
target builds, portability checks, and receipt/checksum validation. Each receipt
names the qualification workflow, run ID, and attempt and hashes every regular
file in the archive. Publishing happens in the final job only. Failure before
publication triggers draft-only cleanup. If the publish response is lost, the
workflow preserves any release already made public for operator verification.
It never deletes a published release as compensation.
