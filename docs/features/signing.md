# Signing and provenance

`ko` can sign every image it publishes with [cosign](https://docs.sigstore.dev/cosign/overview/) and attach an in-toto [SLSA provenance](https://slsa.dev/provenance/v1) attestation.
This is useful in CI, where the image and its build inputs should be verifiable by consumers.

Generate a cosign key pair and keep the private key in your CI secret store:

```sh
cosign generate-key-pair
```

Pass the private key to `ko build`. Set `COSIGN_PASSWORD` when the key is encrypted:

```sh
export COSIGN_PASSWORD="$(cat /path/to/cosign-password)"
KO_DOCKER_REPO=registry.example.com/team \
  ko build --signing-key=cosign.key --preserve-import-paths ./cmd/app
```

The key may also be supplied with the `KO_SIGNING_KEY` environment variable.
Signing is applied only when images are pushed to a registry; it is not applied to `--local`, tarball, or OCI layout output.

For each published image and image index, `ko` writes:

- a cosign simple-signing signature at `sha256-<digest>.sig`
- a signed DSSE in-toto attestation at `sha256-<digest>.att`

The attestation uses the `https://slsa.dev/provenance/v1` predicate type and records the import path, target platform, Go build flags, ldflags, working directory, Go version, reproducible-build settings, and resolved base image.
Multi-platform image indexes also record the platforms that were built.

Verify the image signature:

```sh
cosign verify --key cosign.pub --insecure-ignore-tlog \
  registry.example.com/team/cmd/app@sha256:...
```

Verify that the provenance attestation is signed and inspect it:

```sh
cosign verify-attestation --key cosign.pub --insecure-ignore-tlog \
  --type slsaprovenance1 \
  registry.example.com/team/cmd/app@sha256:...
```

`--insecure-ignore-tlog` is only needed because this key-based flow does not upload signatures to Rekor.
When your signing setup records signatures in a transparency log, omit it.
