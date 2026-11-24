// Copyright 2026 ko Build Authors All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package publish

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/ko/pkg/build"
	"github.com/sigstore/cosign/v3/pkg/oci"
	ocimutate "github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	ctypes "github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

const inTotoStatementType = "https://in-toto.io/Statement/v1"

// Signer signs an arbitrary payload.
type Signer interface {
	Sign([]byte) ([]byte, error)
}

// SignerFunc adapts a function to the Signer interface.
type SignerFunc func([]byte) ([]byte, error)

// Sign implements Signer.
func (f SignerFunc) Sign(payload []byte) ([]byte, error) {
	return f(payload)
}

type attestationStatement struct {
	Type          string               `json:"_type"`
	Subject       []attestationSubject `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     json.RawMessage      `json:"predicate"`
}

type attestationSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []dsseSignature `json:"signatures"`
}

type dsseSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

func passwordFromEnv(bool) ([]byte, error) {
	if password, ok := os.LookupEnv("COSIGN_PASSWORD"); ok {
		return []byte(password), nil
	}
	return nil, errors.New("COSIGN_PASSWORD must be set when the signing key is encrypted")
}

func signerFromKey(keyRef string) (Signer, error) {
	/* #nosec G304 -- the signing key path is intentionally user-controlled. */
	raw, err := os.ReadFile(keyRef)
	if err != nil {
		return nil, fmt.Errorf("reading signing key: %w", err)
	}
	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey(raw, passwordFromEnv)
	if err != nil {
		return nil, fmt.Errorf("parsing signing key: %w", err)
	}
	signer, err := signature.LoadSigner(privateKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return SignerFunc(func(payload []byte) ([]byte, error) {
		return signer.SignMessage(bytes.NewReader(payload))
	}), nil
}

func (d *defalt) signEntity(ctx context.Context, repo name.Repository, se oci.SignedEntity) error {
	d.signMu.Lock()
	defer d.signMu.Unlock()

	h, err := se.Digest()
	if err != nil {
		return err
	}
	digest := repo.Digest(h.String())

	signaturePayload, err := json.Marshal(map[string]any{
		"critical": map[string]any{
			"identity": map[string]string{
				"docker-reference": repo.Name(),
			},
			"image": map[string]string{
				"docker-manifest-digest": h.String(),
			},
			"type": "cosign container image signature",
		},
		"optional": nil,
	})
	if err != nil {
		return fmt.Errorf("marshaling signature payload: %w", err)
	}
	signature, err := d.signer.Sign(signaturePayload)
	if err != nil {
		return fmt.Errorf("signing %s: %w", digest, err)
	}
	ociSignature, err := static.NewSignature(signaturePayload, base64.StdEncoding.EncodeToString(signature))
	if err != nil {
		return fmt.Errorf("creating signature: %w", err)
	}
	signed, err := ocimutate.AttachSignatureToEntity(se, ociSignature)
	if err != nil {
		return fmt.Errorf("attaching signature: %w", err)
	}
	if err := ociremote.WriteSignatures(repo, signed, d.oopt...); err != nil {
		return fmt.Errorf("writing signature for %s: %w", digest, err)
	}
	log.Printf("Signed %v", digest)

	provenance, err := provenanceFor(se, digest)
	if err != nil {
		return err
	}
	statement, err := json.Marshal(attestationStatement{
		Type: inTotoStatementType,
		Subject: []attestationSubject{{
			Name:   repo.String(),
			Digest: map[string]string{h.Algorithm: h.Hex},
		}},
		PredicateType: provenance.PredicateType,
		Predicate:     provenance.Predicate,
	})
	if err != nil {
		return fmt.Errorf("marshaling in-toto statement: %w", err)
	}
	envelope, err := signDSSE(d.signer, statement)
	if err != nil {
		return fmt.Errorf("signing provenance for %s: %w", digest, err)
	}
	attestation, err := static.NewAttestation(
		envelope,
		static.WithLayerMediaType(ctypes.DssePayloadType),
		static.WithAnnotations(map[string]string{"predicateType": provenance.PredicateType}),
	)
	if err != nil {
		return fmt.Errorf("creating attestation: %w", err)
	}
	attested, err := ocimutate.AttachAttestationToEntity(signed, attestation)
	if err != nil {
		return fmt.Errorf("attaching attestation: %w", err)
	}
	if err := ociremote.WriteAttestations(repo, attested, d.oopt...); err != nil {
		return fmt.Errorf("writing attestation for %s: %w", digest, err)
	}
	log.Printf("Attested %v", digest)
	return nil
}

func signDSSE(signer Signer, payload []byte) ([]byte, error) {
	payloadType := ctypes.IntotoPayloadType
	pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
	signature, err := signer.Sign(pae)
	if err != nil {
		return nil, err
	}
	return json.Marshal(dsseEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []dsseSignature{{
			Sig: base64.StdEncoding.EncodeToString(signature),
		}},
	})
}

func provenanceFor(se oci.SignedEntity, digest name.Digest) (*build.Provenance, error) {
	if result, ok := se.(build.ProvenanceResult); ok {
		provenance, err := result.Provenance()
		if err != nil {
			return nil, fmt.Errorf("getting provenance for %s: %w", digest, err)
		}
		if provenance != nil {
			return provenance, nil
		}
	}
	return fallbackProvenance(digest)
}

func fallbackProvenance(digest name.Digest) (*build.Provenance, error) {
	predicate, err := json.Marshal(map[string]any{
		"buildDefinition": map[string]any{
			"buildType": build.ProvenanceBuildType,
			"externalParameters": map[string]string{
				"artifact": digest.String(),
			},
		},
		"runDetails": map[string]any{
			"builder": map[string]string{
				"id": "https://github.com/ko-build/ko",
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling fallback provenance: %w", err)
	}
	return &build.Provenance{
		PredicateType: build.ProvenancePredicateType,
		Predicate:     predicate,
	}, nil
}
