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

package build

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v3/pkg/oci"
)

const (
	// ProvenancePredicateType is the in-toto predicate type used for build
	// provenance.
	ProvenancePredicateType = "https://slsa.dev/provenance/v1"

	// ProvenanceBuildType identifies ko's build provenance format.
	ProvenanceBuildType = "https://ko.build/build/v1"

	provenanceBuilderID = "https://github.com/ko-build/ko"
)

// Provenance is an in-toto predicate, together with the predicate type that
// describes it.
type Provenance struct {
	PredicateType string
	Predicate     []byte
}

// ProvenanceResult is a build result that carries the provenance of the
// operation that produced it.
type ProvenanceResult interface {
	Result
	Provenance() (*Provenance, error)
}

type signedImage = oci.SignedImage

type imageWithProvenance struct {
	signedImage
	provenance *Provenance
}

var _ oci.SignedImage = (*imageWithProvenance)(nil)
var _ ProvenanceResult = (*imageWithProvenance)(nil)

func (i *imageWithProvenance) Provenance() (*Provenance, error) {
	return i.provenance, nil
}

type signedImageIndex = oci.SignedImageIndex

type indexWithProvenance struct {
	signedImageIndex
	provenance *Provenance
	children   map[v1.Hash]*Provenance
}

var _ oci.SignedImageIndex = (*indexWithProvenance)(nil)
var _ ProvenanceResult = (*indexWithProvenance)(nil)

func (i *indexWithProvenance) Provenance() (*Provenance, error) {
	return i.provenance, nil
}

func (i *indexWithProvenance) SignedImage(h v1.Hash) (oci.SignedImage, error) {
	img, err := i.signedImageIndex.SignedImage(h)
	if err != nil {
		return nil, err
	}
	return &imageWithProvenance{
		signedImage: img,
		provenance:  i.children[h],
	}, nil
}

func (i *indexWithProvenance) SignedImageIndex(h v1.Hash) (oci.SignedImageIndex, error) {
	idx, err := i.signedImageIndex.SignedImageIndex(h)
	if err != nil {
		return nil, err
	}
	return &indexWithProvenance{
		signedImageIndex: idx,
		provenance:       i.children[h],
		children:         i.children,
	}, nil
}

type provenancePredicate struct {
	BuildDefinition provenanceBuildDefinition `json:"buildDefinition"`
	RunDetails      provenanceRunDetails      `json:"runDetails"`
}

type provenanceBuildDefinition struct {
	BuildType            string                       `json:"buildType"`
	ExternalParameters   provenanceExternalParameters `json:"externalParameters"`
	InternalParameters   provenanceInternalParameters `json:"internalParameters,omitempty"`
	ResolvedDependencies []provenanceResource         `json:"resolvedDependencies,omitempty"`
}

type provenanceExternalParameters struct {
	ImportPath           string                         `json:"importPath"`
	Platform             string                         `json:"platform"`
	Platforms            []string                       `json:"platforms,omitempty"`
	Builds               []provenanceExternalParameters `json:"builds,omitempty"`
	Flags                []string                       `json:"flags,omitempty"`
	Ldflags              []string                       `json:"ldflags,omitempty"`
	WorkingDirectory     string                         `json:"workingDirectory,omitempty"`
	GoVersion            string                         `json:"goVersion,omitempty"`
	Trimpath             bool                           `json:"trimpath"`
	DisableOptimizations bool                           `json:"disableOptimizations"`
	Debug                bool                           `json:"debug"`
}

type provenanceInternalParameters struct {
	CreationTime       string            `json:"creationTime,omitempty"`
	KoDataCreationTime string            `json:"koDataCreationTime,omitempty"`
	BaseImage          string            `json:"baseImage,omitempty"`
	BaseImageDigest    string            `json:"baseImageDigest,omitempty"`
	GoEnv              map[string]string `json:"goEnv,omitempty"`
}

type provenanceResource struct {
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

type provenanceRunDetails struct {
	Builder provenanceBuilder `json:"builder"`
}

type provenanceBuilder struct {
	ID string `json:"id"`
}

func (g *gobuild) imageProvenance(bc buildContext, baseRef name.Reference, baseDigest *v1.Hash) (*Provenance, error) {
	internal := provenanceInternalParameters{
		GoEnv: goBuildEnv(bc.env),
	}
	if baseRef != nil {
		internal.BaseImage = baseRef.String()
	}
	if !bc.creationTime.IsZero() {
		internal.CreationTime = bc.creationTime.Time.UTC().Format(time.RFC3339)
	}
	if !g.kodataCreationTime.IsZero() {
		internal.KoDataCreationTime = g.kodataCreationTime.Time.UTC().Format(time.RFC3339)
	}
	resolved := make([]provenanceResource, 0, 1)
	if baseDigest != nil {
		internal.BaseImageDigest = baseDigest.String()
		resource := provenanceResource{
			Digest: map[string]string{baseDigest.Algorithm: baseDigest.Hex},
		}
		if baseRef != nil {
			resource.URI = baseRef.String()
		}
		resolved = append(resolved, resource)
	}

	predicate, err := json.Marshal(provenancePredicate{
		BuildDefinition: provenanceBuildDefinition{
			BuildType: ProvenanceBuildType,
			ExternalParameters: provenanceExternalParameters{
				ImportPath:           bc.ip,
				Platform:             bc.platform.String(),
				Flags:                bc.flags,
				Ldflags:              bc.ldflags,
				WorkingDirectory:     bc.dir,
				GoVersion:            runtime.Version(),
				Trimpath:             g.trimpath,
				DisableOptimizations: g.disableOptimizations,
				Debug:                g.debug,
			},
			InternalParameters:   internal,
			ResolvedDependencies: resolved,
		},
		RunDetails: provenanceRunDetails{
			Builder: provenanceBuilder{ID: provenanceBuilderID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling provenance: %w", err)
	}
	return &Provenance{
		PredicateType: ProvenancePredicateType,
		Predicate:     predicate,
	}, nil
}

func indexProvenance(importPath string, platforms []string, children []*Provenance) (*Provenance, error) {
	external := provenanceExternalParameters{
		ImportPath: importPath,
		Platform:   "multi-platform",
		Platforms:  platforms,
	}
	for _, child := range children {
		if child == nil {
			continue
		}
		var childPredicate provenancePredicate
		if err := json.Unmarshal(child.Predicate, &childPredicate); err != nil {
			return nil, fmt.Errorf("unmarshaling child provenance: %w", err)
		}
		params := childPredicate.BuildDefinition.ExternalParameters
		if len(external.Builds) == 0 {
			external.Flags = params.Flags
			external.Ldflags = params.Ldflags
			external.WorkingDirectory = params.WorkingDirectory
			external.GoVersion = params.GoVersion
			external.Trimpath = params.Trimpath
			external.DisableOptimizations = params.DisableOptimizations
			external.Debug = params.Debug
		}
		external.Builds = append(external.Builds, params)
	}

	predicate, err := json.Marshal(provenancePredicate{
		BuildDefinition: provenanceBuildDefinition{
			BuildType:          ProvenanceBuildType,
			ExternalParameters: external,
		},
		RunDetails: provenanceRunDetails{
			Builder: provenanceBuilder{ID: provenanceBuilderID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling index provenance: %w", err)
	}
	return &Provenance{
		PredicateType: ProvenancePredicateType,
		Predicate:     predicate,
	}, nil
}

func goBuildEnv(env []string) map[string]string {
	keys := map[string]struct{}{
		"CGO_ENABLED":  {},
		"GO111MODULE":  {},
		"GO386":        {},
		"GOAMD64":      {},
		"GOARCH":       {},
		"GOARM":        {},
		"GOEXPERIMENT": {},
		"GOFLAGS":      {},
		"GOMIPS":       {},
		"GOMIPS64":     {},
		"GOPPC64":      {},
		"GORISCV64":    {},
		"GOSUMDB":      {},
		"GOTOOLCHAIN":  {},
		"GOWASM":       {},
	}
	result := map[string]string{}
	for _, kv := range env {
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, ok := keys[key]; ok {
			result[key] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
