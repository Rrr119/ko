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

package publish_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/ko/pkg/build"
	"github.com/google/ko/pkg/publish"
)

func TestPublishSignsImageAndProvenance(t *testing.T) {
	cosign, err := exec.LookPath("cosign")
	if err != nil {
		t.Skip("cosign is not installed")
	}

	keyDir := t.TempDir()
	generate := exec.Command(cosign, "generate-key-pair")
	generate.Dir = keyDir
	generate.Env = append(os.Environ(), "COSIGN_PASSWORD=e2e-password")
	if out, err := generate.CombinedOutput(); err != nil {
		t.Fatalf("cosign generate-key-pair: %v\n%s", err, out)
	}
	privateKey := filepath.Join(keyDir, "cosign.key")
	publicKey := filepath.Join(keyDir, "cosign.pub")
	t.Setenv("COSIGN_PASSWORD", "e2e-password")

	base, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	baseRef := name.MustParseReference("example.com/base:latest")
	builder, err := build.NewGo(context.Background(), repoRoot(t),
		build.WithBaseImages(func(context.Context, string) (name.Reference, build.Result, error) {
			return baseRef, base, nil
		}),
		build.WithPlatforms("linux/amd64"),
		build.WithTrimpath(true),
		build.WithLdflags([]string{"-X=main.version=provenance-e2e"}),
		build.WithDisabledSBOM(),
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := builder.Build(context.Background(), "ko://github.com/google/ko/test")
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(registry.New())
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	repo := u.Host + "/signed/test"
	publisher, err := publish.NewDefault(repo, publish.WithSigningKey(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := publisher.Publish(context.Background(), result, "ko://github.com/google/ko/test")
	if err != nil {
		t.Fatal(err)
	}

	runCosign(t, cosign,
		"verify",
		"--key", publicKey,
		"--insecure-ignore-tlog",
		"--allow-http-registry",
		"--allow-insecure-registry",
		ref.String(),
	)

	out := runCosign(t, cosign,
		"verify-attestation",
		"--key", publicKey,
		"--insecure-ignore-tlog",
		"--allow-http-registry",
		"--allow-insecure-registry",
		"--type", "slsaprovenance1",
		ref.String(),
	)

	statement := attestationStatementFromOutput(t, out)
	if statement.PredicateType != build.ProvenancePredicateType {
		t.Fatalf("predicateType = %q, want %q", statement.PredicateType, build.ProvenancePredicateType)
	}
	if statement.Predicate.BuildDefinition.BuildType != build.ProvenanceBuildType {
		t.Fatalf("buildType = %q, want %q", statement.Predicate.BuildDefinition.BuildType, build.ProvenanceBuildType)
	}
	params := statement.Predicate.BuildDefinition.ExternalParameters
	if params.ImportPath != "github.com/google/ko/test" {
		t.Errorf("importPath = %q", params.ImportPath)
	}
	if params.Platform != "linux/amd64" {
		t.Errorf("platform = %q", params.Platform)
	}
	if !slices.Contains(params.Ldflags, "-X=main.version=provenance-e2e") {
		t.Errorf("ldflags = %v", params.Ldflags)
	}
}

type signedStatement struct {
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		BuildDefinition struct {
			BuildType          string `json:"buildType"`
			ExternalParameters struct {
				ImportPath string   `json:"importPath"`
				Platform   string   `json:"platform"`
				Flags      []string `json:"flags"`
				Ldflags    []string `json:"ldflags"`
			} `json:"externalParameters"`
		} `json:"buildDefinition"`
	} `json:"predicate"`
}

func attestationStatementFromOutput(t *testing.T, output []byte) signedStatement {
	t.Helper()
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		var envelope struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &envelope); err != nil || envelope.Payload == "" {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil {
			t.Fatal(err)
		}
		var statement signedStatement
		if err := json.Unmarshal(payload, &statement); err != nil {
			t.Fatal(err)
		}
		return statement
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatalf("no attestation statement found in cosign output:\n%s", output)
	return signedStatement{}
}

func runCosign(t *testing.T, cosign string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(cosign, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cosign %v: %v\n%s", args, err, out)
	}
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(filename), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("locating repository root: %v", err)
	}
	return root
}
