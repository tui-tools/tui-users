package main

import (
	"context"
	"testing"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/manifest"
	tuiusers "github.com/tui-tools/tui-users"
	"github.com/tui-tools/tui-users/internal/shadow"
)

// backendNamed loads one manifest block the binary really reads.
func backendNamed(t *testing.T, name string) compat.Backend {
	t.Helper()
	m, err := manifest.Load(tuiusers.ManifestJSON)
	if err != nil {
		t.Fatalf("the embedded manifest does not parse: %v", err)
	}
	if m.Name != toolName {
		t.Fatalf("manifest name = %q, want %q", m.Name, toolName)
	}
	b, ok := m.Backend(name)
	if !ok {
		t.Fatalf("the manifest declares no %q backend", name)
	}
	return b
}

// TestManifestDeclaresTheAccountBackend pins the decision this tool had to
// make: shadow-utils prints no version from any of its programs, so its
// manifest block carries no version command at all.
func TestManifestDeclaresTheAccountBackend(t *testing.T) {
	b := backendNamed(t, backendName)
	if b.Binary != "useradd" {
		t.Errorf("binary = %q, want useradd", b.Binary)
	}
	if len(b.VersionCommand) != 0 {
		t.Errorf("versionCommand = %v; shadow-utils reports no version, "+
			"and a command that prints none would be probed forever", b.VersionCommand)
	}
	if len(b.Notes) == 0 {
		t.Error("a backend with no version needs a note saying why")
	}
}

// TestProbingABackendWithNoVersionIsHarmless: the kit answers with a Result
// that names the backend, carries no version, and treats every feature as
// present — which is what keeps a view from being hidden over a number nobody
// can read.
func TestProbingABackendWithNoVersionIsHarmless(t *testing.T) {
	result := compat.Probe(context.Background(), backendNamed(t, backendName))
	if result.Version != "" {
		t.Errorf("version = %q, want none", result.Version)
	}
	if result.Status != compat.StatusUnknown {
		t.Errorf("status = %v, want unknown", result.Status)
	}
	if result.Detail == "" {
		t.Error("the result must say why there is no version")
	}
	if !result.Caps().Has(shadow.FeatureSecurityKeys) {
		t.Error("an unprobed backend is treated as capable")
	}
}

func TestManifestDeclaresOpenSSH(t *testing.T) {
	b := backendNamed(t, compatBackendName)
	if b.Binary != "ssh-keygen" {
		t.Errorf("binary = %q, want ssh-keygen", b.Binary)
	}
	if b.Minimum != "8.2" {
		t.Errorf("minimum = %q, want 8.2", b.Minimum)
	}
	if len(b.VersionCommand) == 0 {
		t.Error("openssh does report a version, so it must be probed")
	}
}

// TestVersionRegexReadsRealOutput uses the `ssh -V` banner as it really
// prints: on stderr, with the OpenSSL version after it, which is full of
// digits that must not be mistaken for the OpenSSH one.
func TestVersionRegexReadsRealOutput(t *testing.T) {
	b := backendNamed(t, compatBackendName)
	tests := map[string]string{
		"OpenSSH_9.9p1, OpenSSL 3.2.6 30 Sep 2025":        "9.9",
		"OpenSSH_8.9p1 Ubuntu-3ubuntu0.13, OpenSSL 3.0.2": "8.9",
		"OpenSSH_10.0p2, OpenSSL 3.5.0 8 Apr 2025":        "10.0",
		"OpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017": "7.4",
	}
	for output, want := range tests {
		if got := compat.ParseVersion(output, b.VersionRegex); got != want {
			t.Errorf("ParseVersion(%q) = %q, want %q", output, got, want)
		}
	}
}

// TestSecurityKeysGateMatchesTheRelease pins what was measured: sk- key types
// arrived in OpenSSH 8.2, and below it a FIDO key cannot be fingerprinted.
func TestSecurityKeysGateMatchesTheRelease(t *testing.T) {
	b := backendNamed(t, compatBackendName)
	tests := map[string]bool{"7.4": false, "8.1": false, "8.2": true, "9.9": true}
	for version, want := range tests {
		caps := compat.NewCaps(version, b.Features)
		if got := caps.Has(shadow.FeatureSecurityKeys); got != want {
			t.Errorf("openssh %s: security-keys = %v, want %v", version, got, want)
		}
	}
}

func TestProbeInDemoModeReportsNothing(t *testing.T) {
	if got := probeCompat(context.Background(), true); got.Backend != "" {
		t.Errorf("--demo probed the host: %+v", got)
	}
}

func TestClassifiesVersionsAgainstTheMinimum(t *testing.T) {
	b := backendNamed(t, compatBackendName)
	tests := map[string]compat.Status{
		"7.4": compat.StatusBelowMinimum,
		"8.2": compat.StatusUntested,
		"9.9": compat.StatusUntested,
	}
	for version, want := range tests {
		result := compat.ProbeWith(context.Background(), b,
			func(context.Context, []string) (string, error) {
				return "OpenSSH_" + version + "p1, OpenSSL 3.2.6", nil
			})
		if result.Version != version {
			t.Errorf("probed version %q, want %q", result.Version, version)
		}
		// A version in the manifest's tested list would classify as tested;
		// the expectations above hold while that list is short, so they are
		// skipped for a version the evidence file already covers.
		if isTested(b, version) {
			continue
		}
		if result.Status != want {
			t.Errorf("openssh %s: status %v, want %v", version, result.Status, want)
		}
	}
}

// isTested reports whether the manifest already records a passing run.
func isTested(b compat.Backend, version string) bool {
	for _, tested := range b.Tested {
		if tested == version {
			return true
		}
	}
	return false
}
