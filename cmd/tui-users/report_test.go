package main

import (
	"os"
	"os/user"
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/compat"
)

// TestRunReportDemo checks the half of the block this tool owns. The kit's own
// tests cover the machine facts and the scrubbing; what has to be right here is
// that --demo says demo, that the account backend the fake imitates is named,
// and that no account and no host program were read to produce any of it.
func TestRunReportDemo(t *testing.T) {
	var out strings.Builder
	opts := options{demo: true, report: true}
	if err := runReport(baseConfig(), opts, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		"backend: demo\n",
		"mode: demo (sample data, the system was not read)\n",
		"demo backend: " + backendName + "\n",
		compatBackendName + ": not probed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
	if !strings.HasPrefix(got, toolName+" ") {
		t.Errorf("report should start with the tool name:\n%s", got)
	}
}

// TestRunReportLive checks the live block: the account backend is named, it
// carries the reason it has no version rather than a bare "unknown", and the
// openssh line is there whatever the machine running the test has installed.
func TestRunReportLive(t *testing.T) {
	var out strings.Builder
	if err := runReport(baseConfig(), options{report: true}, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		"backend: " + backendName + " (version unknown: " + shadowNoVersion + ")\n",
		"mode: live\n",
		compatBackendName + ": ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
}

// TestRunReportKeepsItsPrivacyPromise is the assertion the bug form depends on.
// The block is pasted into a public issue, so the user name, the home path and
// the host name appearing in it would be a disclosure, not a cosmetic slip.
//
// A name the block legitimately contains for another reason is not a leak: a
// machine called "fedora" running Fedora, or a test run as root next to the
// `root:` line. Those names are skipped rather than asserted on, because the
// alternative is a test that fails on the machine and not on the code.
func TestRunReportKeepsItsPrivacyPromise(t *testing.T) {
	var out strings.Builder
	if err := runReport(baseConfig(), options{report: true}, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}
	got := out.String()

	if strings.Contains(got, "/home/") {
		t.Errorf("report carries a home path:\n%s", got)
	}
	if host, err := os.Hostname(); err == nil {
		assertAbsent(t, got, host, "host name")
	}
	if u, err := user.Current(); err == nil {
		assertAbsent(t, got, u.Username, "user name")
	}
}

// assertAbsent fails when name appears in a value of the block. The keys are
// fixed by the kit and carry nothing about the machine, so only values are
// looked at; the three values a name can legitimately collide with — the
// distribution, the kernel and the terminal, none of which this tool supplies
// — are skipped, because a machine called "fedora" running Fedora is not a
// leak and failing on it would be a test of the machine rather than the code.
func assertAbsent(t *testing.T, block, name, what string) {
	t.Helper()
	if name == "" {
		return
	}
	for _, line := range strings.Split(block, "\n") {
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			// The headline, which carries only the tool and the versions.
			key, value = "", line
		}
		if key == "distro" || key == "kernel" || key == "term" {
			continue
		}
		if strings.Contains(value, name) {
			t.Errorf("report carries the %s %q on %q", what, name, line)
		}
	}
}

// TestDescribeCompat covers the openssh line, which is what tells a
// fingerprint the tool failed to parse from one the installed ssh-keygen was
// never able to read.
func TestDescribeCompat(t *testing.T) {
	tests := []struct {
		name   string
		result compat.Result
		demo   bool
		want   string
	}{
		{
			name:   "a version that was read",
			result: compat.Result{Backend: "openssh", Version: "9.9"},
			want:   "9.9",
		},
		{
			name:   "a version that was not, with the reason",
			result: compat.Result{Backend: "openssh", Detail: "ssh-keygen not found"},
			want:   "version unknown: ssh-keygen not found",
		},
		{
			name:   "a version that was not, with no reason to give",
			result: compat.Result{Backend: "openssh"},
			want:   "version unknown",
		},
		{
			name:   "demo probes nothing at all",
			result: compat.Result{},
			demo:   true,
			want:   "not probed (demo reads no host program)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeCompat(tc.result, tc.demo); got != tc.want {
				t.Errorf("describeCompat = %q, want %q", got, tc.want)
			}
		})
	}
}
