package main

import (
	"context"
	"fmt"
	"io"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/report"
	"github.com/tui-tools/tui-kit/theme"
)

// shadowNoVersion is why the backend line carries no number. It is not a probe
// failure: no program in shadow-utils prints a version at all, the manifest
// declares no version command for it, and saying "unknown" without the reason
// would read as one more thing that broke.
const shadowNoVersion = "no shadow-utils program prints one"

// runReport prints the block a bug report needs and exits. Everything generic
// — the kit version, the distribution, the kernel, the terminal, where the
// binary came from — is collected by the kit, so the whole family answers
// --report in the same shape. What this function adds is the part only
// tui-users knows: that the account backend is shadow-utils and why it has no
// version, and the openssh version the compat probe read, because the key
// views are gated on it.
//
// It reads no account. --check is the flag that does that, and it escalates
// for /etc/shadow and for another account's keys; a report has to work for a
// user who cannot escalate, because the missing privilege may be the bug. For
// the same reason a machine whose backend cannot even be built still gets a
// report, with the construction error as one of its lines.
func runReport(cfg config.Config, opts options, out io.Writer) error {
	palette, _ := theme.ResolvePalette()

	// The same probe --check and the header use. There is one version probe in
	// this tool and this is it. It reads openssh, not the account backend.
	sshCompat := probeCompat(context.Background(), opts.demo)

	var backendError string
	if _, err := pickBackend(cfg, opts, sshCompat); err != nil {
		backendError = err.Error()
	}

	info := report.Info{
		Tool:          toolName,
		Version:       version,
		Backend:       backendName,
		BackendDetail: shadowNoVersion,
		Demo:          opts.demo,
		Sudo:          cfg.String(config.KeySudo, ""),
		Theme:         palette.Name,
	}
	if opts.demo {
		// The fake imitates the real account backend, and saying which one
		// is what tells a demo bug from a fake that drifted.
		info.Backend = "demo"
		info.Extra = append(info.Extra, report.Field{
			Key: "demo backend", Value: backendName,
		})
	}
	info.Extra = append(info.Extra, report.Field{
		Key: compatBackendName, Value: describeCompat(sshCompat, opts.demo),
	})
	if backendError != "" {
		info.Extra = append(info.Extra, report.Field{
			Key: "backend error", Value: backendError,
		})
	}

	_, err := io.WriteString(out, report.Render(info))
	return err
}

// describeCompat renders the openssh probe as one line. The version is what
// decides which key types `ssh-keygen -l` can read — FIDO keys landed in 8.2 —
// so a report that says only "openssh" leaves the reader guessing whether a
// missing fingerprint is a parse bug or a version that never knew the type.
// A version that could not be read carries the probe's own reason: "openssh is
// not installed" and "ssh-keygen printed something we could not parse" are
// different bugs.
//
// In demo mode nothing was probed, and saying so is the honest answer: the
// host's openssh has nothing to do with the sample machine on screen.
func describeCompat(result compat.Result, demo bool) string {
	if demo {
		return "not probed (demo reads no host program)"
	}
	if result.Version != "" {
		return result.Version
	}
	if result.Detail != "" {
		return "version unknown: " + result.Detail
	}
	return "version unknown"
}

// reportUsage is the flag's one-line help, kept here next to what it prints.
var reportUsage = fmt.Sprintf(
	"print the versions and machine facts a bug report needs, then exit "+
		"(no UI, no privileges, nothing about you: paste it into a %s issue)",
	toolName)
