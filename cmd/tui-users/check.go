package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-users/internal/accounts"
)

// checkTimeout bounds the read. Loading the model shells out to getent,
// lastlog and loginctl, and a machine whose name service is wedged must not
// hang a non-interactive check forever.
const checkTimeout = 30 * time.Second

// flagged is one account the read found something wrong with, in the shape a
// script can assert on without walking the whole model.
type flagged struct {
	User     string `json:"user"`
	UID      int    `json:"uid"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
}

// checkReport is what --check prints: the model the backend parsed, plus the
// counts and the findings a test can assert on without walking the whole
// structure.
//
// It is a report of the read path only. --check never builds and never runs a
// mutation: the whole point is that it is safe to run anywhere, including in
// CI against a production-shaped machine.
type checkReport struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Backend string `json:"backend"`
	// Describe is the backend's own one-line summary, which is where the demo
	// backend says it is a demo.
	Describe string `json:"describe"`
	// Root reports whether the tool itself ran as root, and ShadowRead
	// whether /etc/shadow could be read — which is what decides whether the
	// lock state and the expiry of every account are known at all.
	Root       bool   `json:"root"`
	ShadowRead bool   `json:"shadowRead"`
	ShadowNote string `json:"shadowNote,omitempty"`
	// Users, Humans, System and Groups are the totals across the model.
	Users  int `json:"users"`
	Humans int `json:"humans"`
	System int `json:"system"`
	Groups int `json:"groups"`
	// Sessions is how many login sessions are open right now.
	Sessions int `json:"sessions"`
	// SudoersFiles is how many sudoers files were read, and NoPasswdRules how
	// many of their rules run without a password — the one line of a sudoers
	// file that turns a compromised session into root.
	SudoersFiles  int `json:"sudoersFiles"`
	NoPasswdRules int `json:"noPasswdRules"`
	// Flagged are the accounts the read found something wrong with, worst
	// first. It is the machine-readable form of the top of the list screen.
	Flagged []flagged `json:"flagged"`
	// Compat is what the backend version probe found. It is reported rather
	// than asserted: an untested version is a fact about the machine, not a
	// failure of the read path.
	Compat compat.Result `json:"compat"`
	// Model is the parsed state in full.
	Model accounts.Model `json:"model"`
}

// runCheck exercises the backend's real read path and prints the parsed model
// as JSON. It returns an error when the backend cannot be read, which main
// turns into a non-zero exit — so a caller can treat the exit code alone as
// the verdict.
//
// An unprivileged run is not a failure: every account is still listed, their
// groups, shells and last logins are still read, and the report says the
// password state is unknown. That is the read path working, and it is what the
// smoke test asserts there.
func runCheck(backend accounts.Backend, backendCompat compat.Result,
	out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()

	model, err := backend.Load(ctx)
	if err != nil {
		return fmt.Errorf("%s backend read failed: %w", backend.Name(), err)
	}

	report := checkReport{
		Tool:          toolName,
		Version:       version,
		Backend:       backend.Name(),
		Describe:      backend.Describe(),
		Root:          model.Root,
		ShadowRead:    model.ShadowRead,
		ShadowNote:    model.ShadowNote,
		Users:         len(model.Users),
		Groups:        len(model.Groups),
		Sessions:      len(model.Sessions),
		SudoersFiles:  len(model.Sudoers),
		NoPasswdRules: model.NoPasswdCount(),
		Compat:        backendCompat,
		// An empty list rather than a null, so a script can iterate it
		// without a special case for the machine where nothing was found.
		Flagged: []flagged{},
		Model:   model,
	}
	for _, user := range model.Users {
		if user.System {
			report.System++
			continue
		}
		report.Humans++
	}
	for _, user := range model.Flagged() {
		for _, flag := range user.Flags {
			report.Flagged = append(report.Flagged, flagged{
				User:     user.Name,
				UID:      user.UID,
				Severity: flag.Severity,
				Reason:   flag.Reason,
			})
		}
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
