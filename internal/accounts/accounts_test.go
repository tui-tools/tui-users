package accounts

import (
	"strings"
	"testing"
)

// candidates are the sudo-granting groups a backend offers, in the order
// distributions use them.
var candidates = []string{"wheel", "sudo", "admin"}

// TestSudoGroupAsksTheMachine covers the answer that cannot be hardcoded: the
// same key has to find wheel on Fedora and sudo on Debian, and find nothing at
// all on a machine that grants sudo by a rule instead.
func TestSudoGroupAsksTheMachine(t *testing.T) {
	tests := []struct {
		name   string
		groups []Group
		want   string
	}{
		{
			name:   "Fedora, Arch, RHEL",
			groups: []Group{{Name: "root"}, {Name: "wheel", GID: 10}},
			want:   "wheel",
		},
		{
			name:   "Debian and Ubuntu",
			groups: []Group{{Name: "root"}, {Name: "sudo", GID: 27}},
			want:   "sudo",
		},
		{
			name:   "a machine carrying both prefers the first candidate",
			groups: []Group{{Name: "sudo", GID: 27}, {Name: "wheel", GID: 10}},
			want:   "wheel",
		},
		{
			name:   "neither",
			groups: []Group{{Name: "root"}, {Name: "users", GID: 100}},
			want:   "",
		},
	}
	for _, test := range tests {
		model := Model{Groups: test.groups}
		group, ok := model.SudoGroup(candidates)
		if ok != (test.want != "") {
			t.Errorf("%s: found = %v", test.name, ok)
		}
		if group != test.want {
			t.Errorf("%s: SudoGroup = %q, want %q", test.name, group, test.want)
		}
	}
}

// TestSudoMembersFoldsInThePrimaryOnes is the count a revocation is judged on,
// and /etc/group is exactly the file that does not carry half of it.
func TestSudoMembersFoldsInThePrimaryOnes(t *testing.T) {
	model := Model{Groups: []Group{{
		Name: "wheel", GID: 10,
		Members: []string{"carol"},
		Primary: []string{"alice"},
	}}}
	got := strings.Join(model.SudoMembers("wheel"), " ")
	if got != "alice carol" {
		t.Errorf("SudoMembers = %q, want both members", got)
	}
	if members := model.SudoMembers("nothing-here"); members != nil {
		t.Errorf("SudoMembers of a group that does not exist = %v", members)
	}
}
