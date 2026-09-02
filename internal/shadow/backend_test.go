package shadow

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"
)

// TestKeysNote covers the notes the detail screen shows in place of a key
// list. The point of the empty note is that a missing authorized_keys file is
// an answer ("nobody logs in with a key here"), not a broken read, however the
// read failed: directly, or through the escalated `cat` whose message the
// runner wraps.
func TestKeysNote(t *testing.T) {
	catFailed := func(text string) error {
		return fmt.Errorf(
			"`/usr/bin/sudo -n cat -- /home/ana/.ssh/authorized_keys` failed: %s",
			text)
	}
	cases := []struct {
		name string
		err  error
		root bool
		want string
	}{
		{
			name: "no error",
			err:  nil,
			want: "",
		},
		{
			name: "missing file, read directly",
			err:  fmt.Errorf("open: %w", fs.ErrNotExist),
			want: "",
		},
		{
			name: "missing file, read through cat",
			err: catFailed(
				"cat: /home/ana/.ssh/authorized_keys: No such file or directory"),
			want: "",
		},
		{
			name: "unreadable, read directly",
			err:  fmt.Errorf("open: %w", fs.ErrPermission),
			want: "not readable without root",
		},
		{
			name: "unreadable, read through cat",
			err: catFailed(
				"cat: /home/ana/.ssh/authorized_keys: Permission denied"),
			want: "not readable without root",
		},
		{
			name: "sudo would not run without a password",
			err: errors.New(
				"sudo needs a password: run `sudo -v` in another terminal, then retry"),
			want: "not readable without root",
		},
		{
			name: "unreadable as root keeps the failure",
			err:  catFailed("cat: /home/ana/.ssh/authorized_keys: Permission denied"),
			root: true,
			want: "`/usr/bin/sudo -n cat -- /home/ana/.ssh/authorized_keys` failed: " +
				"cat: /home/ana/.ssh/authorized_keys: Permission denied",
		},
		{
			name: "anything else is passed through, first line only",
			err:  errors.New("`cat` failed: input/output error\nand a second line"),
			want: "`cat` failed: input/output error",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := keysNote(tc.err, tc.root); got != tc.want {
				t.Errorf("keysNote() = %q, want %q", got, tc.want)
			}
		})
	}
}
