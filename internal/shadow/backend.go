// Package shadow is the shadow-utils backend of tui-users, and the only place
// in the repository that starts a process.
//
// Everything about reaching the machine — resolving the binaries, applying the
// privilege prefix, bounding each call, turning a failure into one readable
// line — belongs to the kit runner. What is left here is the translation
// between the account databases and the backend-neutral model in
// internal/accounts, and the assembly of the argv that a confirm dialog will
// show before it runs.
//
// The read path is deliberately wide and shallow: one `getent passwd`, one
// `getent group`, one `getent shadow`, one `lastlog`, one `loginctl`. A tool
// that asked `passwd -S` or `chage -l` per account would start a hundred
// processes on a mail server, so the per-account programs only run on the
// detail screen, for the one account on it.
//
// The programs driven, each through its own runner:
//
//	getent      the passwd, group and shadow databases
//	lastlog2    the last login of every account (lastlog on older machines)
//	last        where one account last logged in from
//	loginctl    who is logged in now
//	id          one account's group memberships, resolved by the system
//	chage       one account's password aging, in words
//	sudo        what one account may run, asked of sudo itself
//	semanage    the SELinux login mapping, read-only
//	ssh-keygen  the fingerprint of an authorized key
//	useradd usermod userdel gpasswd chpasswd chage   the account changes
//	groupadd groupdel                                the group changes
//	install tee                                      the authorized_keys writes
//	cat ls      escalated reads of files a plain user cannot open
package shadow

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-users/internal/accounts"
)

// ErrNotAvailable reports that the backend cannot be used on this machine.
var ErrNotAvailable = runner.ErrNotAvailable

// searchPaths are the locations a non-root PATH commonly omits. Every
// shadow-utils program lives in an sbin directory, which is exactly the
// directory a plain user's PATH does not carry.
var searchPaths = map[string][]string{
	"getent":     {"/usr/bin/getent", "/bin/getent"},
	"lastlog2":   {"/usr/bin/lastlog2", "/bin/lastlog2"},
	"lastlog":    {"/usr/bin/lastlog", "/bin/lastlog"},
	"last":       {"/usr/bin/last", "/bin/last"},
	"loginctl":   {"/usr/bin/loginctl", "/bin/loginctl"},
	"id":         {"/usr/bin/id", "/bin/id"},
	"sudo":       {"/usr/bin/sudo", "/bin/sudo"},
	"semanage":   {"/usr/sbin/semanage", "/sbin/semanage", "/usr/bin/semanage"},
	"ssh-keygen": {"/usr/bin/ssh-keygen", "/bin/ssh-keygen"},
	"useradd":    {"/usr/sbin/useradd", "/sbin/useradd", "/usr/bin/useradd"},
	"usermod":    {"/usr/sbin/usermod", "/sbin/usermod", "/usr/bin/usermod"},
	"userdel":    {"/usr/sbin/userdel", "/sbin/userdel", "/usr/bin/userdel"},
	"gpasswd":    {"/usr/bin/gpasswd", "/bin/gpasswd"},
	"groupadd":   {"/usr/sbin/groupadd", "/sbin/groupadd", "/usr/bin/groupadd"},
	"groupdel":   {"/usr/sbin/groupdel", "/sbin/groupdel", "/usr/bin/groupdel"},
	"chpasswd":   {"/usr/sbin/chpasswd", "/sbin/chpasswd", "/usr/bin/chpasswd"},
	"chage":      {"/usr/bin/chage", "/bin/chage"},
	"install":    {"/usr/bin/install", "/bin/install"},
	"tee":        {"/usr/bin/tee", "/bin/tee"},
	"cat":        {"/usr/bin/cat", "/bin/cat"},
	"ls":         {"/usr/bin/ls", "/bin/ls"},
}

// installHint is appended to the "not found" error.
const installHint = "it ships with shadow-utils on every distribution; " +
	"or use --demo to explore the UI"

// The files read directly, with no process in between. They are read rather
// than shelled out to because they are plain text a user can already open, and
// starting a process to read a file nobody needs privileges for would be
// theatre.
const (
	loginDefsPath = "/etc/login.defs"
	shellsPath    = "/etc/shells"
	sudoersPath   = "/etc/sudoers"
	sudoersDir    = "/etc/sudoers.d"
)

// Real drives shadow-utils on the host. It satisfies accounts.Backend.
type Real struct {
	// runners are keyed by argv[0], which is how a command finds the runner
	// that owns it.
	runners map[string]*runner.Runner
	// caps gates what the openssh on this machine can do. It comes from the
	// manifest, so no version number is written into this file.
	caps compat.Caps
	// root reports that the tool itself runs as root, which decides whether
	// the privileged reads are even worth attempting.
	root bool
	// limits and shells are read once at construction: they change about as
	// often as the machine is reinstalled.
	limits accounts.Limits
	shells []string
}

// Available reports whether the account database can be read at all.
func Available() bool {
	return runner.Available("getent", searchPaths["getent"]...)
}

// readSpec describes one runner: which binary, and whether its *reads* need
// escalation. Only three do — /etc/shadow, a sudoers file and another user's
// aging are all root-only — and every other read runs as the user, which is
// what makes starting this tool without sudo useful.
type readSpec struct {
	bin string
	// privilegedReads escalates this runner's reads.
	privilegedReads bool
	// required fails construction when the binary is missing. Only getent is:
	// without the passwd database there is nothing to show.
	required bool
}

// NewReal locates the binaries and, when not running as root, validates the
// configured privilege prefix. sudoPrefix comes from the configuration
// ("sudo -n"); pass nil to run the commands directly.
func NewReal(sudoPrefix []string, caps compat.Caps) (*Real, error) {
	real := &Real{
		runners: map[string]*runner.Runner{},
		caps:    caps,
		root:    os.Geteuid() == 0,
	}
	unprivileged, privileged := false, true

	for _, spec := range []readSpec{
		{bin: "getent", required: true},
		{bin: "lastlog2"},
		{bin: "lastlog"},
		{bin: "last"},
		{bin: "loginctl"},
		{bin: "id"},
		{bin: "semanage"},
		{bin: "ssh-keygen"},
		{bin: "sudo"},
		// The escalated reads.
		{bin: "cat", privilegedReads: true},
		{bin: "ls", privilegedReads: true},
		{bin: "chage", privilegedReads: true},
		// The changes. Their reads never happen; Run escalates on its own.
		{bin: "useradd"},
		{bin: "usermod"},
		{bin: "userdel"},
		{bin: "gpasswd"},
		{bin: "groupadd"},
		{bin: "groupdel"},
		{bin: "chpasswd"},
		{bin: "install"},
		{bin: "tee"},
	} {
		reads := &unprivileged
		if spec.privilegedReads {
			reads = &privileged
		}
		r, err := runner.New(runner.Options{
			Bin:             spec.bin,
			SearchPaths:     searchPaths[spec.bin],
			SudoPrefix:      sudoPrefix,
			InstallHint:     installHint,
			PrivilegedReads: reads,
			// The parsers read the labels of `chage -l` and the dates of
			// `last`, so the C locale is asked for explicitly rather than
			// hoped for.
			Env: []string{"LC_ALL=C", "LANG=C"},
		})
		if err != nil {
			if spec.required {
				return nil, err
			}
			continue
		}
		real.runners[spec.bin] = r
	}

	// A second getent, this one escalating its reads: /etc/shadow is the one
	// database that needs root, and asking for it through the same runner
	// would escalate `getent passwd` too.
	if r, err := runner.New(runner.Options{
		Bin:             "getent",
		SearchPaths:     searchPaths["getent"],
		SudoPrefix:      sudoPrefix,
		PrivilegedReads: &privileged,
		Env:             []string{"LC_ALL=C", "LANG=C"},
	}); err == nil {
		real.runners["getent-root"] = r
	}

	real.limits = accounts.DefaultLimits()
	if raw, err := os.ReadFile(loginDefsPath); err == nil {
		real.limits = ParseLoginDefs(string(raw))
		real.limits.Source = loginDefsPath
	}
	if raw, err := os.ReadFile(shellsPath); err == nil {
		real.shells = ParseShells(string(raw))
	}
	return real, nil
}

// Name identifies the backend. It is the manifest's backend name.
func (r *Real) Name() string { return "shadow-utils" }

// Describe names the backend for the header.
func (r *Real) Describe() string {
	if r.root {
		return "shadow-utils (running as root)"
	}
	return "shadow-utils via " + strings.Join(escalation(r.runners), " ")
}

// escalation names the privilege prefix the changes will use, for the header.
func escalation(runners map[string]*runner.Runner) []string {
	for _, name := range []string{"usermod", "useradd", "getent"} {
		if r := runners[name]; r != nil && r.Privileged() {
			return r.Privilege
		}
	}
	return []string{"no escalation"}
}

// Capabilities reports what this backend supports.
func (r *Real) Capabilities() accounts.Capabilities {
	caps := Capabilities(r.shells)
	// A missing program is not a crash: the key is dropped from the hint bar
	// and the action is never offered.
	caps.SupportsCreate = r.runners["useradd"] != nil
	caps.SupportsDelete = r.runners["userdel"] != nil
	caps.SupportsLock = r.runners["usermod"] != nil
	caps.SupportsShell = r.runners["usermod"] != nil
	caps.SupportsPassword = r.runners["chpasswd"] != nil
	caps.SupportsGroups = r.runners["gpasswd"] != nil
	caps.SupportsExpiry = r.runners["chage"] != nil
	caps.SupportsKeys = r.runners["install"] != nil && r.runners["tee"] != nil
	caps.SupportsGroupCreate = r.runners["groupadd"] != nil
	caps.SupportsGroupDelete = r.runners["groupdel"] != nil
	return caps
}

// Preview renders the exact command line Run will execute. Every command goes
// through the runner of its own binary, so the preview carries the privilege
// prefix that binary will really be called with.
func (r *Real) Preview(cmd accounts.Command) string {
	if run := r.runnerFor(cmd); run != nil {
		return run.Preview(cmd)
	}
	return cmd.String()
}

// runnerFor picks the runner that owns a command, by its argv[0].
func (r *Real) runnerFor(cmd accounts.Command) *runner.Runner {
	if len(cmd.Argv) == 0 {
		return nil
	}
	return r.runners[cmd.Argv[0]]
}

// Run executes a previewed command.
func (r *Real) Run(ctx context.Context, cmd accounts.Command) (string, error) {
	run := r.runnerFor(cmd)
	if run == nil {
		return "", fmt.Errorf("shadow: %q is not available on this machine",
			firstArg(cmd))
	}
	return run.Run(ctx, cmd)
}

// firstArg names the binary a command wanted, for an error message.
func firstArg(cmd accounts.Command) string {
	if len(cmd.Argv) == 0 {
		return "(empty command)"
	}
	return cmd.Argv[0]
}

// Load reads the machine's accounts.
//
// The read is layered, and every layer but the first is allowed to fail on its
// own: a machine where /etc/shadow cannot be read still lists every account,
// and says in the header that the lock state is unknown rather than implying
// every password is fine. Only a failure to read the passwd database is an
// error, because there is nothing to show without it.
func (r *Real) Load(ctx context.Context) (accounts.Model, error) {
	model := accounts.Model{
		Backend: r.Name(),
		Root:    r.root,
		Limits:  r.limits,
	}

	out, err := r.runners["getent"].Read(ctx, "getent", "passwd")
	if err != nil {
		return accounts.Model{}, err
	}
	model.Users = ParsePasswd(out)

	if out, err := r.runners["getent"].Read(ctx, "getent", "group"); err == nil {
		model.Groups = ParseGroup(out)
	}
	link(&model)

	r.loadShadow(ctx, &model)
	r.loadLastLogins(ctx, &model)
	r.loadSessions(ctx, &model)
	r.loadSudoers(ctx, &model)
	r.loadSELinux(ctx, &model)

	for i := range model.Users {
		user := &model.Users[i]
		user.System = !model.Limits.Human(user.UID)
		user.Sudo.Groups = sudoGroupsOf(*user, capabilities.SudoGroups)
		user.Flags = Flags(*user, model.Limits)
	}
	accounts.SortUsers(model.Users)
	sort.Slice(model.Groups, func(i, j int) bool {
		return model.Groups[i].GID < model.Groups[j].GID
	})
	return model, nil
}

// link fills in what one database knows about the other: the name of each
// account's primary group, the supplementary groups it belongs to, and the
// accounts whose primary group a group is.
//
// That last one is the fact people miss when they read `getent group` by hand:
// a user's primary group does not list them as a member, so a group can look
// empty while half the machine is in it.
func link(model *accounts.Model) {
	byGID := map[int]string{}
	for i := range model.Groups {
		byGID[model.Groups[i].GID] = model.Groups[i].Name
	}
	membership := map[string][]string{}
	for _, group := range model.Groups {
		for _, member := range group.Members {
			membership[member] = append(membership[member], group.Name)
		}
	}
	primary := map[string][]string{}
	for i := range model.Users {
		user := &model.Users[i]
		if name, ok := byGID[user.GID]; ok {
			user.PrimaryGroup = name
			primary[name] = append(primary[name], user.Name)
		} else {
			user.PrimaryGroup = strconv.Itoa(user.GID)
		}
		groups := append([]string{}, membership[user.Name]...)
		sort.Strings(groups)
		user.Groups = groups
	}
	for i := range model.Groups {
		group := &model.Groups[i]
		group.Primary = primary[group.Name]
		sort.Strings(group.Primary)
		group.System = group.GID < model.Limits.GIDMin ||
			group.GID > model.Limits.GIDMax
	}
}

// loadShadow folds /etc/shadow into the accounts. It is the only read that
// escalates by default, because the lock state and the expiry policy of every
// account live nowhere else.
func (r *Real) loadShadow(ctx context.Context, model *accounts.Model) {
	getent := r.runners["getent-root"]
	if getent == nil {
		model.ShadowNote = "getent is not available"
		return
	}
	out, err := getent.Read(ctx, "getent", "shadow")
	if err != nil || strings.TrimSpace(out) == "" {
		model.ShadowNote = "/etc/shadow could not be read, " +
			"so the lock state and the expiry of every account are unknown"
		if err != nil {
			model.ShadowNote = "/etc/shadow: " + runner.FirstLine(err.Error())
		}
		return
	}
	entries := ParseShadow(out)
	if len(entries) == 0 {
		model.ShadowNote = "/etc/shadow came back empty"
		return
	}
	model.ShadowRead = true
	for i := range model.Users {
		entry, ok := entries[model.Users[i].Name]
		if !ok {
			continue
		}
		model.Users[i].Password = entry.State
		model.Users[i].Aging = entry.Aging
	}
}

// loadLastLogins folds the last login of every account into the model,
// preferring lastlog2 — the util-linux replacement that Fedora ships instead
// of lastlog, whose sparse database was dropped.
func (r *Real) loadLastLogins(ctx context.Context, model *accounts.Model) {
	var out string
	switch {
	case r.runners["lastlog2"] != nil:
		out, _ = r.runners["lastlog2"].Read(ctx, "lastlog2")
	case r.runners["lastlog"] != nil:
		out, _ = r.runners["lastlog"].Read(ctx, "lastlog")
	default:
		return
	}
	logins := ParseLastlog(out)
	for i := range model.Users {
		login, ok := logins[model.Users[i].Name]
		if !ok {
			continue
		}
		model.Users[i].LastLogin = login.When
		model.Users[i].LastLoginFrom = login.From
	}
}

// loadSessions reads who is logged in now.
func (r *Real) loadSessions(ctx context.Context, model *accounts.Model) {
	loginctl := r.runners["loginctl"]
	if loginctl == nil {
		return
	}
	out, err := loginctl.Read(ctx, "loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return
	}
	model.Sessions = ParseLoginctl(out)
}

// loadSELinux reads the SELinux login mapping, when the machine has one. It is
// shown and never changed: which SELinux user an account maps to decides what
// that account can do, so it belongs on the screen — and managing it belongs
// to whoever owns SELinux on the machine, not to this tool.
func (r *Real) loadSELinux(ctx context.Context, model *accounts.Model) {
	semanage := r.runners["semanage"]
	if semanage == nil {
		return
	}
	out, err := semanage.Read(ctx, "semanage", "login", "-l")
	if err != nil {
		return
	}
	mapping := ParseSemanageLogin(out)
	if len(mapping) == 0 {
		return
	}
	model.SELinux = true
	fallback := mapping["__default__"]
	for i := range model.Users {
		if seuser, ok := mapping[model.Users[i].Name]; ok {
			model.Users[i].SELinuxLogin = seuser
			continue
		}
		model.Users[i].SELinuxLogin = fallback
	}
}

// loadSudoers reads /etc/sudoers and everything in /etc/sudoers.d.
//
// Both are root-only on most distributions, so the plain read is tried first
// and `sudo -n cat` is the fallback — the same escalated read tui-network needs
// for a netplan-rendered .network file. A machine where neither works shows the
// screen with the reason on it rather than an empty list that reads as "no
// sudo rules here".
func (r *Real) loadSudoers(ctx context.Context, model *accounts.Model) {
	if raw, err := r.readFile(ctx, sudoersPath); err == nil {
		model.Sudoers = append(model.Sudoers, ParseSudoers(sudoersPath, raw))
	} else {
		model.SudoersNote = sudoersPath + ": " + runner.FirstLine(err.Error())
	}

	for _, name := range r.listSudoersDir(ctx) {
		// sudo itself ignores these, so showing them would be showing rules
		// that are not in force.
		if strings.HasSuffix(name, "~") || strings.Contains(name, ".") {
			continue
		}
		filePath := path.Join(sudoersDir, name)
		raw, err := r.readFile(ctx, filePath)
		if err != nil {
			model.Sudoers = append(model.Sudoers, accounts.SudoersFile{
				Path: filePath, Note: runner.FirstLine(err.Error()),
			})
			continue
		}
		model.Sudoers = append(model.Sudoers, ParseSudoers(filePath, raw))
	}
	if len(model.Sudoers) == 0 && model.SudoersNote == "" {
		model.SudoersNote = "no sudoers file could be read"
	}
}

// listSudoersDir names the files in /etc/sudoers.d, escalating when the
// directory itself cannot be listed — which is the normal case on Arch and
// Fedora, where it is mode 0750.
func (r *Real) listSudoersDir(ctx context.Context) []string {
	if entries, err := os.ReadDir(sudoersDir); err == nil {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			if !entry.IsDir() {
				names = append(names, entry.Name())
			}
		}
		return names
	}
	ls := r.runners["ls"]
	if ls == nil {
		return nil
	}
	out, err := ls.Read(ctx, "ls", "-1", "--", sudoersDir)
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if name := strings.TrimSpace(line); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// readFile reads a file, escalating only when it has to.
//
// The plain read costs nothing and is what a process already running as root
// does. The fallback exists because the files worth reading here — /etc/shadow
// aside, which getent answers for — are root-only by design: a sudoers file,
// and an authorized_keys file in a home directory nobody else may enter.
func (r *Real) readFile(ctx context.Context, filePath string) (string, error) {
	raw, err := os.ReadFile(filePath) //nolint:gosec // the paths are fixed system files and home directories from the passwd database
	if err == nil {
		return string(raw), nil
	}
	if !os.IsPermission(err) && !os.IsNotExist(err) {
		return "", err
	}
	cat := r.runners["cat"]
	if cat == nil || !os.IsPermission(err) {
		return "", err
	}
	return cat.Read(ctx, "cat", "--", filePath)
}

// LoadUser re-reads one account in full. The list already carries most of it;
// the detail screen asks again because an account's keys, its sudo rules, its
// sessions and the readable form of its aging are all per-account reads, and
// running them for every account would start a process per line.
func (r *Real) LoadUser(ctx context.Context, user accounts.User) (accounts.User, error) {
	if err := checkName("user", user.Name); err != nil {
		return user, err
	}
	user.Detailed = true

	if id := r.runners["id"]; id != nil {
		// The system's own answer, which folds in every NSS source rather than
		// only the local group file.
		if out, err := id.Read(ctx, "id", "-Gn", "--", user.Name); err == nil {
			groups := strings.Fields(out)
			sort.Strings(groups)
			user.Groups = withoutPrimary(groups, user.PrimaryGroup)
		}
	}

	if chage := r.runners["chage"]; chage != nil {
		if out, err := chage.Read(ctx, "chage", "-l", user.Name); err == nil {
			if aging := ParseChage(out); aging.Known {
				user.Aging = aging
			}
		}
	}

	if last := r.runners["last"]; last != nil && user.LastLogin == "" {
		if out, err := last.Read(ctx, "last", "-n", "1", "-w", user.Name); err == nil {
			if login, ok := ParseLast(out); ok {
				user.LastLogin, user.LastLoginFrom = login.When, login.From
			}
		}
	}

	r.loadKeys(ctx, &user)
	r.loadSudoRules(ctx, &user)

	if loginctl := r.runners["loginctl"]; loginctl != nil {
		if out, err := loginctl.Read(ctx, "loginctl", "list-sessions",
			"--no-legend"); err == nil {
			for _, session := range ParseLoginctl(out) {
				if session.User == user.Name {
					user.Sessions = append(user.Sessions, session)
				}
			}
		}
	}
	return user, nil
}

// withoutPrimary drops the primary group from a supplementary list, which `id
// -Gn` includes and the model keeps separate.
func withoutPrimary(groups []string, primary string) []string {
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		if group != primary {
			out = append(out, group)
		}
	}
	return out
}

// loadKeys reads an account's authorized_keys and fingerprints every key in it.
func (r *Real) loadKeys(ctx context.Context, user *accounts.User) {
	if user.Home == "" {
		user.KeysNote = "the account has no home directory"
		return
	}
	if err := checkHome(user.Home); err != nil {
		user.KeysNote = err.Error()
		return
	}
	user.KeysPath = KeysPath(user.Home)
	raw, err := r.readFile(ctx, user.KeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Not an error: most accounts have no authorized keys at all.
			return
		}
		user.KeysNote = runner.FirstLine(err.Error())
		return
	}
	user.Keys = ParseAuthorizedKeys(raw)
	user.Keys = r.fingerprint(ctx, user.Keys)
}

// fingerprint runs `ssh-keygen -lf` over the keys, staged in a temporary file
// of our own so the account's file is never handed to another program, and so
// a file only root can read is still fingerprinted after the escalated read.
//
// One call for the whole file rather than one per key: ssh-keygen prints a line
// per key in file order, which is what ParseFingerprints zips onto the keys.
func (r *Real) fingerprint(ctx context.Context,
	keys []accounts.Key) []accounts.Key {
	keygen := r.runners["ssh-keygen"]
	if keygen == nil || len(keys) == 0 {
		return keys
	}
	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, key.Raw)
	}
	temp, cleanup, err := stageFile("keys", strings.Join(lines, "\n")+"\n")
	if err != nil {
		return keys
	}
	defer cleanup()

	out, err := keygen.Read(ctx, "ssh-keygen", "-l", "-f", temp)
	if err != nil {
		return keys
	}
	return ParseFingerprints(out, keys)
}

// loadSudoRules asks sudo itself what an account may run. The question needs
// root, so an unprivileged run says so rather than showing an empty list that
// would read as "this account has no sudo access".
func (r *Real) loadSudoRules(ctx context.Context, user *accounts.User) {
	sudo := r.runners["sudo"]
	if sudo == nil {
		user.Sudo.Note = "sudo is not installed"
		return
	}
	if !r.root {
		user.Sudo.Note = "run as root to ask sudo what this account may run; " +
			"the group membership above is what says so without it"
		return
	}
	out, err := sudo.Read(ctx, "sudo", "-n", "-l", "-U", user.Name)
	if err != nil {
		user.Sudo.Note = runner.FirstLine(err.Error())
		return
	}
	user.Sudo.Rules, user.Sudo.NoPasswd = ParseSudoList(out)
	if len(user.Sudo.Rules) == 0 {
		user.Sudo.Note = "sudo grants this account nothing"
	}
}

// sudoGroupsOf reports which sudo-granting groups an account belongs to.
func sudoGroupsOf(user accounts.User, groups []string) []string {
	var out []string
	for _, candidate := range groups {
		if user.PrimaryGroup == candidate {
			out = append(out, candidate)
			continue
		}
		for _, group := range user.Groups {
			if group == candidate {
				out = append(out, candidate)
				break
			}
		}
	}
	return out
}

// stageFile writes text to a private temporary file and returns its path and a
// cleanup. The directory is the user's own, so staging needs no privileges;
// only the install step does.
func stageFile(name, content string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "tui-users-")
	if err != nil {
		return "", func() {}, err
	}
	filePath := filepath.Join(dir, name)
	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", func() {}, err
	}
	return filePath, func() { _ = os.RemoveAll(dir) }, nil
}

// BuildCreateUser builds the account creation.
func (r *Real) BuildCreateUser(spec accounts.NewUser) ([]accounts.Command, error) {
	return BuildCreateUser(spec)
}

// BuildDeleteUser removes an account.
func (r *Real) BuildDeleteUser(name string, removeHome bool) (accounts.Command, error) {
	return BuildDeleteUser(name, removeHome)
}

// BuildLock locks or unlocks an account's password.
func (r *Real) BuildLock(name string, lock bool) (accounts.Command, error) {
	return BuildLock(name, lock)
}

// BuildSetPassword sets an account's password.
func (r *Real) BuildSetPassword(name, password string) (accounts.Command, error) {
	return BuildSetPassword(name, password)
}

// BuildGroupMembership adds a user to a group or removes them from it.
func (r *Real) BuildGroupMembership(add bool, user, group string) (accounts.Command, error) {
	return BuildGroupMembership(add, user, group)
}

// BuildSudo grants or revokes sudo through the machine's sudo group.
func (r *Real) BuildSudo(grant bool, user, group string) (accounts.Command, error) {
	return BuildSudo(grant, user, group)
}

// BuildCreateGroup creates a group.
func (r *Real) BuildCreateGroup(spec accounts.NewGroup) (accounts.Command, error) {
	return BuildCreateGroup(spec)
}

// BuildDeleteGroup deletes an empty group.
func (r *Real) BuildDeleteGroup(group accounts.Group, allowSystem bool) (accounts.Command, error) {
	return BuildDeleteGroup(group, allowSystem)
}

// BuildSetShell changes an account's login shell.
func (r *Real) BuildSetShell(user, shell string) (accounts.Command, error) {
	return BuildSetShell(user, shell)
}

// BuildSetExpiry sets the account expiry and the password lifetime.
func (r *Real) BuildSetExpiry(user, expires, maxDays string) ([]accounts.Command, error) {
	return BuildSetExpiry(user, expires, maxDays)
}

// BuildAddKey validates a pasted key and returns the plan that appends it.
//
// The validation is ssh-keygen's own: the line is written to a private
// temporary file and fingerprinted, so a key that cannot be read is refused
// before any command exists — rather than landing in a file where it would sit
// silently doing nothing.
func (r *Real) BuildAddKey(user accounts.User, key string) (accounts.KeyPlan, error) {
	key = strings.TrimSpace(key)
	if err := CheckKeyLine(key); err != nil {
		return accounts.KeyPlan{}, err
	}
	if keygen := r.runners["ssh-keygen"]; keygen != nil {
		temp, cleanup, err := stageFile("key.pub", key+"\n")
		if err != nil {
			return accounts.KeyPlan{}, err
		}
		defer cleanup()
		out, err := keygen.Read(context.Background(), "ssh-keygen", "-l", "-f", temp)
		if err != nil {
			return accounts.KeyPlan{}, fmt.Errorf(
				"shadow: ssh-keygen does not recognise that key: %s",
				runner.FirstLine(strings.TrimSpace(out)))
		}
	}

	before := ""
	if raw, err := r.readFile(context.Background(), KeysPath(user.Home)); err == nil {
		before = raw
	}
	return keyAppendPlan(user, key, before)
}

// keyAppendPlan builds the plan both backends use for an append: make sure the
// directory is there with the mode sshd insists on, create the file owned by
// the account when it does not exist yet, and only then append.
//
// The file is created with `install -m 600 /dev/null` rather than left to
// `tee`, because a file tee creates belongs to root with mode 0644 — which
// sshd accepts and the account's owner cannot then edit.
func keyAppendPlan(user accounts.User, key, before string) (accounts.KeyPlan, error) {
	dirCmd, err := BuildEnsureKeysDir(user)
	if err != nil {
		return accounts.KeyPlan{}, err
	}
	commands := []accounts.Command{dirCmd}

	if strings.TrimSpace(before) == "" && before == "" {
		createCmd, err := BuildCreateKeysFile(user)
		if err != nil {
			return accounts.KeyPlan{}, err
		}
		commands = append(commands, createCmd)
	}
	appendCmd, err := BuildAppendKey(user, key)
	if err != nil {
		return accounts.KeyPlan{}, err
	}
	commands = append(commands, appendCmd)

	filePath := KeysPath(user.Home)
	after := before
	if after != "" && !strings.HasSuffix(after, "\n") {
		after += "\n"
	}
	after += strings.TrimSpace(key) + "\n"
	return accounts.KeyPlan{
		Path:     filePath,
		Content:  after,
		Diff:     Diff(filePath, before, after),
		Commands: commands,
	}, nil
}

// BuildRemoveKey rewrites the authorized_keys file without one key.
//
// The rewrite is staged in a private temporary file and installed with the
// account's own ownership and mode, so the file that lands is the file the diff
// showed and nothing about it changes but the missing line.
func (r *Real) BuildRemoveKey(user accounts.User, key accounts.Key) (accounts.KeyPlan, error) {
	filePath := KeysPath(user.Home)
	before, err := r.readFile(context.Background(), filePath)
	if err != nil {
		return accounts.KeyPlan{}, err
	}
	after, ok := WithoutKey(before, key)
	if !ok {
		return accounts.KeyPlan{}, fmt.Errorf(
			"shadow: %s no longer holds that key on line %d — reload and try again",
			filePath, key.Line)
	}
	temp, _, err := stageFile(KeysFile, after)
	if err != nil {
		return accounts.KeyPlan{}, err
	}
	// The staging directory is deliberately not cleaned up here: the install
	// command that copies from it has not run yet, and it runs only if the
	// user confirms. It is a private directory under TMPDIR, mode 0700.
	installCmd, err := BuildInstallKeys(user, temp)
	if err != nil {
		return accounts.KeyPlan{}, err
	}
	return accounts.KeyPlan{
		Path:     filePath,
		Content:  after,
		Diff:     Diff(filePath, before, after),
		TempPath: temp,
		Commands: []accounts.Command{installCmd},
	}, nil
}
