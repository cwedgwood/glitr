// Package lish is an interactive shell over the declarative lio library: it
// navigates the live LIO tree and edits it, plus save, restore and clear.
//
// It is a worked example rather than a product. A full administration tool
// would want far more than this -- lish exists to exercise the library below
// it against a live kernel and to show what using that library looks like.
// Read it for the pattern; run it to poke at a real target.
//
// The pattern is worth stating, because it is the whole point of a
// declarative library. Every create, delete and set discovers the live
// configuration, edits that value in memory, and calls lio.Manager.Sync to
// make the kernel match. Nothing writes configfs directly and no command
// tracks what it changed: the kernel converges to the edited state, or Sync
// reports why it could not.
//
// That has a consequence worth understanding before building anything the
// same way. Because each edit re-Syncs the whole discovered configuration,
// fidelity depends entirely on Discover capturing every property that is
// managed -- anything Discover omits is absent from the edited value, and the
// next Sync prunes it. The library discovers a curated set of attributes for
// exactly this reason.
//
// Mutating verbs take a host-wide advisory lock (see Lock) so that only one
// writer touches the kernel tree at a time. Read-only verbs do not lock.
package lish

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/cwedgwood/glitr/lio"
)

// Shell is an interactive/one-shot session over the live LIO tree. It caches
// a discovered configuration for the duration of a single command and
// invalidates it after every mutation.
type Shell struct {
	m    *lio.Manager
	out  io.Writer
	lock *Lock // host-wide mutation interlock (may be nil to disable)

	cwd    *Node
	cached *lio.Config
	done   bool
}

// NewShell returns a shell rooted at "/" driving manager m. Output is written
// to out; lock (may be nil) guards mutating verbs.
func NewShell(m *lio.Manager, out io.Writer, lock *Lock) *Shell {
	return &Shell{m: m, out: out, lock: lock, cwd: rootNode()}
}

// config returns the live configuration, discovering it at most once per
// command cycle.
func (s *Shell) config() (lio.Config, error) {
	if s.cached != nil {
		return *s.cached, nil
	}
	cfg, err := s.m.Discover()
	if err != nil {
		return lio.Config{}, err
	}
	s.cached = &cfg
	return cfg, nil
}

// invalidate drops the cached configuration (call after any mutation).
func (s *Shell) invalidate() { s.cached = nil }

func (s *Shell) printf(format string, a ...any) { fmt.Fprintf(s.out, format, a...) }

// Prompt is the interactive prompt string for the current location.
func (s *Shell) Prompt() string { return "lish " + s.pathOf(s.cwd) + "> " }

// Done reports whether the session was ended (exit/quit).
func (s *Shell) Done() bool { return s.done }

// Exec runs a single command line and returns any error (which the caller
// prints; it is not fatal to an interactive session).
func (s *Shell) Exec(line string) error {
	s.invalidate() // each command sees fresh kernel state
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	cmd, args := fields[0], fields[1:]
	// ONE lock decision, from the classifier both surfaces share. The bug this
	// replaced was two dispatchers disagreeing about `save`; leaving the
	// classification inline here would have left them free to disagree again
	// about the next verb.
	if VerbMutates(cmd) {
		return s.withLock(func() error { return s.dispatch(cmd, args) })
	}
	return s.dispatch(cmd, args)
}

// dispatch routes a verb. It takes no view on locking -- see Exec.
func (s *Shell) dispatch(cmd string, args []string) error {
	switch cmd {
	case "ls":
		return s.cmdLs(args)
	case "tree":
		return s.cmdTree(args)
	case "cd":
		return s.cmdCd(args)
	case "pwd":
		s.printf("%s\n", s.pathOf(s.cwd))
		return nil
	case "help", "?":
		return s.cmdHelp()
	case "exit", "quit":
		s.done = true
		return nil
	case "info":
		return s.cmdInfo(args)
	case "get":
		return s.cmdGet(args)
	case "saveconfig", "save":
		return s.cmdSave(args)
	case "restoreconfig", "restore":
		return s.cmdRestore(args)
	case "clearconfig", "clear":
		return s.cmdClear()
	default:
		// Contextual, node-specific mutating verbs.
		return s.cmdContextual(cmd, args)
	}
}

// VerbMutates reports whether a lish verb changes kernel state and therefore
// needs the host-wide writer lock.
//
// ONE classifier for both surfaces -- the `lish <verb>` CLI and the
// interactive shell. They used to carry separate rules and disagreed about
// `save`: the shell treated it as read-only while the CLI wrapped it in the
// lock, so `lish save` refused to run whenever applianced held the lock,
// reporting "refusing to mutate" about an operation that only reads configfs
// and writes a file elsewhere. Fixing the CLI alone left two independent lists
// still free to drift, which a review pointed out; this is the shared one.
//
// READ-ONLY IS THE ENUMERATED SET and everything else mutates. That direction
// matters: the shell's contextual verbs (create, delete, set, ...) are
// open-ended, so a read-only default would silently leave a NEW mutating verb
// unlocked and racing a live appliance. Being wrong here instead over-locks a
// read, which is visible and recoverable.
//
// `save` is read-only despite writing a file: it is Discover plus a write
// OUTSIDE configfs. The exposure that accepts -- a save concurrent with a
// reconcile can capture a tree mid-change -- is the same one every other read
// has, and a save that cannot run is strictly worse than one that might need
// repeating. A shared lock is not the alternative: applianced holds the
// exclusive lock for its whole LIFETIME, not per reconcile, so any shared
// acquisition would block until the daemon exited.
func VerbMutates(verb string) bool {
	switch verb {
	case "ls", "tree", "cd", "pwd", "help", "?", "exit", "quit",
		"info", "get", "save", "saveconfig", "discover", "validate":
		return false
	}
	return true
}

// withLock runs fn while holding the host-wide mutation lock (if configured).
func (s *Shell) withLock(fn func() error) error {
	if s.lock == nil {
		return fn()
	}
	if err := s.lock.Acquire(); err != nil {
		return err
	}
	defer s.lock.Release()
	return fn()
}

// --- navigation -----------------------------------------------------------

func (s *Shell) cmdLs(args []string) error {
	base := s.cwd
	if len(args) > 0 {
		n, err := s.resolve(args[0])
		if err != nil {
			return err
		}
		base = n
	}
	kids, err := base.children(s)
	if err != nil {
		return err
	}
	if len(kids) == 0 {
		return nil
	}
	slices.SortFunc(kids, func(a, b *Node) int { return strings.Compare(a.name, b.name) })
	for _, k := range kids {
		if sum := k.summary(s); sum != "" {
			s.printf("%s %s\n", k.name, sum)
		} else {
			s.printf("%s\n", k.name)
		}
	}
	return nil
}

func (s *Shell) cmdCd(args []string) error {
	if len(args) == 0 {
		s.cwd = rootNode()
		return nil
	}
	n, err := s.resolve(args[0])
	if err != nil {
		return err
	}
	s.cwd = n
	return nil
}

// cmdTree recursively prints the subtree rooted at the current node (or the
// given path) with summaries — the human-readable "dump the world" view. A
// single command cycle shares one discovered config (see config()).
func (s *Shell) cmdTree(args []string) error {
	base := s.cwd
	if len(args) > 0 {
		n, err := s.resolve(args[0])
		if err != nil {
			return err
		}
		base = n
	}
	label := base.name
	if base.kind == kRoot {
		label = "/"
	}
	s.printf("%s%s\n", label, summarySuffix(base.summary(s)))
	return s.treeChildren(base, "")
}

func (s *Shell) treeChildren(n *Node, indent string) error {
	kids, err := n.children(s)
	if err != nil {
		return err
	}
	slices.SortFunc(kids, func(a, b *Node) int { return strings.Compare(a.name, b.name) })
	for i, k := range kids {
		branch, cont := "├─ ", "│  "
		if i == len(kids)-1 {
			branch, cont = "└─ ", "   "
		}
		s.printf("%s%s%s%s\n", indent, branch, k.name, summarySuffix(k.summary(s)))
		if err := s.treeChildren(k, indent+cont); err != nil {
			return err
		}
	}
	return nil
}

// resolve walks a "/"-separated path (absolute or relative, with "..") to a
// node, validating each segment against live children.
func (s *Shell) resolve(path string) (*Node, error) {
	cur := s.cwd
	if strings.HasPrefix(path, "/") {
		cur = rootNode()
	}
	for seg := range strings.SplitSeq(path, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			p, err := s.parentOf(cur)
			if err != nil {
				return nil, err
			}
			cur = p
			continue
		}
		kids, err := cur.children(s)
		if err != nil {
			return nil, err
		}
		var next *Node
		for _, k := range kids {
			if k.name == seg {
				next = k
				break
			}
		}
		if next == nil {
			return nil, fmt.Errorf("no such path element: %q", seg)
		}
		cur = next
	}
	return cur, nil
}

// pathOf renders a node's absolute path by walking parents.
func (s *Shell) pathOf(n *Node) string {
	if n.kind == kRoot {
		return "/"
	}
	var segs []string
	for cur := n; cur != nil && cur.kind != kRoot; {
		segs = append([]string{cur.name}, segs...)
		p, err := s.parentOf(cur)
		if err != nil {
			break
		}
		cur = p
	}
	return "/" + strings.Join(segs, "/")
}

// parentOf reconstructs a node's parent from its context fields. This avoids
// storing back-pointers in Node (which is rebuilt fresh on every ls).
func (s *Shell) parentOf(n *Node) (*Node, error) {
	switch n.kind {
	case kRoot:
		return rootNode(), nil
	case kBackstores, kISCSI:
		return rootNode(), nil
	case kBSType:
		return &Node{kind: kBackstores, name: "backstores"}, nil
	case kBackstore:
		return &Node{kind: kBSType, name: string(n.btype), btype: n.btype}, nil
	case kTarget:
		return &Node{kind: kISCSI, name: "iscsi"}, nil
	case kTPG:
		return &Node{kind: kTarget, name: n.iqn, iqn: n.iqn}, nil
	case kLUNs, kACLs, kPortals:
		return &Node{kind: kTPG, name: "tpg" + strconv.Itoa(n.tag), iqn: n.iqn, tag: n.tag}, nil
	case kLUN:
		return &Node{kind: kLUNs, name: "luns", iqn: n.iqn, tag: n.tag}, nil
	case kACL:
		return &Node{kind: kACLs, name: "acls", iqn: n.iqn, tag: n.tag}, nil
	case kMappedLUN:
		return &Node{kind: kACL, name: n.initiator, iqn: n.iqn, tag: n.tag, initiator: n.initiator}, nil
	case kPortal:
		return &Node{kind: kPortals, name: "portals", iqn: n.iqn, tag: n.tag}, nil
	}
	return rootNode(), nil
}

// --- mutation core --------------------------------------------------------

// mutate discovers the live config, applies edit to a copy, and Syncs the
// result so the kernel converges to the edited state.
func (s *Shell) mutate(edit func(cfg *lio.Config) error) error {
	cfg, err := s.m.Discover()
	if err != nil {
		return err
	}
	if err := edit(&cfg); err != nil {
		return err
	}
	if _, err := s.m.Sync(cfg); err != nil {
		return err
	}
	s.invalidate()
	return nil
}

func (s *Shell) cmdContextual(cmd string, args []string) error {
	switch cmd {
	case "create":
		return s.cmdCreate(args)
	case "delete":
		return s.cmdDelete(args)
	case "set":
		return s.cmdSet(args)
	case "enable", "disable":
		return s.cmdEnable(cmd == "enable")
	case "map":
		return s.cmdMap(args)
	case "unmap":
		return s.cmdUnmap(args)
	}
	return fmt.Errorf("unknown command %q (try 'help')", cmd)
}
