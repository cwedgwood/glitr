package lio

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

func itoa64(i int64) string { return strconv.FormatInt(i, 10) }

func atoi(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil
}

func wrapf(format string, args ...any) error { return fmt.Errorf(format, args...) }

// splitLast splits s at the last occurrence of sep: "fileio_0" -> "fileio","0".
func splitLast(s string, sep byte) (head, tail string, ok bool) {
	i := strings.LastIndexByte(s, sep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// lastField returns the text after the last sep, trimmed. LIO reports
// serials as "T10 VPD Unit Serial Number: <serial>".
func lastField(s string, sep byte) string {
	i := strings.LastIndexByte(s, sep)
	if i < 0 {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(s[i+1:])
}

// alias generates a 10-character hex name for a configfs symlink. The kernel
// accepts any unique name; the length is a convention, not a requirement.
func alias() string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// sortedKeys returns the map keys in deterministic order.
//
// Generic over the value type because callers hold several different maps and
// a per-type copy of eight lines is how the two versions of a helper drift
// apart. slices.Sorted(maps.Keys(m)) is the whole implementation.
func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

// parseInfoMode extracts the backing mode from a fileio object's info line,
// or "" if absent. The kernel emits exactly two values, from fbd_flags alone:
// "Buffered-WCE" when the file was opened without O_DSYNC, "O_DSYNC" when it
// was (linux v6.6 drivers/target/target_core_file.c:963-966). It does NOT
// consult attrib/emulate_write_cache, which makes this the one honest
// observable for a mode that is otherwise create-time-only and invisible.
//
// The token is taken up to whitespace, NOT up to a non-letter: "Buffered-WCE"
// contains a hyphen, and a [A-Za-z_] scan silently truncates it to "Buffered"
// -- a real mismeasurement this parser exists to make impossible.
// Only the two values the kernel actually emits are returned. Anything else
// -- including a token a LATER kernel might introduce -- comes back "", which
// every caller already treats as "cannot tell".
//
// That matters because the fallback is not symmetric. constrainWriteCache
// derives live WCE as `"0" unless the mode is Buffered-WCE`, so an
// unrecognised token would be read as WRITE-THROUGH: the library would report
// that an acknowledged write is on stable storage while the file was opened
// without O_DSYNC. Claiming durability the device does not have is the one
// direction this must never fail in, and "the kernel will not change this
// string" is exactly the assumption a library nobody is maintaining cannot
// afford to make.
//
// Found by fuzzing: parseInfoMode("Mode: 0") returned "0".
func parseInfoMode(info string) string {
	const key = "Mode: "
	_, after, ok := strings.Cut(info, key)
	if !ok {
		return ""
	}
	rest := after
	if j := strings.IndexAny(rest, " \t\n"); j >= 0 {
		rest = rest[:j]
	}
	switch rest {
	case "O_DSYNC", "Buffered-WCE":
		return rest
	}
	return ""
}

// parseInfoSize extracts the byte size from a fileio object's info line
// (which contains "Size: <n>"), or -1 if it cannot be parsed. The line
// also contains "SectorSize: <n>", so the match requires a word boundary
// (the "Size: " must not be preceded by a letter).
func parseInfoSize(info string) int64 {
	const key = "Size: "
	for i := 0; ; {
		j := strings.Index(info[i:], key)
		if j < 0 {
			return -1
		}
		pos := i + j
		if pos == 0 || !isLetterByte(info[pos-1]) {
			rest := info[pos+len(key):]
			k := 0
			for k < len(rest) && rest[k] >= '0' && rest[k] <= '9' {
				k++
			}
			if k > 0 {
				if n, err := strconv.ParseInt(rest[:k], 10, 64); err == nil {
					return n
				}
			}
		}
		i = pos + len(key)
	}
}

func isLetterByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isHex16 reports whether s is exactly 16 lowercase hex digits.
func isHex16(s string) bool {
	if len(s) != 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
