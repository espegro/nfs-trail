package output

import "strings"

// sanitizeString removes or escapes control characters to prevent log injection
// Security: Prevents attackers from injecting fake log entries via filenames with \n
func sanitizeString(s string) string {
	// Replace common control characters with escaped versions
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")

	// Remove other control characters (ASCII 0-31 and 127)
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1 // Drop control character
		}
		return r
	}, s)
}
