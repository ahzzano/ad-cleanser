package blocklist

import "strings"

type Blacklist struct {
	blocked map[string]struct{}
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

func New(urls []string) Blacklist {
	blocked := make(map[string]struct{}, len(urls))
	for _, u := range urls {
		if n := normalize(u); n != "" {
			blocked[n] = struct{}{}
		}
	}
	return Blacklist{blocked: blocked}
}

// IsBlocked matches the name and every parent domain, case-insensitively.
// The bare last label (TLD) is never checked.
func (s Blacklist) IsBlocked(name string) bool {
	name = normalize(name)
	for strings.Contains(name, ".") {
		if _, ok := s.blocked[name]; ok {
			return true
		}
		_, name, _ = strings.Cut(name, ".")
	}
	return false
}
