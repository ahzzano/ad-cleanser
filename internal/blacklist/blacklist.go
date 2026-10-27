package blacklist

import (
	"strings"
	"sync"
)

// Blacklist is safe for concurrent use: lists are streamed in while queries are served.
type Blacklist struct {
	mu      sync.RWMutex
	blocked map[string]struct{}
	allowed map[string]struct{}
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

// Len returns the number of blocked domains.
func (b *Blacklist) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.blocked)
}

// New builds a Blacklist; allowed names and their subdomains are exempt, and the
// most specific allowed/blocked match wins. The allowed set is immutable afterwards.
func New(blocked, allowed []string) *Blacklist {
	b := &Blacklist{blocked: make(map[string]struct{}, len(blocked)), allowed: make(map[string]struct{}, len(allowed))}
	for _, d := range blocked {
		if n := normalize(d); n != "" {
			b.blocked[n] = struct{}{}
		}
	}
	for _, d := range allowed {
		if n := normalize(d); n != "" {
			b.allowed[n] = struct{}{}
		}
	}
	return b
}

// Block adds name to the blocked set; safe to call while queries are served.
func (b *Blacklist) Block(name string) {
	if n := normalize(name); n != "" {
		b.mu.Lock()
		b.blocked[n] = struct{}{}
		b.mu.Unlock()
	}
}

// IsBlocked matches the name and every parent domain, case-insensitively.
// The bare last label (TLD) is never checked.
func (b *Blacklist) IsBlocked(name string) bool {
	name = normalize(name)
	b.mu.RLock()
	defer b.mu.RUnlock()
	for strings.Contains(name, ".") {
		if _, ok := b.allowed[name]; ok {
			return false
		}
		if _, ok := b.blocked[name]; ok {
			return true
		}
		_, name, _ = strings.Cut(name, ".")
	}
	return false
}
