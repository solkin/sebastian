package webdav

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// defaultLockTimeout is used when a LOCK request omits a Timeout header.
	defaultLockTimeout = 3600 * time.Second
	// maxLockTimeout caps how long a single lock can be held.
	maxLockTimeout = 24 * time.Hour
	// maxLocks bounds the number of simultaneously held locks, so a client cannot
	// grow the lock table without bound.
	maxLocks = 10000
)

// lock is a single exclusive write lock over a resource (and, when depth is
// "infinity", its subtree).
type lock struct {
	token   string // "opaquelocktoken:<hex>"
	path    string // locked relative path (cleaned, no leading slash; "" = root)
	depth   string // "0" or "infinity"
	expires time.Time
}

// covers reports whether this lock applies to the given relative path.
func (lk *lock) covers(path string) bool {
	if lk.path == path {
		return true
	}
	if lk.depth == "infinity" {
		if lk.path == "" {
			return true // root infinity-lock covers everything
		}
		return strings.HasPrefix(path, lk.path+"/")
	}
	return false
}

// lockManager is an in-memory store of WebDAV write locks. All access is
// serialized by mu, and expired locks are reaped lazily on each operation.
type lockManager struct {
	mu    sync.Mutex
	locks map[string]*lock // token -> lock
}

func newLockManager() *lockManager {
	return &lockManager{locks: make(map[string]*lock)}
}

func (m *lockManager) reap(now time.Time) {
	for t, lk := range m.locks {
		if now.After(lk.expires) {
			delete(m.locks, t)
		}
	}
}

// create attempts to add an exclusive lock over path. It fails (ok=false) if an
// existing lock already covers path, if a requested infinity lock would overlap a
// descendant lock, or if the lock table is full.
func (m *lockManager) create(path, depth string, timeout time.Duration) (*lock, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	m.reap(now)

	if len(m.locks) >= maxLocks {
		return nil, false
	}
	for _, lk := range m.locks {
		if lk.covers(path) {
			return nil, false
		}
		if depth == "infinity" && isDescendant(lk.path, path) {
			return nil, false
		}
	}

	lk := &lock{token: newLockToken(), path: path, depth: depth, expires: now.Add(timeout)}
	m.locks[lk.token] = lk
	return lk, true
}

// refresh extends an existing lock identified by token. ok=false if no live lock
// with that token exists.
func (m *lockManager) refresh(token string, timeout time.Duration) (*lock, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	m.reap(now)
	lk, ok := m.locks[token]
	if !ok {
		return nil, false
	}
	lk.expires = now.Add(timeout)
	return lk, true
}

// unlock removes the lock identified by token. ok=false if it does not exist.
func (m *lockManager) unlock(token string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.locks[token]; !ok {
		return false
	}
	delete(m.locks, token)
	return true
}

// canModify reports whether a mutating request on path is allowed: it is allowed
// when no live lock covers path, or when every covering lock's token is present
// in the request's If header.
func (m *lockManager) canModify(path, ifHeader string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reap(time.Now())
	tokens := parseIfTokens(ifHeader)
	for _, lk := range m.locks {
		if lk.covers(path) && !tokens[lk.token] {
			return false
		}
	}
	return true
}

// isDescendant reports whether p lies strictly within ancestor's subtree.
func isDescendant(p, ancestor string) bool {
	if ancestor == "" {
		return p != ""
	}
	return strings.HasPrefix(p, ancestor+"/")
}

// newLockToken returns a fresh opaque lock token.
func newLockToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "opaquelocktoken:" + hex.EncodeToString(b)
}

// parseIfTokens extracts every angle-bracketed token from an If header. The
// grammar can interleave resource tags and condition lists; we tolerantly pull
// out all <...> values, which yields the state tokens (and harmlessly some
// resource URIs) to test lock-token membership against.
func parseIfTokens(h string) map[string]bool {
	out := make(map[string]bool)
	for {
		i := strings.IndexByte(h, '<')
		if i < 0 {
			break
		}
		j := strings.IndexByte(h[i+1:], '>')
		if j < 0 {
			break
		}
		out[h[i+1:i+1+j]] = true
		h = h[i+1+j+1:]
	}
	return out
}

// parseTimeout parses a WebDAV Timeout header ("Second-3600", "Infinite"),
// returning the requested duration clamped to maxLockTimeout, or the default.
func parseTimeout(h string) time.Duration {
	for _, part := range strings.Split(h, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "Second-") {
			if n, err := strconv.Atoi(strings.TrimPrefix(part, "Second-")); err == nil && n > 0 {
				d := time.Duration(n) * time.Second
				if d > maxLockTimeout {
					d = maxLockTimeout
				}
				return d
			}
		}
	}
	return defaultLockTimeout
}
