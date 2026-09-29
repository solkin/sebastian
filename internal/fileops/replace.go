package fileops

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Format 1 uses root-relative paths and manifests captured before any rename.
// Legacy journals contain neither object identity nor an original root binding;
// guessing their meaning after offline edits or relocation would destroy data.
type replacement struct {
	Format      int                `json:"format"`
	Destination string             `json:"destination"`
	Source      string             `json:"source"`
	Backup      string             `json:"backup"`
	CopyStage   string             `json:"copy_stage,omitempty"`
	Old         []replacementEntry `json:"old,omitempty"`
	New         []replacementEntry `json:"new"`
	Committed   bool               `json:"committed"`
}

// ReplaceLocked moves src over dst. Both this function and CopyReplaceLocked
// require the namespace lock. Only fully built objects enter the rename journal.
func ReplaceLocked(root, src, dst string) error {
	return replaceLocked(root, src, dst, nil, func(string) {})
}

// CopyReplaceLocked builds an unpublished copy before touching the destination.
// copy must write and sync the supplied staging path, which does not yet exist.
func CopyReplaceLocked(root, dst string, copy func(string) error) error {
	return replaceLocked(root, "", dst, copy, func(string) {})
}

func replaceLocked(root, src, dst string, copy func(string) error, checkpoint func(string)) error {
	var err error
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	dst, err = replacementName(root, dst)
	if err != nil {
		return err
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	state := replacement{Format: 1, Destination: dst}
	journalDir := filepath.Join(root, ".sebastian", "transactions")
	if err = safeReplacementParents(r, filepath.Join(".sebastian", "transactions", "journal")); err != nil {
		return err
	}
	if err = r.MkdirAll(filepath.Join(".sebastian", "transactions"), 0700); err != nil {
		return err
	}
	if copy != nil {
		stage, err := os.MkdirTemp(filepath.Join(root, filepath.Dir(dst)), ".seb-tmp-replace-*")
		if err != nil {
			return err
		}
		state.CopyStage, _ = filepath.Rel(root, stage)
		src = filepath.Join(stage, "payload")
		if err = copy(src); err != nil {
			return errors.Join(err, os.RemoveAll(stage), SyncDir(filepath.Dir(stage)))
		}
		checkpoint("built")
	} else if src == "" {
		return fmt.Errorf("missing replacement source")
	}
	// Until the journal is durable, the COPY stage contains only disposable copies.
	journalWritten := false
	defer func() {
		if !journalWritten && state.CopyStage != "" {
			_ = r.RemoveAll(state.CopyStage)
		}
	}()
	if state.Source, err = replacementName(root, src); err != nil {
		return err
	}
	if err = safeReplacementParents(r, state.Source); err != nil {
		return err
	}
	if err = safeReplacementParents(r, dst); err != nil {
		return err
	}
	if state.New, err = replacementTree(r, state.Source); err != nil {
		return err
	}
	if len(state.New) == 0 {
		return fmt.Errorf("missing replacement source %s", state.Source)
	}
	if state.Old, err = replacementTree(r, dst); err != nil {
		return err
	}
	id := rand.Text()
	state.Backup = filepath.Join(filepath.Dir(dst), ".seb-bak-"+id)
	if _, err := r.Lstat(state.Backup); !os.IsNotExist(err) {
		if err == nil {
			err = os.ErrExist
		}
		return err
	}
	if err = validateReplacement(state); err != nil {
		return err
	}
	journal := filepath.Join(journalDir, "replace-"+id+".json")
	// A failed directory fsync may still leave a valid journal: retain its stage.
	journalWritten = true
	if err = writeReplacement(journal, state); err != nil {
		return err
	}
	checkpoint("prepared")
	rollback := func(cause error) error { return errors.Join(cause, recoverReplacement(r, journal, state, checkpoint)) }
	if len(state.Old) != 0 {
		if err = r.Rename(dst, state.Backup); err != nil {
			return rollback(err)
		}
		if err = SyncDir(filepath.Join(root, filepath.Dir(dst))); err != nil {
			return rollback(err)
		}
	}
	checkpoint("backed-up")
	if err = r.Rename(state.Source, dst); err != nil {
		return rollback(err)
	}
	if err = syncReplacementParents(root, state); err != nil {
		return rollback(err)
	}
	checkpoint("published")
	state.Committed = true
	if err = writeReplacement(journal, state); err != nil {
		return err
	}
	checkpoint("committed")
	if err = recoverReplacement(r, journal, state, checkpoint); err != nil {
		return err
	}
	checkpoint("cleaned")
	return nil
}

func writeReplacement(path string, state replacement) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".seb-tmp-journal-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

func syncReplacementParents(root string, state replacement) error {
	return errors.Join(SyncSurvivingParent(filepath.Join(root, state.Destination), root), SyncSurvivingParent(filepath.Join(root, state.Source), root))
}

func recoverReplacement(r *os.Root, journal string, state replacement, checkpoint func(string)) error {
	if err := validateReplacement(state); err != nil {
		return err
	}
	// Check every parent before the first change. Root also enforces containment
	// on the actual syscalls, rather than relying on a lexical prefix check.
	for _, name := range []string{state.Source, state.Destination, state.Backup} {
		if err := safeReplacementParents(r, name); err != nil {
			return err
		}
	}
	backup, err := replacementTree(r, state.Backup)
	if err != nil {
		return err
	}
	if state.Committed {
		// A previous cleanup may have stopped after deleting some entries. Missing
		// entries are safe; changed or newly added entries must never be deleted.
		if !matchesReplacement(backup, state.Old, true) {
			return replacementConflict(state.Backup)
		}
		if err = removeReplacementTree(r, state.Backup, checkpoint); err != nil {
			return err
		}
		checkpoint("cleanup-backup")
	} else {
		source, err := replacementTree(r, state.Source)
		if err != nil {
			return err
		}
		dest, err := replacementTree(r, state.Destination)
		if err != nil {
			return err
		}
		restored := len(backup) == 0 && matchesReplacement(dest, state.Old, false)
		if restored {
			// Prepared, or rollback finished before journal removal. Only COPY's
			// private staging source may already have been partially cleaned up.
			if !matchesReplacement(source, state.New, state.CopyStage != "") {
				return replacementConflict(state.Source)
			}
		} else {
			if !matchesReplacement(backup, state.Old, false) {
				return replacementConflict(state.Backup)
			}
			switch {
			case len(dest) == 0 && matchesReplacement(source, state.New, false):
				// Interrupted after backing up dst but before publishing src.
			case len(source) == 0 && matchesReplacement(dest, state.New, false):
				// Restore by rename, never by deleting a possibly unrelated destination.
				if err = r.Rename(state.Destination, state.Source); err != nil {
					return err
				}
				if err = syncReplacementParents(r.Name(), state); err != nil {
					return err
				}
				checkpoint("rollback-source")
			default:
				return replacementConflict(state.Destination)
			}
			if len(state.Old) != 0 {
				if err = r.Rename(state.Backup, state.Destination); err != nil {
					return err
				}
				if err = SyncDir(filepath.Join(r.Name(), filepath.Dir(state.Destination))); err != nil {
					return err
				}
			}
			checkpoint("rollback-destination")
		}
		if state.CopyStage != "" {
			if err = removeReplacementTree(r, state.Source, checkpoint); err != nil {
				return err
			}
			checkpoint("cleanup-copy")
		}
	}
	if state.CopyStage != "" {
		// Remove only an empty staging container; preserve unexpected contents.
		if err = r.Remove(state.CopyStage); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err = syncReplacementParents(r.Name(), state); err != nil {
		return err
	}
	rel, err := filepath.Rel(r.Name(), journal)
	if err != nil {
		return err
	}
	if err = r.Remove(rel); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(journal))
}

func replacementConflict(name string) error {
	return fmt.Errorf("replacement recovery conflict at %q: contents changed or missing; preserve the journal and backups and restore the expected paths before retrying", name)
}

// Remove children before parents, exposing actual partial-cleanup boundaries to
// process-cut tests. Callers first verify the complete remaining manifest.
func removeReplacementTree(r *os.Root, name string, checkpoint func(string)) error {
	info, err := r.Lstat(name)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		f, err := r.Open(name)
		if err != nil {
			return err
		}
		entries, err := f.ReadDir(-1)
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err = removeReplacementTree(r, filepath.Join(name, entry.Name()), checkpoint); err != nil {
				return err
			}
		}
	}
	if err = r.Remove(name); err != nil {
		return err
	}
	checkpoint("cleanup-entry")
	return nil
}

func replacementName(root, path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, filepath.Join(parent, filepath.Base(abs)))
	if err != nil || !localReplacementName(rel) {
		return "", fmt.Errorf("invalid replacement path %q", path)
	}
	return rel, nil
}

func localReplacementName(name string) bool {
	return name != "." && filepath.IsLocal(name) && filepath.Clean(name) == name
}

func safeReplacementParents(r *os.Root, name string) error {
	if !localReplacementName(name) {
		return fmt.Errorf("invalid replacement path %q", name)
	}
	parent := filepath.Dir(name)
	if parent == "." {
		return nil
	}
	cur := ""
	for _, part := range strings.Split(parent, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		info, err := r.Lstat(cur)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("replacement parent %q is not a real directory", cur)
		}
	}
	return nil
}

func validateReplacement(s replacement) error {
	if s.Format != 1 {
		return fmt.Errorf("unsupported replacement journal format %d: retain all files and backups; explicit recovery is required for legacy journals", s.Format)
	}
	for _, p := range []string{s.Destination, s.Source, s.Backup} {
		if !localReplacementName(p) {
			return fmt.Errorf("invalid replacement journal path %q", p)
		}
	}
	under := func(a, b string) bool { return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) }
	if under(s.Source, s.Destination) || under(s.Destination, s.Source) || under(s.Backup, s.Source) || under(s.Source, s.Backup) || s.Backup == s.Destination || filepath.Dir(s.Backup) != filepath.Dir(s.Destination) || !strings.HasPrefix(filepath.Base(s.Backup), ".seb-bak-") {
		return fmt.Errorf("overlapping or invalid replacement journal paths")
	}
	for _, p := range []string{s.Source, s.Destination, s.Backup} {
		if under(p, ".sebastian") {
			return fmt.Errorf("replacement journal targets private state")
		}
	}
	if s.CopyStage != "" && (!localReplacementName(s.CopyStage) || filepath.Dir(s.CopyStage) != filepath.Dir(s.Destination) || !strings.HasPrefix(filepath.Base(s.CopyStage), ".seb-tmp-replace-") || s.Source != filepath.Join(s.CopyStage, "payload") || under(s.Destination, s.CopyStage)) {
		return fmt.Errorf("invalid replacement copy staging path")
	}
	if len(s.New) == 0 {
		return fmt.Errorf("replacement journal has no source manifest")
	}
	for _, tree := range [][]replacementEntry{s.New, s.Old} {
		if err := validateReplacementTree(tree); err != nil {
			return err
		}
	}
	return nil
}

// RecoverLocked runs before accepting mutations. A second process
// termination during rollback or partial cleanup is safely retried.
func RecoverLocked(root string) error { return recoverLocked(root, func(string) {}) }
func recoverLocked(root string, checkpoint func(string)) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	dir := filepath.Join(".sebastian", "transactions")
	if err = safeReplacementParents(r, filepath.Join(dir, "journal")); err != nil {
		return err
	}
	f, err := r.Open(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	entries, err := f.ReadDir(-1)
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !isReplacementJournal(entry.Name()) {
			continue
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("invalid replacement journal file %s", entry.Name())
		}
		name := filepath.Join(dir, entry.Name())
		data, err := r.ReadFile(name)
		if err != nil {
			return err
		}
		var state replacement
		if err = json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("read replacement journal %s: %w", name, err)
		}
		if err = recoverReplacement(r, filepath.Join(root, name), state, checkpoint); err != nil {
			return fmt.Errorf("recover replacement %s: %w", name, err)
		}
	}
	return nil
}

func isReplacementJournal(name string) bool {
	return strings.HasPrefix(name, "replace-") && strings.HasSuffix(name, ".json")
}

// ReplacementPendingLocked prevents the scratch janitor from deleting a COPY
// stage that is still owned by a recovery journal (including a blocked one).
func ReplacementPendingLocked(root string) (bool, error) {
	entries, err := os.ReadDir(filepath.Join(root, ".sebastian", "transactions"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	for _, entry := range entries {
		if isReplacementJournal(entry.Name()) {
			return true, nil
		}
	}
	return false, nil
}

// Old releases did not journal backup destinations. Refuse to accept mutations
// while an unmapped backup exists: guessing or sweeping it can destroy data.
func CheckOrphanedBackups(root string, ignore func(string) bool) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != root && strings.HasPrefix(d.Name(), ".seb-bak-") {
			return fmt.Errorf("unmapped recovery backup %s; restore it to its original path before restarting", path)
		}
		rel, _ := filepath.Rel(root, path)
		if path != root && d.IsDir() && (d.Name() == ".sebastian" || (ignore != nil && ignore(filepath.ToSlash(rel)))) {
			return filepath.SkipDir
		}
		return nil
	})
}
