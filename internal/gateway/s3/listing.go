package s3

import (
	"container/heap"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/solkin/sebastian/internal/gateway"
)

type listingItem struct {
	key    string
	object ObjectInfo
	prefix bool
}

type listingHeap []listingItem

func (h listingHeap) Len() int           { return len(h) }
func (h listingHeap) Less(i, j int) bool { return h[i].key > h[j].key }
func (h listingHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *listingHeap) Push(v any)        { *h = append(*h, v.(listingItem)) }
func (h *listingHeap) Pop() any {
	items := *h
	item := items[len(items)-1]
	*h = items[:len(items)-1]
	return item
}

// Filesystem pages keep only maxKeys+1 candidates. Directory entries are read
// in batches, and the full walk preserves global key ordering across directory
// boundaries without a bucket-size cap or an unbounded CommonPrefixes set.
func (g *Gateway) filesystemPage(ctx context.Context, bp, prefix, delimiter, after string, maxKeys int) ([]ObjectInfo, []CommonPrefix, bool, string, error) {
	candidates := &listingHeap{}
	present := make(map[string]bool)
	err := g.walkListing(ctx, bp, prefix, delimiter, func(item listingItem) {
		if item.key <= after || present[item.key] {
			return
		}
		if candidates.Len() == maxKeys+1 {
			if item.key >= (*candidates)[0].key {
				return
			}
			old := heap.Pop(candidates).(listingItem)
			delete(present, old.key)
		}
		heap.Push(candidates, item)
		present[item.key] = true
	})
	if err != nil {
		return nil, nil, false, "", err
	}
	var objects []ObjectInfo
	var prefixes []string
	for _, item := range *candidates {
		if item.prefix {
			prefixes = append(prefixes, item.key)
		} else {
			objects = append(objects, item.object)
		}
	}
	o, p, truncated, next := paginate(objects, prefixes, after, maxKeys)
	return o, p, truncated, next, nil
}

func (g *Gateway) walkListing(ctx context.Context, bp, prefix, delimiter string, visit func(listingItem)) error {
	var walk func(string) error
	walk = func(dir string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		f, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer f.Close()
		for {
			entries, readErr := f.ReadDir(256)
			for _, entry := range entries {
				if err := ctx.Err(); err != nil {
					return err
				}
				path := filepath.Join(dir, entry.Name())
				if gateway.IsScratchFile(entry.Name()) {
					continue
				}
				info, err := entry.Info()
				if os.IsNotExist(err) {
					continue
				}
				if err != nil {
					return err
				}
				if !gateway.IsClientVisiblePath(g.rootDir, path) {
					continue
				}
				rel, err := filepath.Rel(bp, path)
				if err != nil {
					return err
				}
				key := filepath.ToSlash(rel)
				if info.IsDir() {
					subtree := key + "/"
					if prefix != "" && !strings.HasPrefix(subtree, prefix) && !strings.HasPrefix(prefix, subtree) {
						continue
					}
					if err := walk(path); err != nil && !os.IsNotExist(err) {
						return err
					}
					continue
				}
				if info.Mode()&os.ModeSymlink != 0 {
					if !gateway.PathResolvesWithin(bp, path) {
						continue
					}
					info, err = os.Stat(path)
					if os.IsNotExist(err) {
						continue
					}
					if err != nil {
						return err
					}
				}
				if !info.Mode().IsRegular() || !strings.HasPrefix(key, prefix) {
					continue
				}
				if delimiter != "" {
					if pos := strings.Index(key[len(prefix):], delimiter); pos >= 0 {
						common := key[:len(prefix)+pos+len(delimiter)]
						visit(listingItem{key: common, prefix: true})
						continue
					}
				}
				visit(listingItem{key: key, object: ObjectInfo{
					Key: key, LastModified: info.ModTime().UTC().Format(s3TimeFormat),
					ETag: etagFor(info), Size: info.Size(), StorageClass: "STANDARD",
				}})
			}
			if readErr == io.EOF {
				return nil
			}
			if readErr != nil {
				return readErr
			}
		}
	}
	return walk(bp)
}
