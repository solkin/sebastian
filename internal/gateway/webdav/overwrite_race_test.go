package webdav

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Racing Overwrite:F requests must preserve the one winner and every losing source.
func TestCopyMoveConcurrentOverwriteKeepsOneWinner(t *testing.T) {
	for _, method := range []string{"COPY", "MOVE"} {
		for round := 0; round < 5; round++ {
			t.Run(fmt.Sprintf("%s/%d", method, round), func(t *testing.T) {
				root := t.TempDir()
				g := New(root, Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
				const writers = 4
				start := make(chan struct{})
				responses := make([]*httptest.ResponseRecorder, writers)
				var wg sync.WaitGroup
				for i := 0; i < writers; i++ {
					name := fmt.Sprintf("src%d", i)
					reviewWrite(t, root, name, name, time.Now())
					responses[i] = httptest.NewRecorder()
					wg.Add(1)
					go func(i int, name string) {
						defer wg.Done()
						<-start
						request := httptest.NewRequest(method, "http://node/"+name, nil)
						request.Header.Set("Destination", "http://node/dst")
						request.Header.Set("Overwrite", "F")
						g.server.Handler.ServeHTTP(responses[i], request)
					}(i, name)
				}
				close(start)
				wg.Wait()
				winner := -1
				for i, response := range responses {
					if response.Code == http.StatusCreated {
						if winner != -1 {
							t.Fatal("multiple requests replaced Overwrite:F destination")
						}
						winner = i
					} else if response.Code != http.StatusPreconditionFailed {
						t.Fatalf("unexpected status: %d %s", response.Code, response.Body)
					}
				}
				if winner == -1 {
					t.Fatal("no successful replacement")
				}
				body, err := os.ReadFile(filepath.Join(root, "dst"))
				if err != nil || string(body) != fmt.Sprintf("src%d", winner) {
					t.Fatalf("winner lost: %q %v", body, err)
				}
				for i := 0; i < writers; i++ {
					name := fmt.Sprintf("src%d", i)
					body, err := os.ReadFile(filepath.Join(root, name))
					if method == "MOVE" && i == winner {
						if !os.IsNotExist(err) {
							t.Fatalf("MOVE source still exists: %v", err)
						}
					} else if err != nil || string(body) != name {
						t.Fatalf("losing source changed: %q %v", body, err)
					}
				}
			})
		}
	}
}
