package httpui

import (
	"bufio"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/solkin/sebastian/internal/fileops"
)

// maxUploadParts bounds the parts of one upload form. It is the limit
// ParseMultipartForm applied before uploads were streamed.
const maxUploadParts = 1000

// maxUploadFieldBytes bounds the text fields of one upload form together: the
// target directory and one relative path per file.
const maxUploadFieldBytes = 1 << 20

// uploadBufferSize turns the small reads a multipart part delivers (a few KiB
// each) into large writes to the scratch file.
const uploadBufferSize = 1 << 20

// publishUpload publishes a staged file; a variable so a test can present the
// destination as another filesystem.
var publishUpload = fileops.Publish

// errUploadForm marks a form that exceeds the limits above.
var errUploadForm = errors.New("upload form exceeds its limits")

// stagedFile is an uploaded file held in a scratch file inside the volume
// until the whole form has arrived.
type stagedFile struct {
	file      *os.File // closed; kept to release the scratch reservation
	filename  string   // the part's file name, used when no relpath is given
	published bool
}

// handleUpload accepts a multipart upload of one or more files.
//
// The body is streamed: each file goes from the connection straight into a
// scratch file inside the volume — in the target directory when it already
// exists, otherwise at the root — and is published from there by an atomic
// rename, so an upload is written to disk once and never to os.TempDir.
// Nothing is published before the whole form has arrived: a file's name may
// come in a later "relpaths" field, and a form cut short must change nothing.
// Every scratch file not published is removed before the handler returns; one
// left by a crash is swept at startup.
func (g *Gateway) handleUpload(w http.ResponseWriter, r *http.Request) {
	// Bound concurrent uploads; wait for a slot unless the client goes away.
	select {
	case g.uploadSem <- struct{}{}:
		defer func() { <-g.uploadSem }()
	case <-r.Context().Done():
		return
	}

	limit := int64(defaultMaxUploadBytes)
	if g.config.MaxUploadBytes > 0 {
		limit = g.config.MaxUploadBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	mr, err := r.MultipartReader()
	if err != nil {
		jsonError(w, http.StatusBadRequest, "failed to parse upload")
		return
	}

	// As with FormValue before, a path in the query string wins over the field.
	target, targetSet := "", false
	if q := r.URL.Query(); q.Has("path") {
		target, targetSet = q.Get("path"), true
	}
	var relpaths []string
	var staged []*stagedFile
	defer func() {
		for _, s := range staged {
			if !s.published {
				os.Remove(s.file.Name())
			}
			fileops.ReleaseTemp(s.file)
		}
	}()

	stageDir := ""
	fieldBytes := 0
	var buf *bufio.Writer
	for parts := 0; ; parts++ {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err == nil && parts == maxUploadParts {
			err = errUploadForm
		}
		if err != nil {
			g.uploadBodyFailed(w, target, err)
			return
		}
		name, filename := part.FormName(), part.FileName()
		switch {
		case name == "files" && filename != "":
			if stageDir == "" {
				if stageDir, err = g.uploadStageDir(target, targetSet); err != nil {
					g.invalidPath(w, target, err)
					return
				}
			}
			f, err := fileops.CreateTemp(stageDir, ".seb-tmp-upload-*")
			if err != nil {
				g.logger.Error("upload failed", "dir", target, "error", err)
				jsonError(w, http.StatusInternalServerError, "failed to create file")
				return
			}
			// Recorded before the first byte, so the cleanup above owns it.
			staged = append(staged, &stagedFile{file: f, filename: filename})
			if buf == nil {
				buf = bufio.NewWriterSize(f, uploadBufferSize)
			} else {
				buf.Reset(f)
			}
			readErr, writeErr := copyPart(buf, part)
			if err := f.Close(); writeErr == nil && readErr == nil {
				writeErr = err
			}
			if readErr != nil {
				g.uploadBodyFailed(w, target, readErr)
				return
			}
			if writeErr != nil {
				g.logger.Error("upload failed", "dir", target, "name", filename, "error", writeErr)
				jsonError(w, http.StatusInternalServerError, "failed to write file")
				return
			}
		case filename == "" && (name == "path" || name == "relpaths"):
			value, err := readField(part, maxUploadFieldBytes-fieldBytes)
			if err != nil {
				g.uploadBodyFailed(w, target, err)
				return
			}
			fieldBytes += len(value)
			if name == "relpaths" {
				relpaths = append(relpaths, value)
			} else if !targetSet {
				target, targetSet = value, true
			}
		}
		// Any other part is skipped; NextPart discards what is left of it.
	}

	_, dirFullPath, err := g.resolvePath(target)
	if err != nil {
		g.invalidPath(w, target, err)
		return
	}
	if len(staged) == 0 {
		jsonError(w, http.StatusBadRequest, "no files provided")
		return
	}

	// Name every file before publishing any, so a form with a name refused
	// here publishes nothing. (A name only the filesystem refuses, such as one
	// too long, fails at its own publication.)
	type publication struct {
		file *stagedFile
		name string
		dest string
	}
	plan := make([]publication, 0, len(staged))
	for i, s := range staged {
		// Use relpath if provided, otherwise fall back to the base filename.
		// Go's multipart parser applies filepath.Base() to filenames, so the
		// frontend sends relative paths as separate "relpaths" fields in the
		// same order as "files".
		name := s.filename
		if i < len(relpaths) && relpaths[i] != "" {
			name = relpaths[i]
		}

		cleanName := filepath.ToSlash(filepath.Clean(name))
		cleanName = strings.TrimPrefix(cleanName, "/")
		if cleanName == "" || cleanName == "." || cleanName == ".." || strings.HasPrefix(cleanName, "../") {
			jsonError(w, http.StatusBadRequest, "invalid file name")
			return
		}

		destRel, destPath, err := g.resolvePath(path.Join(target, cleanName))
		if err != nil || destRel == "" {
			g.logger.Debug("upload refused", "name", cleanName, "dir", target, "error", err)
			jsonError(w, http.StatusBadRequest, "invalid file name")
			return
		}
		plan = append(plan, publication{file: s, name: cleanName, dest: destPath})
	}

	// Ensure target directory exists.
	if err := fileops.Mkdir(g.rootDir, dirFullPath, 0o755, true); err != nil {
		g.mutationFailed(w, "upload", target, err, "failed to create directory")
		return
	}
	for _, p := range plan {
		// Create intermediate directories for folder uploads.
		if err := fileops.Mkdir(g.rootDir, filepath.Dir(p.dest), 0o755, true); err != nil {
			g.mutationFailed(w, "upload", p.name, err, "failed to create directory")
			return
		}
		err := publishUpload(g.rootDir, p.file.file.Name(), p.dest)
		if errors.Is(err, syscall.EXDEV) {
			// A bucket may be a separate mount, and a scratch file staged
			// outside it cannot be renamed in; copy it next to the destination.
			err = g.publishAcrossFilesystems(p.file, p.dest)
		}
		if err != nil {
			g.mutationFailed(w, "upload", p.name, err, "failed to save file")
			return
		}
		p.file.published = true
		g.logger.Info("file uploaded", "name", p.name, "dir", target)
	}

	jsonOK(w)
}

// publishAcrossFilesystems copies a staged upload into a scratch file in the
// destination's directory and publishes that one.
func (g *Gateway) publishAcrossFilesystems(staged *stagedFile, dest string) error {
	src, err := os.Open(staged.file.Name())
	if err != nil {
		return err
	}
	defer src.Close()
	tmp, err := fileops.CreateTemp(filepath.Dir(dest), ".seb-tmp-upload-*")
	if err != nil {
		return err
	}
	defer fileops.ReleaseTemp(tmp)
	_, err = io.Copy(tmp, src)
	if err == nil {
		err = tmp.Sync()
	}
	if err = errors.Join(err, tmp.Close()); err == nil {
		err = fileops.Publish(g.rootDir, tmp.Name(), dest)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return err
	}
	// The copy is published; the scratch file it came from is now just a
	// leftover, which the handler's cleanup would keep as "published".
	os.Remove(staged.file.Name())
	return nil
}

// uploadStageDir picks where an upload's scratch files go: the target
// directory when it already exists, so a file is published by a rename within
// that directory, and otherwise the root — an upload that never completes must
// not leave the directories it would have created behind. Either way the
// scratch file is on the volume, and publication is a rename, never a copy.
func (g *Gateway) uploadStageDir(target string, targetSet bool) (string, error) {
	if !targetSet {
		return g.rootDir, nil
	}
	_, full, err := g.resolvePath(target)
	if err != nil {
		return "", err
	}
	if info, err := os.Stat(full); err == nil && info.IsDir() {
		return full, nil
	}
	return g.rootDir, nil
}

// uploadBodyFailed answers an upload whose form could not be read to its end.
// That is the client's doing — it went away, sent a malformed form, or more
// than the limits allow — so it is logged at Info, never as a server error.
func (g *Gateway) uploadBodyFailed(w http.ResponseWriter, target string, err error) {
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		g.logger.Info("upload rejected: body exceeds the size limit", "dir", target, "limit", tooLarge.Limit)
		jsonError(w, http.StatusRequestEntityTooLarge, "upload exceeds the size limit")
	case errors.Is(err, errUploadForm):
		g.logger.Info("upload rejected", "dir", target, "error", err)
		jsonError(w, http.StatusBadRequest, "failed to parse upload")
	default:
		g.logger.Info("upload aborted", "dir", target, "error", err)
		jsonError(w, http.StatusBadRequest, "failed to parse upload")
	}
}

// copyPart copies a file part through buf into its scratch file and tells the
// two sides apart: a read error is the client's (it went away, sent a broken
// form or too much), a write error is the server's.
func copyPart(buf *bufio.Writer, part io.Reader) (readErr, writeErr error) {
	dst := &writeFailures{w: buf}
	if _, err := io.Copy(dst, part); err != nil {
		if dst.err != nil {
			return nil, dst.err
		}
		return err, nil
	}
	return nil, buf.Flush()
}

// writeFailures remembers a failed write, so copyPart can tell it from a
// failed read.
type writeFailures struct {
	w   io.Writer
	err error
}

func (s *writeFailures) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if err != nil {
		s.err = err
	}
	return n, err
}

// readField reads a text field of at most max bytes.
func readField(part *multipart.Part, max int) (string, error) {
	b, err := io.ReadAll(io.LimitReader(part, int64(max)+1))
	if err != nil {
		return "", err
	}
	if len(b) > max {
		return "", errUploadForm
	}
	return string(b), nil
}
