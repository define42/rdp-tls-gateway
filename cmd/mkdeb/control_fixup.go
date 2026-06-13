package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// debpkg v1.0.0 writes the control file's trailing Description field (and thus
// the whole control file) without a final newline. dpkg >= 1.22, the parser
// shipped in current Debian/Ubuntu, rejects such a control file at install time
// with "end of file during value of field 'Description' (missing final
// newline)". The library predates that stricter parser and exposes no way to
// influence the trailing byte, so we patch the produced archive ourselves.
//
// fixControlTrailingNewline reads the debpkg-produced .deb (an `ar` archive of
// debian-binary, control.tar.gz and data.tar.gz), appends a newline to the
// `control` entry inside control.tar.gz when it lacks one, and rewrites the
// archive in place. It is a no-op when the control file already ends with a
// newline, so it is safe to call unconditionally.
func fixControlTrailingNewline(debPath string) error {
	raw, err := os.ReadFile(debPath) //nolint:gosec // debPath is the .deb mkdeb just wrote.
	if err != nil {
		return err
	}

	members, err := parseAr(raw)
	if err != nil {
		return err
	}

	for i := range members {
		if members[i].name() != "control.tar.gz" {
			continue
		}
		patched, changed, err := appendNewlineToControl(members[i].data)
		if err != nil {
			return fmt.Errorf("patch control.tar.gz: %w", err)
		}
		if !changed {
			return nil
		}
		members[i].setData(patched)
		return os.WriteFile(debPath, writeAr(members), 0o644) //nolint:gosec // package files are world-readable.
	}
	return fmt.Errorf("control.tar.gz not found in %s", debPath)
}

const arMagic = "!<arch>\n"

// arHeaderSize is the fixed System V/GNU ar header length; the size field lives
// at bytes [48:58] as a space-padded decimal string.
const (
	arHeaderSize = 60
	arSizeStart  = 48
	arSizeEnd    = 58
)

// arMember is a single ar entry: its verbatim 60-byte header and unpadded data.
type arMember struct {
	header [arHeaderSize]byte
	data   []byte
}

func (m *arMember) name() string {
	return strings.TrimRight(string(m.header[:16]), " ")
}

// setData replaces the member body and rewrites the size field in the header so
// the rebuilt archive stays consistent.
func (m *arMember) setData(b []byte) {
	m.data = b
	s := strconv.Itoa(len(b))
	field := []byte(s + strings.Repeat(" ", arSizeEnd-arSizeStart-len(s)))
	copy(m.header[arSizeStart:arSizeEnd], field)
}

// parseAr splits a Debian ar archive into its members. Each member's data is
// stored without the trailing pad byte that aligns odd-sized entries.
func parseAr(b []byte) ([]arMember, error) {
	if !strings.HasPrefix(string(b), arMagic) {
		return nil, fmt.Errorf("not an ar archive: bad magic")
	}
	off := len(arMagic)
	var members []arMember
	for off < len(b) {
		if off+arHeaderSize > len(b) {
			return nil, fmt.Errorf("truncated ar header at offset %d", off)
		}
		var m arMember
		copy(m.header[:], b[off:off+arHeaderSize])
		sizeField := strings.TrimRight(string(m.header[arSizeStart:arSizeEnd]), " ")
		size, err := strconv.Atoi(sizeField)
		if err != nil {
			return nil, fmt.Errorf("bad ar size field %q: %w", sizeField, err)
		}
		start := off + arHeaderSize
		if start+size > len(b) {
			return nil, fmt.Errorf("truncated ar member %q", m.name())
		}
		m.data = b[start : start+size]
		members = append(members, m)
		off = start + size
		if size%2 == 1 { // entries are padded to an even length with '\n'.
			off++
		}
	}
	return members, nil
}

// writeAr serializes members back into an ar archive, re-applying the even-byte
// padding ar requires after each odd-sized entry.
func writeAr(members []arMember) []byte {
	var buf bytes.Buffer
	buf.WriteString(arMagic)
	for _, m := range members {
		buf.Write(m.header[:])
		buf.Write(m.data)
		if len(m.data)%2 == 1 {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

// appendNewlineToControl rewrites a control.tar.gz, ensuring the `control` entry
// ends with a newline. It reports whether a change was made so the caller can
// skip an unnecessary rewrite.
func appendNewlineToControl(gz []byte) (out []byte, changed bool, err error) {
	gr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, false, err
	}
	defer gr.Close()

	var body bytes.Buffer
	gw := gzip.NewWriter(&body)
	tw := tar.NewWriter(gw)
	tr := tar.NewReader(gr)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false, err
		}
		content, err := io.ReadAll(tr) //nolint:gosec // control.tar.gz holds only small text metadata files.
		if err != nil {
			return nil, false, err
		}
		if needsTrailingNewline(hdr.Name, content) {
			content = append(content, '\n')
			hdr.Size = int64(len(content))
			changed = true
		}
		if err := writeTarEntry(tw, hdr, content); err != nil {
			return nil, false, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, false, err
	}
	if err := gw.Close(); err != nil {
		return nil, false, err
	}
	return body.Bytes(), changed, nil
}

// needsTrailingNewline reports whether a control.tar.gz entry is the `control`
// file and is missing its mandatory final newline.
func needsTrailingNewline(name string, content []byte) bool {
	return strings.TrimPrefix(name, "./") == "control" &&
		(len(content) == 0 || content[len(content)-1] != '\n')
}

func writeTarEntry(tw *tar.Writer, hdr *tar.Header, content []byte) error {
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(content)
	return err
}
