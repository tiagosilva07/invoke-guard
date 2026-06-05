package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

func makeTarGz(t *testing.T, entries map[string]string, extra func(*tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	if extra != nil {
		extra(tw)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestExtractBasic(t *testing.T) {
	tgz := makeTarGz(t, map[string]string{"package/package.json": `{"name":"x"}`, "package/index.js": "ok"}, nil)
	files, err := ExtractTarGz(tgz, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if files["package/package.json"] != `{"name":"x"}` {
		t.Fatalf("missing package.json: %v", files)
	}
}

func TestExtractRejectsTraversalAndSymlink(t *testing.T) {
	trav := makeTarGz(t, map[string]string{"../evil": "x"}, nil)
	if f, _ := ExtractTarGz(trav, DefaultLimits()); len(f) != 0 {
		t.Errorf("path traversal entry must be skipped: %v", f)
	}
	sym := makeTarGz(t, nil, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	})
	if f, _ := ExtractTarGz(sym, DefaultLimits()); len(f) != 0 {
		t.Errorf("symlink entry must be skipped: %v", f)
	}
}

func TestExtractFileCountCap(t *testing.T) {
	many := map[string]string{}
	for i := 0; i < 50; i++ {
		many[fmtName(i)] = "x"
	}
	lim := DefaultLimits()
	lim.MaxFiles = 10
	if _, err := ExtractTarGz(makeTarGz(t, many, nil), lim); err == nil {
		t.Fatal("exceeding MaxFiles must error")
	}
}

func fmtName(i int) string {
	return "package/f" + string(rune('a'+i%26)) + string(rune('0'+i/26)) + ".js"
}
