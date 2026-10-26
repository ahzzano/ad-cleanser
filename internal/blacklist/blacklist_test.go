package blacklist

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// upstream is unused by these tests: httptest URLs are IP literals, so nothing is resolved.
const upstream = "127.0.0.1:1"

func TestParseHosts(t *testing.T) {
	var got []string
	n, err := parseHosts(strings.NewReader("# Title\n   # indented\n\n0.0.0.0 ads.example.com\n127.0.0.1 a.com b.com # note.com\nbare.net\n"+
		"127.0.0.1 localhost localhost.localdomain\n0.0.0.0 0.0.0.0\n::1 ip6-localhost IP6-Loopback\n255.255.255.255 broadcasthost\n0.0.0.0\n"), func(d string) { got = append(got, d) })
	if err != nil {
		t.Fatal(err)
	}
	if want := "ads.example.com a.com b.com bare.net"; strings.Join(got, " ") != want || n != 4 {
		t.Errorf("parseHosts = %v (n=%d), want %q (n=4)", got, n, want)
	}
}

func TestFetchListsProgressive(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0.0.0.0 early.com\n"))
		w.(http.Flusher).Flush()
		<-release
		w.Write([]byte("0.0.0.0 late.com\n"))
	}))
	defer srv.Close()

	bl := New(nil, nil)
	done := bl.FetchLists([]string{srv.URL}, upstream)
	deadline := time.Now().Add(2 * time.Second)
	for !bl.IsBlocked("early.com") {
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("early.com not blocked while download still in progress")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if bl.IsBlocked("late.com") {
		t.Error("late.com blocked before it was sent")
	}
	close(release)
	<-done
	if !bl.IsBlocked("late.com") {
		t.Error("late.com not blocked after download finished")
	}
}

func TestFetchLists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("# Title\n   # indented comment\n#0.0.0.0 commented.com\n\n0.0.0.0 ads.example.com\n127.0.0.1 a.com b.com # note.com\nbare.net\n"))
	}))
	defer srv.Close()

	bl := New(nil, nil)
	<-bl.FetchLists([]string{srv.URL + "/missing", srv.URL + "/hosts"}, upstream)
	for name, want := range map[string]bool{
		"ads.example.com": true,
		"a.com":           true,
		"b.com":           true,
		"bare.net":        true,
		"commented.com":   false,
		"note.com":        false,
	} {
		if got := bl.IsBlocked(name); got != want {
			t.Errorf("IsBlocked(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestIsBlocked(t *testing.T) {
	bl := New([]string{"Example.Ad.com.", "", "com"}, nil)
	for name, want := range map[string]bool{
		"example.ad.com":     true,
		"EXAMPLE.AD.COM":     true,
		"example.ad.com.":    true,
		"sub.example.ad.com": true,
		"a.b.example.ad.com": true,
		"notexample.ad.com":  false,
		"ad.com":             false,
		"other.com":          false, // bare TLD entries never match
		"":                   false,
	} {
		if got := bl.IsBlocked(name); got != want {
			t.Errorf("IsBlocked(%q) = %v, want %v", name, got, want)
		}
	}
	if New(nil, nil).IsBlocked("example.com") {
		t.Error("empty blacklist blocked a name")
	}
}

func TestAllow(t *testing.T) {
	bl := New([]string{"example.com", "both.com"}, []string{"Ads.Example.com.", "both.com", ""})
	for name, want := range map[string]bool{
		"ads.example.com":   false,
		"x.ads.example.com": false,
		"example.com":       true,
		"other.example.com": true,
		"both.com":          false,
	} {
		if got := bl.IsBlocked(name); got != want {
			t.Errorf("IsBlocked(%q) = %v, want %v", name, got, want)
		}
	}

	specific := New([]string{"ads.example.com"}, []string{"example.com"})
	if !specific.IsBlocked("ads.example.com") {
		t.Error("allowed parent unblocked a more specific blocked name")
	}

	New(nil, []string{"example.com"}) // must not panic
}
