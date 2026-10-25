package blocklist

import "testing"

func TestIsBlocked(t *testing.T) {
	bl := New([]string{"Example.Ad.com.", "", "com"})
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
	if New(nil).IsBlocked("example.com") {
		t.Error("empty blacklist blocked a name")
	}
}
