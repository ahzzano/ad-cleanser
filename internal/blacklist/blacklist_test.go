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

func TestAllow(t *testing.T) {
	bl := New([]string{"example.com", "both.com"})
	bl.Allow("Ads.Example.com.")
	bl.Allow("both.com")
	bl.Allow("")
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

	specific := New([]string{"ads.example.com"})
	specific.Allow("example.com")
	if !specific.IsBlocked("ads.example.com") {
		t.Error("allowed parent unblocked a more specific blocked name")
	}

	empty := New(nil)
	empty.Allow("example.com") // must not panic
}
