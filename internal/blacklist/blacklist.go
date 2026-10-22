package blocklist

import "slices"

type Blacklist struct {
	blockedUrls []string
}

func New(urls []string) Blacklist {
	return Blacklist{
		blockedUrls: urls,
	}
}

func (s *Blacklist) IsBlocked(url string) bool {
	return slices.Contains(s.blockedUrls, url)
}
