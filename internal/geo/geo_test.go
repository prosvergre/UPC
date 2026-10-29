package geo

import "testing"

func TestCodeFromName(t *testing.T) {
	cases := map[string]string{
		"🇬🇧 United Kingdom - Manchester": "GB",
		"🇩🇪[openproxylist.com] vless-DE": "DE",
		"🔒 TR-WS-TLS 🏴‍☠️ NA-1.1.1.1":    "",
		"no flag": "",
		"x 🇺🇸 y":  "US",
	}
	for in, want := range cases {
		if got := CodeFromName(in); got != want {
			t.Errorf("%q: %q != %q", in, got, want)
		}
	}
}
