package scanner

import "testing"

func FuzzParseSSOutput(f *testing.F) {
	f.Add("LISTEN 0 128")
	f.Add("garbage")
	f.Fuzz(func(t *testing.T, s string) {
		res := parseSSOutput(s, 9999)
		if res == nil {
			t.Fatal("nil result")
		}
	})
}
