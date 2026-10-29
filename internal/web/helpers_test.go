package web

import (
	"encoding/json"
	"net/http"
	"testing"
)

func jsonStr(s string) string { b, _ := json.Marshal(s); return string(b) }

func decode(t *testing.T, r *http.Response, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}
