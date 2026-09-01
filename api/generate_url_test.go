package api

import (
	"net/url"
	"testing"
)

// generateURL is exercised indirectly by every request test, but nothing covered
// a base URL carrying a path prefix — the case path.Join is there for, and the
// shape of a Passbolt hosted in a subdirectory (https://host/passbolt). These
// tests cover it directly, and pin that the caller's base URL is never modified.

func TestGenerateURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		base string
		path string
		opt  any
		want string
	}{
		{
			name: "host root",
			base: "https://passbolt.test",
			path: "/resources.json",
			want: "https://passbolt.test/resources.json",
		},
		{
			name: "path prefix is preserved, not replaced",
			base: "https://passbolt.test/passbolt",
			path: "/resources.json",
			want: "https://passbolt.test/passbolt/resources.json",
		},
		{
			name: "trailing slash on base does not double up",
			base: "https://passbolt.test/passbolt/",
			path: "/resources.json",
			want: "https://passbolt.test/passbolt/resources.json",
		},
		{
			name: "relative path joins the same way",
			base: "https://passbolt.test/passbolt",
			path: "resources.json",
			want: "https://passbolt.test/passbolt/resources.json",
		},
		{
			name: "port is kept",
			base: "http://localhost:8080",
			path: "/auth/verify.json",
			want: "http://localhost:8080/auth/verify.json",
		},
		{
			name: "options become the query string",
			base: "https://passbolt.test",
			path: "/resources.json",
			opt:  &GetResourcesOptions{FilterIsFavorite: true},
			want: "https://passbolt.test/resources.json?filter%5Bis-favorite%5D=true",
		},
		{
			name: "options and a path prefix combine",
			base: "https://passbolt.test/passbolt",
			path: "/resources.json",
			opt:  &GetResourcesOptions{FilterHasTag: "prod"},
			want: "https://passbolt.test/passbolt/resources.json?filter%5Bhas-tag%5D=prod",
		},
		{
			name: "an existing query on the base is replaced",
			base: "https://passbolt.test/passbolt?stale=1",
			path: "/resources.json",
			want: "https://passbolt.test/passbolt/resources.json",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base, err := url.Parse(tc.base)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tc.base, err)
			}
			got, err := generateURL(base, tc.path, tc.opt)
			if err != nil {
				t.Fatalf("generateURL: %v", err)
			}
			if got != tc.want {
				t.Errorf("generateURL(%q, %q) = %q, want %q", tc.base, tc.path, got, tc.want)
			}
		})
	}
}

// TestGenerateURL_DoesNotMutateBase pins the guarantee that makes it safe to hand
// generateURL the Client's own baseURL pointer: it copies, so repeated calls stay
// independent and the caller's URL is untouched. Without the copy, the second call
// would join onto the first call's path.
func TestGenerateURL_DoesNotMutateBase(t *testing.T) {
	t.Parallel()

	const raw = "https://user:pass@passbolt.test/passbolt?keep=me"
	base, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	userinfo := base.User // *url.Userinfo is immutable, so the pointer must survive as-is

	const want = "https://user:pass@passbolt.test/passbolt/resources.json"
	for i := range 3 {
		got, err := generateURL(base, "/resources.json", nil)
		if err != nil {
			t.Fatalf("generateURL call %d: %v", i+1, err)
		}
		if got != want {
			t.Fatalf("call %d returned %q, want %q — base is being mutated across calls", i+1, got, want)
		}
	}

	if base.String() != raw {
		t.Errorf("base is now %q, want %q — generateURL modified the caller's URL", base.String(), raw)
	}
	if base.User != userinfo {
		t.Errorf("base.User was replaced; generateURL must not touch the caller's Userinfo")
	}
}
