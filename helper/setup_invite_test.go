package helper

import "testing"

// ParseInviteURL splits a Passbolt invite URL into a user ID and a
// setup token. The integration TestMain uses it to bootstrap the test
// client, so a regression breaks the entire integration suite — a
// localized unit test surfaces the problem before it spreads.

func TestParseInviteURL(t *testing.T) {
	t.Parallel()

	const userID = "11111111-1111-1111-1111-111111111111"
	const token = "22222222-2222-2222-2222-222222222222"

	cases := []struct {
		name     string
		input    string
		wantUser string
		wantTok  string
		wantErr  bool
	}{
		{
			// Canonical invite URL emitted by Passbolt.
			name:     "valid URL with .json suffix",
			input:    "https://passbolt.example.com/setup/install/" + userID + "/" + token + ".json",
			wantUser: userID,
			wantTok:  token,
		},
		{
			// Some flows omit the .json suffix; the function must
			// still extract both parts cleanly.
			name:     "valid URL without .json suffix",
			input:    "https://passbolt.example.com/setup/install/" + userID + "/" + token,
			wantUser: userID,
			wantTok:  token,
		},
		{
			// Anything with fewer than 4 slashes fails the
			// arithmetic — the function returns a descriptive error
			// rather than indexing into a too-short slice.
			name:    "too few slashes",
			input:   "no-slashes-at-all",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			user, tok, err := ParseInviteURL(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil (user=%q, token=%q)", tc.input, user, tok)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if user != tc.wantUser {
				t.Errorf("userID = %q, want %q", user, tc.wantUser)
			}
			if tok != tc.wantTok {
				t.Errorf("token = %q, want %q", tok, tc.wantTok)
			}
		})
	}
}
