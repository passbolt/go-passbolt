package api

type MFAChallenge struct {
	Provider MFAProviders `json:"providers,omitempty"`
}

type MFAProviders struct {
	TOTP string `json:"totp,omitempty"`
}

type MFAChallengeResponse struct {
	TOTP string `json:"totp,omitempty"`
}
