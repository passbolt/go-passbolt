package api

type MFAChallange struct {
	Provider MFAProviders `json:"providers,omitempty"`
}

type MFAProviders struct {
	TOTP string `json:"totp,omitempty"`
}

type MFAChallangeResponse struct {
	TOTP string `json:"totp,omitempty"`
}
