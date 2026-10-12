package httpapi_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/CriticalOptimisation/passkey-auth/internal/testauthn"
)

var profiles = []testauthn.Profile{testauthn.Roaming, testauthn.Platform}

// The same suite runs against both classes of authenticator.
func TestRegisterThenAuthenticate(t *testing.T) {
	for _, p := range profiles {
		t.Run(p.Name, func(t *testing.T) {
			e := newEnv(t)
			a := testauthn.New(p, origin)

			reg, err := e.verifyToken(e.register(a, "account-1"))
			if err != nil {
				t.Fatalf("registration token: %v", err)
			}
			e.checkStandardClaims(reg)
			cred := testauthn.B64(a.Latest().ID)
			want := custom{Ceremony: "registration", Origin: origin, Cred: cred, UV: true, BE: p.BackupEligible, BS: p.BackupState, Assurance: "passkey", AAGUID: uuid(p.AAGUID), Fmt: "none"}
			if reg.Subject != "account-1" || reg.custom != want {
				t.Errorf("registration claims:\n got %+v sub %q\nwant %+v sub account-1", reg.custom, reg.Subject, want)
			}

			nonce := newNonce()
			r := e.assertion(a, nonce, testauthn.Overrides{})
			auth, err := e.verifyToken(tokenOf(t, mustOK(t, r)))
			if err != nil {
				t.Fatalf("authentication token: %v", err)
			}
			e.checkStandardClaims(auth)
			want = custom{Ceremony: "authentication", Origin: origin, Cred: cred, UV: true, BE: p.BackupEligible, BS: p.BackupState, Nonce: nonce, Assurance: "passkey", AAGUID: uuid(p.AAGUID)}
			if auth.Subject != "account-1" || auth.custom != want {
				t.Errorf("authentication claims:\n got %+v sub %q\nwant %+v sub account-1", auth.custom, auth.Subject, want)
			}
			if auth.ID == reg.ID {
				t.Error("jti reused across tokens")
			}
		})
	}
}

// registrationOpts is the part of the registration options checked here.
type registrationOpts struct {
	PublicKey struct {
		RP struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"rp"`
		User struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		} `json:"user"`
		Challenge        string `json:"challenge"`
		PubKeyCredParams []struct {
			Type string `json:"type"`
			Alg  int    `json:"alg"`
		} `json:"pubKeyCredParams"`
		Timeout                int `json:"timeout"`
		AuthenticatorSelection struct {
			ResidentKey      string `json:"residentKey"`
			UserVerification string `json:"userVerification"`
		} `json:"authenticatorSelection"`
		Attestation        string `json:"attestation"`
		ExcludeCredentials []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
	} `json:"publicKey"`
}

func TestRegistrationOptions(t *testing.T) {
	e := newEnv(t)
	var opts registrationOpts
	body := e.registrationOptions("account-1")
	if err := json.Unmarshal(body, &opts); err != nil {
		t.Fatal(err)
	}
	pk := opts.PublicKey
	if pk.RP.ID != rpID || pk.RP.Name != "Example" {
		t.Errorf("rp = %+v", pk.RP)
	}
	if n := decodedLen(t, pk.User.ID); n != 64 {
		t.Errorf("user handle is %d bytes, want 64", n)
	}
	if pk.User.Name != "account-1 display" || pk.User.DisplayName != "account-1 display" {
		t.Errorf("user = %+v", pk.User)
	}
	if n := decodedLen(t, pk.Challenge); n != 32 {
		t.Errorf("challenge is %d bytes, want 32", n)
	}
	var algs []int
	for _, p := range pk.PubKeyCredParams {
		algs = append(algs, p.Alg)
	}
	if len(algs) != 3 || algs[0] != -7 || algs[1] != -8 || algs[2] != -257 {
		t.Errorf("algorithms = %v, want [-7 -8 -257]", algs)
	}
	if pk.Timeout != 300000 {
		t.Errorf("timeout = %d, want 300000", pk.Timeout)
	}
	if pk.AuthenticatorSelection.ResidentKey != "required" || pk.AuthenticatorSelection.UserVerification != "required" {
		t.Errorf("authenticatorSelection = %+v", pk.AuthenticatorSelection)
	}
	if pk.Attestation != "direct" {
		t.Errorf("attestation = %q, want direct", pk.Attestation)
	}
	if len(pk.ExcludeCredentials) != 0 {
		t.Errorf("excludeCredentials = %v for a new account", pk.ExcludeCredentials)
	}

	// Complete this registration; the next one for the same account keeps the
	// user handle and excludes the credential just registered.
	a := testauthn.New(testauthn.Roaming, origin)
	resp, err := a.Register(body, testauthn.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	mustOK(t, e.post("/v1/registration/verify", resp))

	var next registrationOpts
	if err := json.Unmarshal(e.registrationOptions("account-1"), &next); err != nil {
		t.Fatal(err)
	}
	if next.PublicKey.User.ID != pk.User.ID {
		t.Error("user handle changed between registrations of the same account")
	}
	ex := next.PublicKey.ExcludeCredentials
	if len(ex) != 1 || ex[0].ID != testauthn.B64(a.Latest().ID) {
		t.Errorf("excludeCredentials = %v, want the registered credential", ex)
	}

	// Another account gets another user handle.
	var other registrationOpts
	if err := json.Unmarshal(e.registrationOptions("account-2"), &other); err != nil {
		t.Fatal(err)
	}
	if other.PublicKey.User.ID == pk.User.ID {
		t.Error("two accounts share a user handle")
	}
}

func TestAuthenticationOptions(t *testing.T) {
	e := newEnv(t)
	var opts struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			Timeout          int    `json:"timeout"`
			RPID             string `json:"rpId"`
			AllowCredentials []any  `json:"allowCredentials"`
			UserVerification string `json:"userVerification"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(e.authenticationOptions(newNonce()), &opts); err != nil {
		t.Fatal(err)
	}
	pk := opts.PublicKey
	if n := decodedLen(t, pk.Challenge); n != 32 {
		t.Errorf("challenge is %d bytes, want 32", n)
	}
	if pk.RPID != rpID || pk.Timeout != 300000 || pk.UserVerification != "required" {
		t.Errorf("options = %+v", pk)
	}
	if pk.AllowCredentials == nil || len(pk.AllowCredentials) != 0 {
		t.Errorf("allowCredentials = %v, want []", pk.AllowCredentials)
	}

	for _, bad := range []string{"", "short", testauthn.B64(random(15)), testauthn.B64(random(65)), "not base64url!"} {
		mustFail(t, e.post("/v1/authentication/options", map[string]string{"nonce": bad}), http.StatusBadRequest, "invalid_request")
	}
}

func TestTicketIsSingleUse(t *testing.T) {
	e := newEnv(t)
	tk := e.ticket("account-1", "Account")
	mustOK(t, e.post("/v1/registration/options", map[string]string{"ticket": tk}))
	mustFail(t, e.post("/v1/registration/options", map[string]string{"ticket": tk}), http.StatusBadRequest, "ticket_invalid")
	mustFail(t, e.post("/v1/registration/options", map[string]string{"ticket": "unknown"}), http.StatusBadRequest, "ticket_invalid")
}

func TestTicketExpires(t *testing.T) {
	e := newEnv(t)
	tk := e.ticket("account-1", "Account")
	e.advance(15*time.Minute + time.Second)
	mustFail(t, e.post("/v1/registration/options", map[string]string{"ticket": tk}), http.StatusBadRequest, "ticket_invalid")
}

func TestWrongOriginIsRejected(t *testing.T) {
	for _, bad := range []string{"https://evil.example", "https://example.com:8443", "http://example.com", "https://sub.example.com"} {
		t.Run(bad, func(t *testing.T) {
			e := newEnv(t)
			a := testauthn.New(testauthn.Roaming, origin)
			resp, err := a.Register(e.registrationOptions("account-1"), testauthn.Overrides{Origin: bad})
			if err != nil {
				t.Fatal(err)
			}
			mustFail(t, e.post("/v1/registration/verify", resp), http.StatusBadRequest, "verification_failed")

			e.register(a, "account-1")
			mustFail(t, e.assertion(a, newNonce(), testauthn.Overrides{Origin: bad}), http.StatusBadRequest, "verification_failed")
		})
	}
}

func TestWrongRPIDIsRejected(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)
	resp, err := a.Register(e.registrationOptions("account-1"), testauthn.Overrides{RPID: "evil.example"})
	if err != nil {
		t.Fatal(err)
	}
	mustFail(t, e.post("/v1/registration/verify", resp), http.StatusBadRequest, "verification_failed")

	e.register(a, "account-1")
	mustFail(t, e.assertion(a, newNonce(), testauthn.Overrides{RPID: "evil.example"}), http.StatusBadRequest, "verification_failed")
}

func TestReplayedChallengeIsRejected(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)

	resp, err := a.Register(e.registrationOptions("account-1"), testauthn.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	mustOK(t, e.post("/v1/registration/verify", resp))
	mustFail(t, e.post("/v1/registration/verify", resp), http.StatusBadRequest, "challenge_invalid")

	assertion, err := a.Authenticate(e.authenticationOptions(newNonce()), testauthn.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	mustOK(t, e.post("/v1/authentication/verify", assertion))
	mustFail(t, e.post("/v1/authentication/verify", assertion), http.StatusBadRequest, "challenge_invalid")
}

func TestUnknownChallengeIsRejected(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)
	e.register(a, "account-1")
	mustFail(t, e.assertion(a, newNonce(), testauthn.Overrides{Challenge: random(32)}), http.StatusBadRequest, "challenge_invalid")
}

func TestExpiredChallengeIsRejected(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)

	resp, err := a.Register(e.registrationOptions("account-1"), testauthn.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	e.advance(5*time.Minute + time.Second)
	mustFail(t, e.post("/v1/registration/verify", resp), http.StatusBadRequest, "challenge_invalid")

	e.register(a, "account-1")
	assertion, err := a.Authenticate(e.authenticationOptions(newNonce()), testauthn.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	e.advance(5*time.Minute + time.Second)
	mustFail(t, e.post("/v1/authentication/verify", assertion), http.StatusBadRequest, "challenge_invalid")
}

// A challenge issued for one ceremony cannot complete the other one.
func TestChallengeIsBoundToItsCeremony(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)
	e.register(a, "account-1")

	var reg struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(e.registrationOptions("account-1"), &reg); err != nil {
		t.Fatal(err)
	}
	challenge, _ := base64.RawURLEncoding.DecodeString(reg.PublicKey.Challenge)
	mustFail(t, e.assertion(a, newNonce(), testauthn.Overrides{Challenge: challenge}), http.StatusBadRequest, "challenge_invalid")
}

func TestUserVerificationIsRequired(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)
	resp, err := a.Register(e.registrationOptions("account-1"), testauthn.Overrides{UV: ptr(false)})
	if err != nil {
		t.Fatal(err)
	}
	mustFail(t, e.post("/v1/registration/verify", resp), http.StatusBadRequest, "verification_failed")

	e.register(a, "account-1")
	mustFail(t, e.assertion(a, newNonce(), testauthn.Overrides{UV: ptr(false)}), http.StatusBadRequest, "verification_failed")
}

func TestSignCounter(t *testing.T) {
	t.Run("synced passkey stays at zero", func(t *testing.T) {
		e := newEnv(t)
		a := testauthn.New(testauthn.Platform, origin)
		e.register(a, "account-1")
		for range 3 {
			mustOK(t, e.assertion(a, newNonce(), testauthn.Overrides{}))
		}
	})
	t.Run("increasing counter is accepted", func(t *testing.T) {
		e := newEnv(t)
		a := testauthn.New(testauthn.Roaming, origin)
		e.register(a, "account-1")
		mustOK(t, e.assertion(a, newNonce(), testauthn.Overrides{})) // 1
		mustOK(t, e.assertion(a, newNonce(), testauthn.Overrides{Counter: ptr(uint32(7))}))
		mustOK(t, e.assertion(a, newNonce(), testauthn.Overrides{})) // 8
	})
	for _, c := range []uint32{5, 3, 0} {
		t.Run(fmt.Sprintf("regression to %d is rejected", c), func(t *testing.T) {
			e := newEnv(t)
			a := testauthn.New(testauthn.Roaming, origin)
			e.register(a, "account-1")
			mustOK(t, e.assertion(a, newNonce(), testauthn.Overrides{Counter: ptr(uint32(5))}))
			mustFail(t, e.assertion(a, newNonce(), testauthn.Overrides{Counter: ptr(c)}), http.StatusBadRequest, "verification_failed")
			// The genuine authenticator, still ahead, keeps working.
			mustOK(t, e.assertion(a, newNonce(), testauthn.Overrides{Counter: ptr(uint32(6))}))
		})
	}
}

func TestUnknownCredentialIsRejected(t *testing.T) {
	e := newEnv(t)
	a := testauthn.New(testauthn.Roaming, origin)
	// A credential created on the authenticator but never sent to the service.
	if _, err := a.Register(e.registrationOptions("account-1"), testauthn.Overrides{}); err != nil {
		t.Fatal(err)
	}
	mustFail(t, e.assertion(a, newNonce(), testauthn.Overrides{}), http.StatusBadRequest, "credential_unknown")
}

func decodedLen(t *testing.T, s string) int {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("%q is not base64url: %v", s, err)
	}
	return len(b)
}

func uuid(b [16]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, x := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hex[x>>4], hex[x&0xf])
	}
	return string(out)
}
