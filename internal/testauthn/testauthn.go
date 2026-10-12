// Package testauthn is a software WebAuthn authenticator for tests.
//
// It answers the options returned by the service with the JSON a browser
// would post (WebAuthn Level 3 serialisation), and lets a test forge any part
// of a ceremony: origin, RP ID hash, client data type, challenge, flags and
// signature counter. It uses ES256 keys and "none" attestation.
package testauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator data flags.
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
)

// Profile describes a class of authenticator.
type Profile struct {
	Name           string
	Attachment     string   // "platform" or "cross-platform"
	Transports     []string // reported at registration
	AAGUID         [16]byte
	UV             bool   // user verification performed
	BackupEligible bool   // BE flag
	BackupState    bool   // BS flag
	CounterStep    uint32 // added to the counter at each assertion; 0 for synced passkeys
}

// Roaming is a CTAP2 USB security key: resident keys, UV, a counting
// signature counter, no backup.
var Roaming = Profile{
	Name:        "roaming",
	Attachment:  "cross-platform",
	Transports:  []string{"usb"},
	AAGUID:      [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
	UV:          true,
	CounterStep: 1,
}

// Platform is a platform authenticator holding a synced passkey: backup
// eligible and backed up, counter always 0.
var Platform = Profile{
	Name:           "platform",
	Attachment:     "platform",
	Transports:     []string{"internal", "hybrid"},
	AAGUID:         [16]byte{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
	UV:             true,
	BackupEligible: true,
	BackupState:    true,
}

// Overrides forge parts of one ceremony. Zero values keep the honest
// behaviour.
type Overrides struct {
	Origin       string  // clientDataJSON.origin; default: the authenticator's origin
	RPID         string  // RP ID hashed into authenticator data; default: from the options
	Type         string  // clientDataJSON.type; default: webauthn.create / webauthn.get
	Challenge    []byte  // clientDataJSON.challenge; default: from the options
	UV           *bool   // UV flag; default: the profile's
	Counter      *uint32 // exact counter to report (assertions only); default: stored + step
	CredentialID []byte  // credential to use (assertions only); default: the latest for the RP ID
	CrossOrigin  bool    // clientDataJSON.crossOrigin
	TopOrigin    string  // clientDataJSON.topOrigin; omitted when empty
}

// Credential is a key pair held by the authenticator.
type Credential struct {
	ID         []byte
	RPID       string
	UserHandle []byte
	Key        *ecdsa.PrivateKey
	Counter    uint32
}

// Authenticator is a software authenticator for one profile, used from one
// origin.
type Authenticator struct {
	Profile Profile
	Origin  string
	creds   []*Credential
}

// New returns an empty authenticator.
func New(p Profile, origin string) *Authenticator {
	return &Authenticator{Profile: p, Origin: origin}
}

// Credentials returns the credentials created so far, oldest first.
func (a *Authenticator) Credentials() []*Credential { return a.creds }

// Latest returns the most recent credential, or nil.
func (a *Authenticator) Latest() *Credential {
	if len(a.creds) == 0 {
		return nil
	}
	return a.creds[len(a.creds)-1]
}

// PrivateKeyBytes returns the private scalars of every credential, to check
// that none of them ever reaches the service.
func (a *Authenticator) PrivateKeyBytes() [][]byte {
	var out [][]byte
	for _, c := range a.creds {
		b, err := c.Key.Bytes()
		if err != nil {
			panic(err)
		}
		out = append(out, b)
	}
	return out
}

var b64 = base64.RawURLEncoding

// B64 is base64url without padding, as used throughout WebAuthn JSON.
func B64(b []byte) string { return b64.EncodeToString(b) }

type creationOptions struct {
	PublicKey struct {
		RP struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Challenge          string `json:"challenge"`
		ExcludeCredentials []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
	} `json:"publicKey"`
}

type requestOptions struct {
	PublicKey struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

// Register creates a credential from the body of a registration options
// response and returns the RegistrationResponseJSON to post.
func (a *Authenticator) Register(optionsJSON []byte, o Overrides) ([]byte, error) {
	var opts creationOptions
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return nil, fmt.Errorf("testauthn: creation options: %w", err)
	}
	pk := opts.PublicKey
	challenge, err := b64.DecodeString(pk.Challenge)
	if err != nil {
		return nil, fmt.Errorf("testauthn: challenge: %w", err)
	}
	userHandle, err := b64.DecodeString(pk.User.ID)
	if err != nil {
		return nil, fmt.Errorf("testauthn: user.id: %w", err)
	}
	for _, ex := range pk.ExcludeCredentials {
		for _, c := range a.creds {
			if B64(c.ID) == ex.ID {
				return nil, errors.New("testauthn: InvalidStateError: credential excluded")
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	cred := &Credential{ID: random(32), RPID: pk.RP.ID, UserHandle: userHandle, Key: key}

	rpID := pk.RP.ID
	if o.RPID != "" {
		rpID = o.RPID
	}
	authData := a.authData(rpID, a.flags(o)|flagAT, 0)
	authData = append(authData, a.Profile.AAGUID[:]...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(cred.ID)))
	authData = append(authData, cred.ID...)
	coseKey, err := coseES256(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	authData = append(authData, coseKey...)

	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		return nil, err
	}
	clientData, err := a.clientData("webauthn.create", challenge, o)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	a.creds = append(a.creds, cred)

	return json.Marshal(map[string]any{
		"id":    B64(cred.ID),
		"rawId": B64(cred.ID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":     B64(clientData),
			"attestationObject":  B64(attObj),
			"authenticatorData":  B64(authData),
			"publicKey":          B64(spki),
			"publicKeyAlgorithm": -7,
			"transports":         a.Profile.Transports,
		},
		"authenticatorAttachment": a.Profile.Attachment,
		"clientExtensionResults":  map[string]any{},
	})
}

// Authenticate signs an assertion for the body of an authentication options
// response and returns the AuthenticationResponseJSON to post.
func (a *Authenticator) Authenticate(optionsJSON []byte, o Overrides) ([]byte, error) {
	var opts requestOptions
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return nil, fmt.Errorf("testauthn: request options: %w", err)
	}
	pk := opts.PublicKey
	challenge, err := b64.DecodeString(pk.Challenge)
	if err != nil {
		return nil, fmt.Errorf("testauthn: challenge: %w", err)
	}
	cred := a.pick(pk.RPID, o.CredentialID)
	if cred == nil {
		return nil, errors.New("testauthn: NotAllowedError: no credential for this RP ID")
	}

	counter := cred.Counter + a.Profile.CounterStep
	if o.Counter != nil {
		counter = *o.Counter
	}
	cred.Counter = counter

	rpID := pk.RPID
	if o.RPID != "" {
		rpID = o.RPID
	}
	authData := a.authData(rpID, a.flags(o), counter)
	clientData, err := a.clientData("webauthn.get", challenge, o)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(clientData)
	signed := sha256.Sum256(append(append([]byte{}, authData...), digest[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, cred.Key, signed[:])
	if err != nil {
		return nil, err
	}

	return json.Marshal(map[string]any{
		"id":    B64(cred.ID),
		"rawId": B64(cred.ID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    B64(clientData),
			"authenticatorData": B64(authData),
			"signature":         B64(sig),
			"userHandle":        B64(cred.UserHandle),
		},
		"authenticatorAttachment": a.Profile.Attachment,
		"clientExtensionResults":  map[string]any{},
	})
}

func (a *Authenticator) pick(rpID string, id []byte) *Credential {
	for i := len(a.creds) - 1; i >= 0; i-- {
		c := a.creds[i]
		if id != nil && string(c.ID) == string(id) {
			return c
		}
		if id == nil && c.RPID == rpID {
			return c
		}
	}
	return nil
}

func (a *Authenticator) flags(o Overrides) byte {
	f := byte(flagUP)
	uv := a.Profile.UV
	if o.UV != nil {
		uv = *o.UV
	}
	if uv {
		f |= flagUV
	}
	if a.Profile.BackupEligible {
		f |= flagBE
	}
	if a.Profile.BackupState {
		f |= flagBS
	}
	return f
}

func (a *Authenticator) authData(rpID string, flags byte, counter uint32) []byte {
	h := sha256.Sum256([]byte(rpID))
	d := append([]byte{}, h[:]...)
	d = append(d, flags)
	return binary.BigEndian.AppendUint32(d, counter)
}

func (a *Authenticator) clientData(typ string, challenge []byte, o Overrides) ([]byte, error) {
	if o.Type != "" {
		typ = o.Type
	}
	if o.Challenge != nil {
		challenge = o.Challenge
	}
	origin := a.Origin
	if o.Origin != "" {
		origin = o.Origin
	}
	cd := map[string]any{
		"type":        typ,
		"challenge":   B64(challenge),
		"origin":      origin,
		"crossOrigin": o.CrossOrigin,
	}
	if o.TopOrigin != "" {
		cd["topOrigin"] = o.TopOrigin
	}
	return json.Marshal(cd)
}

// coseES256 encodes a P-256 public key as a COSE_Key (RFC 9053).
func coseES256(pub *ecdsa.PublicKey) ([]byte, error) {
	raw, err := pub.Bytes() // 0x04 || X || Y
	if err != nil {
		return nil, err
	}
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return enc.Marshal(map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: raw[1:33],
		-3: raw[33:65],
	})
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
