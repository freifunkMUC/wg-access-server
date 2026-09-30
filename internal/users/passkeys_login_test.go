package users

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// softKey is an authenticator in software, enough to sign in with.
type softKey struct {
	key *ecdsa.PrivateKey
	id  []byte
}

func newSoftKey(t *testing.T) *softKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &softKey{key: key, id: id}
}

// register stores the passkey the way FinishRegistration would.
func (k *softKey) register(t *testing.T, s storage.Storage, signCount uint32, cloneWarning bool) {
	t.Helper()
	public := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: k.key.X.FillBytes(make([]byte, 32)),
		YCoord: k.key.Y.FillBytes(make([]byte, 32)),
	}
	encoded, err := webauthncbor.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(webauthn.Credential{
		ID:              k.id,
		PublicKey:       encoded,
		AttestationType: "none",
		Authenticator:   webauthn.Authenticator{SignCount: signCount, CloneWarning: cloneWarning},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddPasskey(&storage.Passkey{
		ID: base64.RawURLEncoding.EncodeToString(k.id), Owner: "alice", Name: "soft", Data: data, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
}

// answer signs the challenge of options with the given sign count.
func (k *softKey) answer(t *testing.T, options json.RawMessage, signCount uint32) []byte {
	t.Helper()
	var parsed struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &parsed); err != nil {
		t.Fatal(err)
	}

	clientData, err := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": parsed.PublicKey.Challenge,
		"origin":    "https://vpn.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	rpID := sha256.Sum256([]byte("vpn.example.com"))
	authData := append(rpID[:], 0x05) // user present and verified
	authData = binary.BigEndian.AppendUint32(authData, signCount)

	clientDataHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	encode := base64.RawURLEncoding.EncodeToString
	answer, err := json.Marshal(map[string]any{
		"id":    encode(k.id),
		"rawId": encode(k.id),
		"type":  "public-key",
		"response": map[string]string{
			"authenticatorData": encode(authData),
			"clientDataJSON":    encode(clientData),
			"signature":         encode(signature),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return answer
}

func (k *softKey) signIn(t *testing.T, p *Passkeys, signCount uint32) error {
	t.Helper()
	options, err := p.BeginLogin(request(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	return p.FinishLogin(request(), "alice", k.answer(t, options, signCount))
}

func storedSignCount(t *testing.T, s storage.Storage, k *softKey) uint32 {
	t.Helper()
	stored, err := s.GetPasskey(base64.RawURLEncoding.EncodeToString(k.id))
	if err != nil {
		t.Fatal(err)
	}
	credential := webauthn.Credential{}
	if err := json.Unmarshal(stored.Data, &credential); err != nil {
		t.Fatal(err)
	}
	return credential.Authenticator.SignCount
}

func TestSigningInWithAPasskey(t *testing.T) {
	p, s := testPasskeys(t)
	key := newSoftKey(t)
	key.register(t, s, 0, false)

	if err := key.signIn(t, p, 5); err != nil {
		t.Fatalf("the passkey was refused: %v", err)
	}
	if got := storedSignCount(t, s, key); got != 5 {
		t.Errorf("stored sign count = %d, want 5", got)
	}
}

// A sign count that goes backwards means two copies of the key are in use.
func TestACloneOfAPasskeyIsRefused(t *testing.T) {
	p, s := testPasskeys(t)
	key := newSoftKey(t)
	key.register(t, s, 5, false)

	if err := key.signIn(t, p, 3); err == nil {
		t.Fatal("a sign count going backwards was accepted")
	}
	if got := storedSignCount(t, s, key); got != 5 {
		t.Errorf("stored sign count = %d after the refused sign-in, want it left at 5", got)
	}
}

// Earlier versions stored the library's clone warning without acting on it.
// Only what this sign-in shows counts, so a passkey with an old warning
// still signs in.
func TestAnOldCloneWarningDoesNotLockThePasskey(t *testing.T) {
	p, s := testPasskeys(t)
	key := newSoftKey(t)
	key.register(t, s, 5, true)

	if err := key.signIn(t, p, 6); err != nil {
		t.Fatalf("the passkey was refused: %v", err)
	}
}

// The same answer sent twice at once must sign in only once.
func TestAPasskeyAnswerCountsOnce(t *testing.T) {
	p, s := testPasskeys(t)
	key := newSoftKey(t)
	key.register(t, s, 0, false)

	options, err := p.BeginLogin(request(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	answer := key.answer(t, options, 1)

	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if p.FinishLogin(request(), "alice", answer) == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != 1 {
		t.Errorf("the answer signed in %d times, want once", got)
	}
}
