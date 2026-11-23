package jwt_test

import (
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// nullHS256Key is the offline HMAC secret used for the null-semantics fixtures.
// No network or external key material is involved.
var nullHS256Key = []byte("null-semantics-offline-key")

// makeNullHS256Token builds an HS256 token with a caller-supplied raw claims
// payload, allowing an explicit JSON null to be placed on any registered claim.
// The signature is produced with the library's own signing method, so the
// fixture exercises the real parse + verify + validate pipeline end to end.
func makeNullHS256Token(t *testing.T, claimsJSON string) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	signingInput := enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(claimsJSON))
	sig, err := jwt.SigningMethodHS256.Sign(signingInput, nullHS256Key)
	if err != nil {
		t.Fatalf("could not sign fixture: %v", err)
	}
	return signingInput + "." + enc(sig)
}

func nullKeyFunc(*jwt.Token) (any, error) { return nullHS256Key, nil }

// TestNullClaim_MapAndStructParity is the core convergence test: the same
// signed token carrying an explicit null on a registered claim must reach the
// same validation outcome whether it is parsed into the dynamic MapClaims
// container or into the structured RegisteredClaims container. A null means
// "claim absent", so optional claims validate, required/expected claims fail
// with a missing-claim error, and a genuinely expired (numeric) exp is still
// rejected in both containers.
func TestNullClaim_MapAndStructParity(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		options   []jwt.ParserOption
		wantValid bool
		wantErr   error // nil means the token must validate
	}{
		// Optional time/string claims: null == absent, both carriers validate.
		{name: "exp null is optional", payload: `{"exp":null}`, wantValid: true},
		{name: "nbf null is optional", payload: `{"nbf":null}`, wantValid: true},
		{name: "iat null is optional", payload: `{"iat":null}`, wantValid: true},
		{name: "iss null is optional", payload: `{"iss":null}`, wantValid: true},
		{name: "sub null is optional", payload: `{"sub":null}`, wantValid: true},
		{name: "aud null is optional", payload: `{"aud":null}`, wantValid: true},

		// Null with a requirement: the claim is treated as missing, not as a
		// value, so the requirement must fail with a missing-claim error.
		{
			name:      "exp null with exp required",
			payload:   `{"exp":null}`,
			options:   []jwt.ParserOption{jwt.WithExpirationRequired()},
			wantValid: false,
			wantErr:   jwt.ErrTokenRequiredClaimMissing,
		},
		{
			name:      "nbf null with nbf required",
			payload:   `{"nbf":null}`,
			options:   []jwt.ParserOption{jwt.WithNotBeforeRequired()},
			wantValid: false,
			wantErr:   jwt.ErrTokenRequiredClaimMissing,
		},
		{
			name:      "iss null with issuer expected",
			payload:   `{"iss":null}`,
			options:   []jwt.ParserOption{jwt.WithIssuer("me")},
			wantValid: false,
			wantErr:   jwt.ErrTokenRequiredClaimMissing,
		},
		{
			name:      "sub null with subject expected",
			payload:   `{"sub":null}`,
			options:   []jwt.ParserOption{jwt.WithSubject("me")},
			wantValid: false,
			wantErr:   jwt.ErrTokenRequiredClaimMissing,
		},
		{
			name:      "aud null with audience expected",
			payload:   `{"aud":null}`,
			options:   []jwt.ParserOption{jwt.WithAudience("example.com")},
			wantValid: false,
			wantErr:   jwt.ErrTokenRequiredClaimMissing,
		},

		// iat verification enabled: a null iat carries no instant, so there is
		// nothing to be "in the future"; it validates like an absent iat.
		{
			name:      "iat null with issued-at verification",
			payload:   `{"iat":null}`,
			options:   []jwt.ParserOption{jwt.WithIssuedAt()},
			wantValid: true,
		},

		// Guard rails: a present, numeric time claim keeps its normal meaning.
		// An expired token must never be turned back into a valid one.
		{
			name:      "numeric expired exp stays rejected",
			payload:   `{"exp":` + strconv.FormatInt(time.Now().Unix()-100, 10) + `}`,
			wantValid: false,
			wantErr:   jwt.ErrTokenExpired,
		},
		{
			name:      "future nbf stays not-valid-yet",
			payload:   `{"nbf":` + strconv.FormatInt(time.Now().Unix()+100, 10) + `}`,
			wantValid: false,
			wantErr:   jwt.ErrTokenNotValidYet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString := makeNullHS256Token(t, tt.payload)

			mapToken, mapErr := jwt.NewParser(tt.options...).
				ParseWithClaims(tokenString, jwt.MapClaims{}, nullKeyFunc)
			regToken, regErr := jwt.NewParser(tt.options...).
				ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, nullKeyFunc)

			if (mapErr == nil) != tt.wantValid {
				t.Fatalf("MapClaims validity = %v, want %v (err: %v)", mapErr == nil, tt.wantValid, mapErr)
			}
			if (regErr == nil) != tt.wantValid {
				t.Fatalf("RegisteredClaims validity = %v, want %v (err: %v)", regErr == nil, tt.wantValid, regErr)
			}

			// The two carriers must agree, including the error identity.
			if (mapErr == nil) != (regErr == nil) {
				t.Fatalf("carrier drift: MapClaims err=%v RegisteredClaims err=%v", mapErr, regErr)
			}
			if tt.wantErr != nil {
				if !errors.Is(mapErr, tt.wantErr) {
					t.Errorf("MapClaims error = %v, want errors.Is %v", mapErr, tt.wantErr)
				}
				if !errors.Is(regErr, tt.wantErr) {
					t.Errorf("RegisteredClaims error = %v, want errors.Is %v", regErr, tt.wantErr)
				}
			}

			// token.Valid must track the error outcome in both carriers.
			if mapToken.Valid != tt.wantValid || regToken.Valid != tt.wantValid {
				t.Errorf("token.Valid drift: map=%v struct=%v want=%v", mapToken.Valid, regToken.Valid, tt.wantValid)
			}
		})
	}
}

// TestNullClaim_WrongTypeStillRejected guards the boundary of the null
// convergence. Only an explicit null is treated as "absent"; a non-null value
// of the wrong type must still be rejected in every container. The precise
// error differs by container for structural reasons (MapClaims reports
// ErrInvalidType from its accessor, while a struct fails JSON decoding with
// ErrTokenMalformed), but both outcomes are hard rejections, never a valid
// token. This behavior pre-dates and is intentionally left untouched by the
// null-semantics change.
func TestNullClaim_WrongTypeStillRejected(t *testing.T) {
	tokenString := makeNullHS256Token(t, `{"exp":"soon"}`)

	mapToken, mapErr := jwt.NewParser().
		ParseWithClaims(tokenString, jwt.MapClaims{}, nullKeyFunc)
	if mapErr == nil || mapToken.Valid {
		t.Fatalf("MapClaims must reject a string exp, got err=%v valid=%v", mapErr, mapToken.Valid)
	}
	if !errors.Is(mapErr, jwt.ErrInvalidType) {
		t.Errorf("MapClaims error = %v, want errors.Is %v", mapErr, jwt.ErrInvalidType)
	}

	regToken, regErr := jwt.NewParser().
		ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, nullKeyFunc)
	if regErr == nil || regToken.Valid {
		t.Fatalf("RegisteredClaims must reject a string exp, got err=%v valid=%v", regErr, regToken.Valid)
	}
	if !errors.Is(regErr, jwt.ErrTokenMalformed) {
		t.Errorf("RegisteredClaims error = %v, want errors.Is %v", regErr, jwt.ErrTokenMalformed)
	}
}
