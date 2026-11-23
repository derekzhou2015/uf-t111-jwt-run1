package jwt_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNumericDate(t *testing.T) {
	var s struct {
		Iat jwt.NumericDate `json:"iat"`
		Exp jwt.NumericDate `json:"exp"`
	}

	oldPrecision := jwt.TimePrecision

	jwt.TimePrecision = time.Microsecond

	raw := `{"iat":1516239022.000000,"exp":1516239022.123450}`

	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	b, _ := json.Marshal(s)

	if raw != string(b) {
		t.Errorf("Serialized format of numeric date mismatch. Expecting: %s  Got: %s", raw, string(b))
	}

	jwt.TimePrecision = oldPrecision
}

func TestSingleArrayMarshal(t *testing.T) {
	jwt.MarshalSingleStringAsArray = false

	s := jwt.ClaimStrings{"test"}
	expected := `"test"`

	b, err := json.Marshal(s)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if expected != string(b) {
		t.Errorf("Serialized format of string array mismatch. Expecting: %s  Got: %s", expected, string(b))
	}

	jwt.MarshalSingleStringAsArray = true

	expected = `["test"]`

	b, err = json.Marshal(s)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if expected != string(b) {
		t.Errorf("Serialized format of string array mismatch. Expecting: %s  Got: %s", expected, string(b))
	}
}

func TestNumericDate_MarshalJSON(t *testing.T) {
	// Do not run this test in parallel because it's changing
	// global state.
	oldPrecision := jwt.TimePrecision
	t.Cleanup(func() {
		jwt.TimePrecision = oldPrecision
	})

	tt := []struct {
		in        time.Time
		want      string
		precision time.Duration
	}{
		{time.Unix(5243700879, 0), "5243700879", time.Second},
		{time.Unix(5243700879, 0), "5243700879.000", time.Millisecond},
		{time.Unix(5243700879, 0), "5243700879.000000", time.Microsecond},
		{time.Unix(5243700879, 0), "5243700879.000000000", time.Nanosecond},
		//
		{time.Unix(4239425898, 0), "4239425898", time.Second},
		{time.Unix(4239425898, 0), "4239425898.000", time.Millisecond},
		{time.Unix(4239425898, 0), "4239425898.000000", time.Microsecond},
		{time.Unix(4239425898, 0), "4239425898.000000000", time.Nanosecond},
		//
		{time.Unix(253402271999, 0), "253402271999", time.Second},
		{time.Unix(253402271999, 0), "253402271999.000", time.Millisecond},
		{time.Unix(253402271999, 0), "253402271999.000000", time.Microsecond},
		{time.Unix(253402271999, 0), "253402271999.000000000", time.Nanosecond},
		//
		{time.Unix(0, 1644285000210402000), "1644285000", time.Second},
		{time.Unix(0, 1644285000210402000), "1644285000.210", time.Millisecond},
		{time.Unix(0, 1644285000210402000), "1644285000.210402", time.Microsecond},
		{time.Unix(0, 1644285000210402000), "1644285000.210402000", time.Nanosecond},
		//
		{time.Unix(0, 1644285315063096000), "1644285315", time.Second},
		{time.Unix(0, 1644285315063096000), "1644285315.063", time.Millisecond},
		{time.Unix(0, 1644285315063096000), "1644285315.063096", time.Microsecond},
		{time.Unix(0, 1644285315063096000), "1644285315.063096000", time.Nanosecond},
		// Maximum time that a go time.Time can represent
		{time.Unix(math.MaxInt64, 999999999), "9223372036854775807", time.Second},
		{time.Unix(math.MaxInt64, 999999999), "9223372036854775807.999", time.Millisecond},
		{time.Unix(math.MaxInt64, 999999999), "9223372036854775807.999999", time.Microsecond},
		{time.Unix(math.MaxInt64, 999999999), "9223372036854775807.999999999", time.Nanosecond},
		// Strange precisions
		{time.Unix(math.MaxInt64, 999999999), "9223372036854775807", time.Second},
		{time.Unix(math.MaxInt64, 999999999), "9223372036854775756", time.Minute},
		{time.Unix(math.MaxInt64, 999999999), "9223372036854774016", time.Hour},
		{time.Unix(math.MaxInt64, 999999999), "9223372036854745216", 24 * time.Hour},
	}

	for i, tc := range tt {
		jwt.TimePrecision = tc.precision
		by, err := jwt.NewNumericDate(tc.in).MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if got := string(by); got != tc.want {
			t.Errorf("[%d]: failed encoding: got %q want %q", i, got, tc.want)
		}
	}
}

// TestNumericDate_NullIsNoValue pins the converged null semantics at the
// decoding layer. An explicit JSON null must not be a decode error and must
// leave the value untouched, so a null time claim is read as "no value" rather
// than as the UNIX epoch or a malformed token. This is what makes a null
// exp/nbf/iat decode identically across value-typed and pointer-typed fields.
func TestNumericDate_NullIsNoValue(t *testing.T) {
	t.Run("value-typed field keeps zero value on null", func(t *testing.T) {
		var s struct {
			Exp jwt.NumericDate `json:"exp"`
		}
		if err := json.Unmarshal([]byte(`{"exp":null}`), &s); err != nil {
			t.Fatalf("unexpected error decoding null exp: %v", err)
		}
		if !s.Exp.Time.IsZero() {
			t.Fatalf("expected zero NumericDate after null, got %v", s.Exp.Time)
		}
	})

	t.Run("pointer field becomes nil on null", func(t *testing.T) {
		var s struct {
			Exp *jwt.NumericDate `json:"exp"`
		}
		// Pre-populate to prove decoding null clears it rather than skipping.
		s.Exp = jwt.NewNumericDate(time.Unix(1516239022, 0))
		if err := json.Unmarshal([]byte(`{"exp":null}`), &s); err != nil {
			t.Fatalf("unexpected error decoding null exp: %v", err)
		}
		if s.Exp != nil {
			t.Fatalf("expected nil *NumericDate after null, got %v", s.Exp)
		}
	})

	t.Run("numeric value still decodes after null handling", func(t *testing.T) {
		var s struct {
			Exp jwt.NumericDate `json:"exp"`
		}
		if err := json.Unmarshal([]byte(`{"exp":1516239022}`), &s); err != nil {
			t.Fatalf("unexpected error decoding numeric exp: %v", err)
		}
		if got := s.Exp.Unix(); got != 1516239022 {
			t.Fatalf("expected 1516239022, got %d", got)
		}
	})

	t.Run("non-numeric non-null value still errors", func(t *testing.T) {
		var s struct {
			Exp jwt.NumericDate `json:"exp"`
		}
		if err := json.Unmarshal([]byte(`{"exp":"soon"}`), &s); err == nil {
			t.Fatal("expected a decode error for a string exp, got nil")
		}
	})
}

func TestGetSignatureAfterSigning(t *testing.T) {
	token := jwt.New(jwt.SigningMethodHS256, nil)
	signedString, err := token.SignedString([]byte("test12345"))
	if err != nil {
		t.Fatal(err)
	}

	sigStr := signedString[strings.LastIndex(signedString, ".")+1:]
	sig, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sig, token.Signature) {
		t.Errorf("token.Signature not equal to signature in signed string")
	}
}
