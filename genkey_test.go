package genkey_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	gk "github.com/takanoriyanagitani/go-genkey"
)

func TestGenkey(t *testing.T) {
	t.Parallel()

	t.Run("DeriveKey", func(t *testing.T) {
		t.Parallel()

		t.Run("well-known", func(t *testing.T) {
			t.Parallel()

			ikm, e := gk.
				IkmEmpty.
				AppendHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
			if nil != e {
				t.Fatalf("invalid ikm: %v\n", e)
			}

			salt, e := gk.
				SaltEmpty.
				AppendHex("000102030405060708090a0b0c")
			if nil != e {
				t.Fatalf("invalid salt: %v\n", e)
			}

			info, err := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
			if nil != err {
				t.Fatalf("invalid info: %v\n", err)
			}

			derived, e := gk.DeriveKey(
				ikm,
				salt,
				string(info),
				42,
			)
			if nil != e {
				t.Fatalf("unable to derive a key: %v\n", e)
			}

			expected, err := hex.DecodeString(
				"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
			)
			if nil != err {
				t.Fatalf("unexpected err: %v\n", err)
			}

			if !bytes.Equal(expected, derived) {
				t.Fatalf("key unmatch\n")
			}
		})
	})
}
