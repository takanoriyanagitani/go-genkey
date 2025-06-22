package genkey

import (
	"crypto/sha256"
	"encoding/hex"

	"crypto/hkdf"
)

type Ikm struct{ secret []byte }

var IkmEmpty Ikm

func (i Ikm) AppendHex(hstr string) (Ikm, error) {
	decoded, e := hex.DecodeString(hstr)
	i.secret = append(i.secret, decoded...)
	return i, e
}

func (i Ikm) AppendSecret(s []byte) Ikm {
	i.secret = append(i.secret, s...)
	return i
}

type Pepper struct{ secret []byte }

func (p Pepper) AppendSecret(s []byte) Pepper {
	p.secret = append(p.secret, s...)
	return p
}

var PepperEmpty Pepper

func (p Pepper) IntoNewIkm(original Ikm) Ikm {
	p.secret = append(p.secret, original.secret...)
	return Ikm(p)
}

type Salt struct{ raw []byte }

func (i Salt) AppendHex(hstr string) (Salt, error) {
	decoded, e := hex.DecodeString(hstr)
	i.raw = append(i.raw, decoded...)
	return i, e
}

func (i Salt) AppendRaw(raw []byte) Salt {
	i.raw = append(i.raw, raw...)
	return i
}

type Info struct{ info []byte }

var InfoEmpty Info

func (i Info) AppendRaw(raw []byte) Info {
	i.info = append(i.info, raw...)
	return i
}

func (i Info) InfoAsString() string { return string(i.info) }

var SaltEmpty Salt

func DeriveKey(
	ikm Ikm,
	salt Salt,
	info string,
	keyLen int,
) ([]byte, error) {
	return hkdf.Key(
		sha256.New,
		ikm.secret,
		salt.raw,
		info,
		keyLen,
	)
}
