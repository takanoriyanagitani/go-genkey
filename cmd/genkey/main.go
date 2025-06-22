package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"

	gk "github.com/takanoriyanagitani/go-genkey"
	. "github.com/takanoriyanagitani/go-genkey/util"
)

var envValByKey func(string) IO[string] = Lift(
	func(key string) (string, error) {
		val, found := os.LookupEnv(key)
		switch found {
		case true:
			return val, nil
		default:
			return "", fmt.Errorf("env var %s missing", key)
		}
	},
)

func limit2filename2bytes(limit int64) func(string) IO[[]byte] {
	return Lift(func(filename string) ([]byte, error) {
		f, e := os.Open(filename)
		if nil != e {
			return nil, e
		}
		defer f.Close()

		limited := &io.LimitedReader{
			R: f,
			N: limit,
		}

		var buf bytes.Buffer
		_, e = io.Copy(&buf, limited)

		return buf.Bytes(), e
	})
}

func limit2env2filename2bytes(limit int64) func(string) IO[[]byte] {
	return func(envKey string) IO[[]byte] {
		var envVal IO[string] = envValByKey(envKey)
		return Bind(
			envVal,
			limit2filename2bytes(limit),
		)
	}
}

var salt IO[gk.Salt] = Bind(
	limit2env2filename2bytes(32)("ENV_IN_PUBLIC_SALT_LOCATION"),
	Lift(func(salt []byte) (gk.Salt, error) {
		return gk.SaltEmpty.AppendRaw(salt), nil
	}),
)

var info IO[gk.Info] = Bind(
	limit2env2filename2bytes(1024)("ENV_IN_PUBLIC_INFO_LOCATION"),
	Lift(func(info []byte) (gk.Info, error) {
		return gk.InfoEmpty.AppendRaw(info), nil
	}),
)

var ikmOriginal IO[gk.Ikm] = Bind(
	limit2env2filename2bytes(32)("ENV_IN_SECRET_IKM_LOCATION"),
	Lift(func(secret []byte) (gk.Ikm, error) {
		return gk.IkmEmpty.AppendSecret(secret), nil
	}),
)

var pepper IO[gk.Pepper] = Bind(
	limit2env2filename2bytes(32)("ENV_IN_SECRET_PEPPER_LOCATION"),
	Lift(func(secret []byte) (gk.Pepper, error) {
		return gk.PepperEmpty.AppendSecret(secret), nil
	}),
)

var ikm IO[gk.Ikm] = Bind(
	pepper,
	func(p gk.Pepper) IO[gk.Ikm] {
		return Bind(
			ikmOriginal,
			Lift(func(original gk.Ikm) (gk.Ikm, error) {
				return p.IntoNewIkm(original), nil
			}),
		)
	},
)

type PublicInput struct {
	gk.Salt
	gk.Info
}

var pinput IO[PublicInput] = Bind(
	salt,
	func(s gk.Salt) IO[PublicInput] {
		return Bind(
			info,
			Lift(func(i gk.Info) (PublicInput, error) {
				return PublicInput{
					Salt: s,
					Info: i,
				}, nil
			}),
		)
	},
)

type KeyGenerator struct {
	gk.Ikm
	gk.Salt
	gk.Info
}

func (g KeyGenerator) GenerateKey(keyLen int) ([]byte, error) {
	return gk.DeriveKey(
		g.Ikm,
		g.Salt,
		g.Info.InfoAsString(),
		keyLen,
	)
}

var keyGen IO[KeyGenerator] = Bind(
	pinput,
	func(i PublicInput) IO[KeyGenerator] {
		return Bind(
			ikm,
			Lift(func(k gk.Ikm) (KeyGenerator, error) {
				return KeyGenerator{
					Ikm:  k,
					Salt: i.Salt,
					Info: i.Info,
				}, nil
			}),
		)
	},
)

var generatedKey32 IO[[]byte] = Bind(
	keyGen,
	Lift(func(g KeyGenerator) ([]byte, error) { return g.GenerateKey(32) }),
)

var digest IO[[]byte] = Bind(
	generatedKey32,
	Lift(func(key []byte) ([]byte, error) {
		var h [32]byte = sha256.Sum256(key)
		return h[:], nil
	}),
)

var printDigest func([]byte) IO[Void] = Lift(
	func(d []byte) (Void, error) {
		fmt.Printf("%x\n", d)
		return Empty, nil
	},
)

var sub IO[Void] = Bind(
	digest,
	printDigest,
)

func main() {
	_, e := sub(context.Background())
	if nil != e {
		log.Printf("%v\n", e)
	}
}
