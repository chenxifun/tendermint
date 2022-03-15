package gmssl

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"math/big"
	"encoding/json"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/tendermint/tendermint/crypto/tmhash"
	"github.com/tendermint/tendermint/crypto"
	tmjson "github.com/tendermint/tendermint/libs/json"
)

const (
	PrivKeyName = "tendermint/PrivKeyGmSSL"
	PubKeyName = "tendermint/PubKeyGmSSL"

	PrivKeySize = 32
	PubKeySize = 33
	SignatureSize = 64

	KeyType = "gmssl"
)

func init() {
	tmjson.RegisterType(&PubKeySm2{}, PubKeyName)
	tmjson.RegisterType(&PrivKeySm2{}, PrivKeyName)
}

var _ crypto.PrivKey = &PrivKeySm2{}
var _ crypto.PubKey = &PubKeySm2{}

// type PrivKeySm2 *PrivateKey


type PrivKeySm2 struct {
	Key *PrivateKey
}

type PubKeySm2 struct { 
	Key *PublicKey
}

func (privKey *PrivKeySm2) UnmarshalJSON(sk []byte) error {
	// fmt.Println(string(sk))
	var buffer []byte
	if err := json.Unmarshal(sk, &buffer); err != nil {
		return err
	}

	sm2keygenargs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2sk, err := GeneratePrivateKeyByBuffer("EC", sm2keygenargs, nil, buffer[:])
	PanicError(err)
	privKey.Key = sm2sk
	return err
}

func (privKey *PrivKeySm2) MarshalJSON() ([]byte, error) {
	blob, err := json.Marshal(privKey.Bytes())
	return blob[:], err
}


func (privKey *PrivKeySm2) Bytes() []byte {
	ret, err := privKey.Key.GetKeyBuffer()
	PanicError(err)
	return ret
}

func (privKey *PrivKeySm2) Type() string {
	return PrivKeyName
}


func GenPrivKey() *PrivKeySm2 {
	sm2keygenargs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2sk, err := GeneratePrivateKey("EC", sm2keygenargs, nil)
	PanicError(err)
	return &PrivKeySm2{Key: sm2sk}
}

func GenPrivKeyByBuf(buffer []byte) *PrivKeySm2 {
	sm2keygenargs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2sk, err := GeneratePrivateKeyByBuffer("EC", sm2keygenargs, nil, buffer[:])
	PanicError(err)
	return &PrivKeySm2{Key :sm2sk}
}

func GenPrivKeyFromSecret(secret []byte) *PrivKeySm2 {
	secHash := sha256.Sum256(secret);
	sm2keygenargs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2sk, err := GeneratePrivateKeyBySecret("EC", sm2keygenargs, nil, secHash[:])
	PanicError(err)
	return &PrivKeySm2{Key :sm2sk}
}

func (privKey *PrivKeySm2) PubKey() crypto.PubKey {
	sm2pk, err := privKey.Key.GetPublicKey()
	PanicError(err)

	return &PubKeySm2{Key: sm2pk}
}

func (privKey *PrivKeySm2) Sign(msg []byte) ([]byte, error) {
	sm3ctx, err := NewDigestContext(SM3)
	PanicError(err)
	err = sm3ctx.Reset()
	PanicError(err)
	
	default_uid := "1234567812345678"
	sm2_zid, err:= privKey.Key.ComputeSM2IDDigest(default_uid)
	PanicError(err)

	err = sm3ctx.Update(sm2_zid)
	PanicError(err)

	err = sm3ctx.Update(msg)
	PanicError(err)

	digest, err := sm3ctx.Final()
	PanicError(err)

	sig, err := privKey.Key.Sign("sm2sign", digest, nil)
	if err != nil {
		return nil, err
	}
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return nil, GetErrors()
	}

	ret := make([]byte, 64)
	R := r.Bytes()
	S := s.Bytes()
	copy(ret[32-len(R):32], R[:])
	copy(ret[64-len(S):], S[:])

	return ret[:], nil
}

func (privKey *PrivKeySm2) Equals(other crypto.PrivKey) bool {
	if otherSm2, ok := other.(*PrivKeySm2); ok {
		return bytes.Equal(
			privKey.Bytes(), otherSm2.Bytes(),
		)
	} else {
		return false
	}
}

func GenPubKeyByBuf(keyData []byte) *PubKeySm2 {
	sm2keygenargs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	pubkey, err := GeneratePublicKeyByBuffer("EC", sm2keygenargs, nil, keyData[:])
	PanicError(err)
	return &PubKeySm2{Key: pubkey}
}

func (pubKey *PubKeySm2) UnmarshalJSON(pk []byte) error {
	var buffer []byte
	if err := json.Unmarshal(pk, &buffer); err != nil {
		return err
	}

	sm2keygenargs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2pk, err := GeneratePublicKeyByBuffer("EC", sm2keygenargs, nil, buffer[:])
	PanicError(err)
	pubKey.Key = sm2pk
	return err
}

func (pubKey *PubKeySm2) MarshalJSON() ([]byte, error) {
	blob, err := json.Marshal(pubKey.Bytes())
	return blob[:], err
}

func (pubKey *PubKeySm2) Type() string {
	return KeyType
}

func (pubKey *PubKeySm2) Bytes() []byte {
	ret, err := pubKey.Key.GetKeyBuffer()
	PanicError(err)
	return ret
}

func (pubKey *PubKeySm2) Address() crypto.Address {
	return crypto.Address(tmhash.SumTruncated(pubKey.Bytes()))
}

func (pubKey *PubKeySm2) Equals(other crypto.PubKey) bool {
	if otherSm2, ok := other.(*PubKeySm2); ok {
		return bytes.Equal(
			pubKey.Bytes(), otherSm2.Bytes(),
		)
	} else {
		return false
	}
}

func (pubKey *PubKeySm2) VerifySignature(msg []byte, sig []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})

	sm3ctx, err := NewDigestContext(SM3)
	PanicError(err)

	err = sm3ctx.Reset()
	PanicError(err)
	
	default_uid := "1234567812345678"
	sm2_zid, err := pubKey.Key.ComputeSM2IDDigest(default_uid)
	PanicError(err)

	err = sm3ctx.Update(sm2_zid)
	PanicError(err)

	err = sm3ctx.Update(msg)
	PanicError(err)

	digest, err := sm3ctx.Final()
	PanicError(err)

	ret, err := b.Bytes()
	PanicError(err)

	return pubKey.Key.Verify("sm2sign", digest, ret, nil) == nil
}

func (pubKey *PubKeySm2) String() string {
	return fmt.Sprintf("PubKeySm2{%X}", pubKey.Bytes()[:])
}
