package gmssl_test

import (
	"bytes"
	"fmt"
	"testing"

	// "github.com/stretchr/testify/assert"
	// "github.com/stretchr/testify/require"
	crypto "github.com/tendermint/tendermint/crypto"
	gmssl "github.com/tendermint/tendermint/crypto/gmssl"
	sm2 "github.com/tendermint/tendermint/crypto/sm2"
	// big "math/big"
	// "golang.org/x/crypto/cryptobyte"
	// cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func newSM3DigestContext() *gmssl.DigestContext {
	sm3ctx, err := gmssl.NewDigestContext(gmssl.SM3)
	gmssl.PanicError(err)
	return sm3ctx
}

func TestTjfocGmSSLMatched(t *testing.T) {
	privKey_sm2 := sm2.GenPrivKey()
	// privKey_sm2[len(privKey_sm2)-1] = 1
	// for i:=0; i<len(privKey_sm2)-1; i++ {
	// 	privKey_sm2[i] = 0
	// }

	pubKey_sm2 := privKey_sm2.PubKey().(sm2.PubKeySm2)
	msg := crypto.CRandBytes(128)

	sig_sm2, err := privKey_sm2.Sm2Sign(msg)
	gmssl.PanicError(err)

	if !pubKey_sm2.Sm2VerifyBytes(msg, sig_sm2) {
		fmt.Printf("# : Verify error\n")
	}

	privKey_gmssl := gmssl.GenPrivKeyByBuf(privKey_sm2.Bytes()[:])

	if bytes.Equal(privKey_sm2.Bytes()[:], privKey_gmssl.Bytes()[:]) {
		fmt.Println("Private Key Assign Succeed!")
	} else {
		t.Fatalf("Private Key Assign Failed")
	}

	pubKey_gmssl := privKey_gmssl.PubKey()
	pubKey_gmssl2 := gmssl.GenPubKeyByBuf(pubKey_sm2.Bytes())
	if bytes.Equal(pubKey_sm2.Bytes()[:], pubKey_gmssl.Bytes()[:]) {
		fmt.Println("Public Key Assign Succeed!")
	} else {
		t.Fatalf("Public Key Assign Failed")
	}

	if bytes.Equal(pubKey_sm2.Bytes()[:], pubKey_gmssl2.Bytes()[:]) {
		fmt.Println("Public Key Assign Succeed!")
	} else {
		t.Fatalf("Public Key Assign Failed")
	}

	if bytes.Equal(pubKey_sm2.Address().Bytes(), pubKey_gmssl.Address().Bytes()[:]) {
		fmt.Println("Same address for public key!")
	} else {
		t.Fatalf("Different address for public key")
	}

	sig_gmssl, err := privKey_gmssl.Sign(msg)
	gmssl.PanicError(err)
	if pubKey_gmssl.VerifySignature(msg, sig_sm2) {
		fmt.Println("Signature by tjfoc can be verified by GmSSL!")
	} else {
		t.Fatalf("Signature by tjfoc can not be verified by GmSSL")
	}

	if pubKey_gmssl2.VerifySignature(msg, sig_sm2) {
		fmt.Println("Signature by tjfoc can be verified by GmSSL!")
	} else {
		t.Fatalf("Signature by tjfoc can not be verified by GmSSL")
	}

	if pubKey_sm2.Sm2VerifyBytes(msg, sig_gmssl) {
		fmt.Println("Signature by GmSSL can be verified by tjfoc!")
	} else {
		t.Fatalf("Signature by GmSSL can be not verified by tjfoc!")
	}

	privKey_sm2_secret := sm2.GenPrivKeySm2FromSecret(msg)
	privKey_gmssl_secret := gmssl.GenPrivKeyFromSecret(msg)

	if bytes.Equal(privKey_gmssl_secret.Bytes(), privKey_sm2_secret.Bytes()) {
		fmt.Println("Generate same secret private key!")
	} else {
		t.Fatalf("Generate different secret private key")
	}

	if bytes.Equal(privKey_gmssl_secret.PubKey().Bytes(), privKey_sm2_secret.PubKey().Bytes()) {
		fmt.Println("Generate same secret public key!")
	} else {
		t.Fatalf("Generate different secret public key")
	}
}

func TestGmSSLVerify(t *testing.T) {
	for i := 0; i < 1; i++ {
		/* SM2 key pair operations */
		// secret := crypto.CRandBytes(32)
		// privKey := gmssl.GenPrivKeyFromSecret(secret[:])
		// fmt.Println(i)
		privKey := gmssl.GenPrivKey()
		pubKey := privKey.PubKey().(*gmssl.PubKeySm2)
		msg := crypto.CRandBytes(128)
		sig, err := privKey.Sign(msg)
		gmssl.PanicError(err)

		// Test the signature
		if !pubKey.VerifySignature(msg[:], sig[:]) {

			fmt.Println("msg = ")
			fmt.Println(msg)
			fmt.Println("sig = ")
			fmt.Println(sig)
			fmt.Println(len(sig))
			t.Fatalf("Verify error\n")
		}
	}

}

func BenchmarkGmSSLVerify(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < 1000; i++ {
		// secret := crypto.CRandBytes(32)
		// sk := gmssl.GenPrivKeyFromSecret(secret[:])
		sk := gmssl.GenPrivKey()
		fmt.Println(sk)
		pk := sk.PubKey()
		fmt.Println(pk)

		// msg := crypto.CRandBytes(128)
		// fmt.Println(msg)
		// , _ := sk.Sign(msg)

		// pk.VerifySignature(msg[:], sig[:])
	}
}

func BenchmarkSm2Verify(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		secret := crypto.CRandBytes(32)
		sk := sm2.GenPrivKeySm2FromSecret(secret[:])
		pk := sk.PubKey()

		msg := crypto.CRandBytes(128)
		sig, _ := sk.Sign(msg)

		pk.VerifySignature(msg[:], sig[:])
	}
}

func TestKeyPair(t *testing.T) {
	/* SM2 key pair operations */
	sm2keygenargs := [][2]string{
		{"ec_paramgen_curve", "sm2p256v1"},
		{"ec_param_enc", "named_curve"},
	}
	sm2sk, err := gmssl.GeneratePrivateKey("EC", sm2keygenargs, nil)
	gmssl.PanicError(err)
	sm2pk, err := sm2sk.GetPublicKey()
	gmssl.PanicError(err)
	sm3ctx := newSM3DigestContext()
	/* SM2 sign/verification */
	sm2zid, err := sm2pk.ComputeSM2IDDigest("1234567812345678")
	gmssl.PanicError(err)

	err = sm3ctx.Reset()
	gmssl.PanicError(err)
	err = sm3ctx.Update(sm2zid)
	gmssl.PanicError(err)
	err = sm3ctx.Update([]byte("test"))
	gmssl.PanicError(err)
	digest, err := sm3ctx.Final()
	gmssl.PanicError(err)
	fmt.Println(digest)

	signature, err := sm2sk.Sign("sm2sign", digest, nil)
	gmssl.PanicError(err)

	fmt.Printf("sm2sign(sm3(\"test\")) = \n")
	fmt.Println(signature)

	fmt.Printf("length of signature = %d\n", len(signature))

	err = sm2pk.Verify("sm2sign", digest, signature, nil)
	if err == nil {
		fmt.Printf("sm2 verify success\n")
	} else {
		t.Fatalf("sm2 verify failure")
	}
}
