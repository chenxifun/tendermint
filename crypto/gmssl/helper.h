#ifndef GMSSL_HELPER_H
#define GMSSL_HELPER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <gmssl/sm2.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/objects.h>
#include <openssl/opensslconf.h>

int EVP_PKEY_priv2buf(const EVP_PKEY *pkey, unsigned char **priv);
int EVP_PKEY_pub2buf(const EVP_PKEY *pkey, unsigned char **pub);
char *my_buf2hexstr(const unsigned char *buffer, long len);
static int EC_KEY_set_private_key_by_hexstr(EC_KEY *ec_key, const char *hexstr, int IsSecret);
int EVP_PKEY_set_private_key_by_buffer(EVP_PKEY *pkey, const unsigned char *buf, long length, int IsSecret);
static int EC_KEY_set_public_key_by_hexstr(EC_KEY *ec_key, const char *hexstr);
int EVP_PKEY_set_public_key_by_buffer(EVP_PKEY *pkey, const unsigned char *buf, long length);


int EVP_PKEY_priv2buf(const EVP_PKEY *pkey, unsigned char **priv)
{
	EC_KEY *x = EVP_PKEY_get0_EC_KEY((EVP_PKEY *) pkey);
	*priv = NULL;
	int privlen = EC_KEY_priv2buf(x, priv);

    // char *y = my_buf2hexstr(*priv, privlen);
    // printf("%s\n", y);
    // OPENSSL_free(y);
	return privlen;
}

int EVP_PKEY_pub2buf(const EVP_PKEY *pkey, unsigned char **pub)
{
	EC_KEY *x = EVP_PKEY_get0_EC_KEY((EVP_PKEY *) pkey);
	*pub = NULL;
	// int publen = EC_KEY_key2buf(x, EC_KEY_get_conv_form(x), pub, NULL);
    int publen = EC_KEY_key2buf(x, POINT_CONVERSION_COMPRESSED, pub, NULL);

    // char *y = my_buf2hexstr(*pub, publen);
    // printf("%s\n", y);
    // OPENSSL_free(y);
	return publen;
}

char *my_buf2hexstr(const unsigned char *buffer, long len)
{
    const static char hexdig[] = "0123456789ABCDEF";
    char *tmp, *q;
    const unsigned char *p;
    int i;

    if (len == 0)
        return OPENSSL_zalloc(1);

    if ((tmp = OPENSSL_malloc(len * 3)) == NULL) {
        CRYPTOerr(CRYPTO_F_OPENSSL_BUF2HEXSTR, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    q = tmp;
    for (i = 0, p = buffer; i < len; i++, p++) {
        *q++ = hexdig[(*p >> 4) & 0xf];
        *q++ = hexdig[*p & 0xf];
        // *q++ = ':';
    }
    q[0] = '\0';
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(tmp, tmp, q - tmp - 1);
#endif
    return tmp;
}

int EC_KEY_set_private_key_by_hexstr(EC_KEY *ec_key, const char *hexstr, int IsSecret)
{
    if (!ec_key) return 0;

    BIGNUM *priv = BN_new();
    BN_hex2bn(&priv, hexstr);

    if(IsSecret)
    {
        BN_CTX * ctx = BN_CTX_new();
        BIGNUM * order = BN_new();
        if(!EC_GROUP_get_order(EC_KEY_get0_group(ec_key), order, ctx))
            return 0;
        BIGNUM * one = BN_new();
        if(!BN_one(one)) return 0;
        BIGNUM * order_minus_one = BN_new();
        if(!BN_sub(order_minus_one, order, one))
            return 0;
        BIGNUM * temp = BN_new();
        if(!BN_mod(temp, priv, order_minus_one, ctx))
            return 0;
        if(!BN_add(priv, temp, one)) return 0;

        if(BN_num_bytes(priv) != 32)
        {

            if(!BN_lshift(temp, priv, (32 - BN_num_bytes(priv)) * 8))
                return 0;
            BN_copy(priv, temp);
        }
        BN_free(order);
        BN_free(one);
        BN_free(order_minus_one);
        BN_free(temp);
        BN_CTX_free(ctx);
    }


    int ret = EC_KEY_set_private_key(ec_key, priv);

    // Update corresponding public key
    const EC_GROUP * group = EC_KEY_get0_group(ec_key);
    EC_POINT * pub = EC_POINT_new(group);

    BN_CTX * ctx = BN_CTX_new();
    if(!EC_POINT_mul(
        group,
        pub,
        NULL,
        EC_GROUP_get0_generator(group),
        priv,
        ctx
    )) return 0;

    int ret_pub = EC_KEY_set_public_key(ec_key, pub);
    BN_CTX_free(ctx);
    BN_free(priv);

    return ret && ret_pub;
}

int EVP_PKEY_set_private_key_by_buffer(EVP_PKEY *pkey, const unsigned char *buf, long length, int IsSecret)
{
    char *hexstr = my_buf2hexstr(buf, length);
    int ret = EC_KEY_set_private_key_by_hexstr(EVP_PKEY_get1_EC_KEY(pkey), hexstr, IsSecret);
    OPENSSL_free(hexstr);
    return ret;
}

int EC_KEY_set_public_key_by_hexstr(EC_KEY *ec_key, const char *hexstr)
{
    if (!ec_key) return 0;

    BN_CTX *ctx = BN_CTX_new();
    EC_POINT * ec_p = EC_POINT_new(EC_KEY_get0_group(ec_key));
    ec_p = EC_POINT_hex2point(EC_KEY_get0_group(ec_key), hexstr, ec_p, ctx);
    if(ec_p == NULL) return 0;

    int ret = EC_KEY_set_public_key(ec_key, ec_p);

    BN_CTX_free(ctx);
    return ret;
}

int EVP_PKEY_set_public_key_by_buffer(EVP_PKEY *pkey, const unsigned char *buf, long length)
{
    char *hexstr = my_buf2hexstr(buf, length);
    int ret = EC_KEY_set_public_key_by_hexstr(EVP_PKEY_get1_EC_KEY(pkey), hexstr);
    OPENSSL_free(hexstr);
    return ret;
}


#endif // GMSSL_HELPER_H
