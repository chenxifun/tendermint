/*
 * Copyright 2020 The Hyperledger-TWGC Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/* +build cgo */

package gmssl

/*
#cgo CFLAGS: -I/usr/local/gmssl/include
#cgo LDFLAGS: -L/usr/local/gmssl/lib -lssl -lcrypto -ldl

#include <openssl/bio.h>
#include <openssl/crypto.h>

long _BIO_get_mem_data(BIO *b, char **pp) {
	return BIO_get_mem_data(b, pp);
}

void _OPENSSL_free(void *addr) {
	OPENSSL_free(addr);
}
*/
import "C"
