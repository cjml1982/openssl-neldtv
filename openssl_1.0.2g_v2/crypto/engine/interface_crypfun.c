/*---------------------------------------------------------------------------
//
//	Copyright(C) NELDTV Corporation, 2011-2016.
//
//  File	:	interface_cryfun.c
//	Purpose	:
//	History :
//	2017-08-16 modified  by Shiney Yu
//	2017-08-06 modified  by Guohao	
//	2018-08-06 created by Bitter Chen
//
//
--------------------------------------------------------------------------*/


#define M_LINUXPLAT


#ifndef  M_LINUXPLAT

#include "windows.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>

#include <openssl/crypto.h>
#include <openssl/e_os2.h>
#include <openssl/ecdsa.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha1_routines.h>
#include <openssl/sha2_routines.h>

#else
	
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#include <openssl/crypto.h>
#include <openssl/e_os2.h>
#include <openssl/ecdsa.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha1_routines.h>
#include <openssl/sha2_routines.h>


#endif

#include <openssl/interface_crypfun.h>
//#include "end_porting.h"  


#define   M_CRYPTODEV_VERSION_STR   "CryptoDev 1.08 NELDTV"
//#define   M_CODE_MODE_SOFT


#define   M_CLOSED_ST   (0)
#define   M_OPENED_ST   (1)

unsigned int  g_uni_cryptodev_status = M_CLOSED_ST;
/*
#ifndef  M_LINUXPLAT
HANDLE ghandle = NULL;
#else
HANDLE ghandle = 0;	
#endif
*/
/* CDE instance */
ENGINE *cryptodev_e =NULL;
ENGINE *openssl_default_e = NULL;


static ENGINE *load_cryptodev()
{
    ENGINE *e;
    ENGINE_load_cryptodev();
    ENGINE_load_builtin_engines();
    ENGINE_load_dynamic();
    e = ENGINE_by_id("cryptodev");
    if(!e)
        return NULL;

#if 0    
    print_debug("Setting engine default digest :%d\n",ENGINE_set_default_digests(e));
    print_debug("Setting engine default cipher :%d\n",ENGINE_set_default_ciphers(e));
#endif
    return e;
}

static ENGINE *load_openssl_default()
{
    ENGINE *e;
    ENGINE_load_openssl_default();
    ENGINE_load_builtin_engines2();
    ENGINE_load_dynamic();
    e = ENGINE_by_id("openssl_default");
    if(!e)
        return NULL;

#if 0    
    print_debug("Setting engine default digest :%d\n",ENGINE_set_default_digests(e));
    print_debug("Setting engine default cipher :%d\n",ENGINE_set_default_ciphers(e));
#endif
	return e;
}

static ENGINE *load_cryptodev_nodigst()
{
    ENGINE *e;
    ENGINE_load_cryptodev_nodigst();
    ENGINE_load_builtin_engines();
    ENGINE_load_dynamic();
    e = ENGINE_by_id("cryptodev");
    if(!e)
        return NULL;

#if 0    
    print_debug("Setting engine default digest :%d\n",ENGINE_set_default_digests(e));
    print_debug("Setting engine default cipher :%d\n",ENGINE_set_default_ciphers(e));
#endif
    return e;
}


NELDTVC_RV  NELDTV_open_cryptodev(void)
{
	unsigned int  uni_retst = M_NELDTVCR_OK;

//	SSL_library_init();
//    SSL_load_error_strings();
    if (NULL != openssl_default_e){
	ENGINE_free(openssl_default_e);
	openssl_default_e =NULL;
# ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
# endif
	}
	if(NULL == cryptodev_e ){
		OpenSSL_add_all_algorithms();
		/* LOAD CRYPTODEV ENGINE */
		if (NULL == (cryptodev_e = load_cryptodev()))
		{
			printf("CRYPTODEV ENGINE IS NOT AVAILABLE \n"); 
			uni_retst = M_NELDTVCR_ENOTOPENDEV;
		}
		ENGINE_register_complete(cryptodev_e);
	}
	return uni_retst;
}


NELDTVC_RV  NELDTV_open_cryptodev_nodigst(void)
{
	unsigned int  uni_retst = M_NELDTVCR_OK;

//	SSL_library_init();
//    SSL_load_error_strings();

	/* LOAD CRYPTODEV ENGINE */
	if (NULL == (cryptodev_e = load_cryptodev_nodigst()))
	{
		 OpenSSL_add_all_algorithms();
		printf("CRYPTODEV ENGINE IS NOT AVAILABLE \n"); 
		uni_retst = M_NELDTVCR_ENOTOPENDEV;
	}
	ENGINE_register_complete(cryptodev_e);
	return uni_retst;
}



NELDTVC_RV  NELDTV_close_cryptodev(void)
{
    unsigned int  uni_retst = M_NELDTVCR_OK;

	/*
	if (NULL != cryptodev_e)
	{
		ENGINE_unregister_ciphers(cryptodev_e);
		ENGINE_unregister_digests(cryptodev_e);
		ENGINE_unregister_RSA(cryptodev_e);
		ENGINE_unregister_DSA(cryptodev_e);
		ENGINE_unregister_DH(cryptodev_e);
		ENGINE_unregister_ECDH(cryptodev_e);
		ENGINE_unregister_ECDSA(cryptodev_e);
	}
	*/

    if (NULL != cryptodev_e){
	ENGINE_free(cryptodev_e);
//	ENGINE_finish(cryptodev_e);
	cryptodev_e =NULL;
# ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
# endif
    }
    //ENGINE_set_default(cryptodev_e,ENGINE_METHOD_ALL);
//	RSA_set_default_method(RSA_PKCS1_SSLeay());
//	ECDSA_set_default_method(ECDSA_OpenSSL());
	if(NULL == openssl_default_e){
		OpenSSL_add_all_algorithms();
		/* LOAD CRYPTODEV ENGINE */
		if (NULL == (openssl_default_e = load_openssl_default()))
		{
			printf("DEFAULT ENGINE IS NOT AVAILABLE \n"); 
		}
		ENGINE_register_complete(openssl_default_e);

	}
    return(uni_retst);
}


char *  NELDTV_get_version_cryptodev(void)
{

       return (M_CRYPTODEV_VERSION_STR);

}


T_ndn_Error
ndn_AesAlgorithm_encrypt128Cbc_hardware
  (const uint8_t *key, size_t keyLength, const uint8_t *initialVector,
   size_t initialVectorLength, const uint8_t *plainData,
   int plainDataLength, uint8_t *encryptedData, int *encryptedDataLength)
{
   unsigned int  uni_retst = M_NELDTVCR_OK;
	if ((uni_retst = NELDTV_open_cryptodev()))
		goto err;
//	const EVP_CIPHER *c = EVP_get_cipherbyname("aes_cbc");
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	if(!EVP_EncryptInit_ex(ctx,EVP_aes_128_cbc(),NULL,key,initialVector))
	    {
	    printf("EncryptInit failed\n");
	    goto err;
	    }
	EVP_CIPHER_CTX_set_padding(ctx,0);

	if(!EVP_EncryptUpdate(ctx,encryptedData,encryptedDataLength,plainData,plainDataLength))
	    {
	    printf("Encrypt failed\n");
	    goto err;
	    }
	
	int outl2;
	if(!EVP_EncryptFinal_ex(ctx,encryptedData+*encryptedDataLength,&outl2))
	    {
	    printf("EncryptFinal failed\n");
	    goto err;
	    }
	*encryptedDataLength += outl2;
	EVP_CIPHER_CTX_free(ctx);

err:
	return uni_retst;
}

T_ndn_Error
ndn_AesAlgorithm_encrypt128Cbc_software
  (const uint8_t *key, size_t keyLength, const uint8_t *initialVector,
   size_t initialVectorLength, const uint8_t *plainData,
   int plainDataLength, uint8_t *encryptedData, int *encryptedDataLength)
{
   unsigned int  uni_retst = M_NELDTVCR_OK;
	if ((uni_retst = NELDTV_close_cryptodev()))
		goto err;
//	const EVP_CIPHER *c = EVP_get_cipherbyname("aes_cbc");
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	if(!EVP_EncryptInit_ex(ctx,EVP_aes_128_cbc(),NULL,key,initialVector))
	    {
	    printf("EncryptInit failed\n");
	    goto err;
	    }
	EVP_CIPHER_CTX_set_padding(ctx,0);

	if(!EVP_EncryptUpdate(ctx,encryptedData,encryptedDataLength,plainData,plainDataLength))
	    {
	    printf("Encrypt failed\n");
	    goto err;
	    }
	
	int outl2;
	if(!EVP_EncryptFinal_ex(ctx,encryptedData+*encryptedDataLength,&outl2))
	    {
	    printf("EncryptFinal failed\n");
	    goto err;
	    }
	*encryptedDataLength += outl2;
	EVP_CIPHER_CTX_free(ctx);

err:
	return uni_retst;
}


T_ndn_Error
 ndn_AesAlgorithm_decrypt128Cbc_hardware
 (const uint8_t *key, size_t keyLength, const uint8_t *initialVector,
  size_t initialVectorLength, const uint8_t *encryptedData,
  int encryptedDataLength, uint8_t *plainData, int *plainDataLength)
  {
	  unsigned int  uni_retst = M_NELDTVCR_OK;
 
	if ((uni_retst = NELDTV_open_cryptodev()))
		goto err;
	
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, initialVector))
	    {
	    printf("EncryptInit failed\n");
	    goto err;
	    }
	EVP_CIPHER_CTX_set_padding(ctx,0);

	if(!EVP_DecryptUpdate(ctx,plainData,plainDataLength,encryptedData,encryptedDataLength))
	    {
	    printf("Encrypt failed\n");
	    goto err;
	    }
	
	int outl2;
	if(!EVP_DecryptFinal_ex(ctx,plainData+*plainDataLength,&outl2))
	    {
	    printf("EncryptFinal failed\n");
	    goto err;
	    }
	*plainDataLength += outl2;
	EVP_CIPHER_CTX_free(ctx);
err:
	
	return uni_retst;
 }

T_ndn_Error
 ndn_AesAlgorithm_decrypt128Cbc_software
 (const uint8_t *key, size_t keyLength, const uint8_t *initialVector,
  size_t initialVectorLength, const uint8_t *encryptedData,
  int encryptedDataLength, uint8_t *plainData, int *plainDataLength)
  {
	  unsigned int  uni_retst = M_NELDTVCR_OK;
 
	if ((uni_retst = NELDTV_close_cryptodev()))
		goto err;
	
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, initialVector))
	    {
	    printf("EncryptInit failed\n");
	    goto err;
	    }
	EVP_CIPHER_CTX_set_padding(ctx,0);

	if(!EVP_DecryptUpdate(ctx,plainData,plainDataLength,encryptedData,encryptedDataLength))
	    {
	    printf("Encrypt failed\n");
	    goto err;
	    }
	
	int outl2;
	if(!EVP_DecryptFinal_ex(ctx,plainData+*plainDataLength,&outl2))
	    {
	    printf("EncryptFinal failed\n");
	    goto err;
	    }
	*plainDataLength += outl2;
	EVP_CIPHER_CTX_free(ctx);
err:
	
	return uni_retst;
 }


 T_ndn_Error
 ndn_AesAlgorithm_encrypt128Ecb_hardware
 (const uint8_t *key, size_t keyLength, const uint8_t *plainData,
  int plainDataLength, uint8_t *encryptedData, int *encryptedDataLength)
{
  unsigned int  uni_retst = M_NELDTVCR_OK;
 
	if ((uni_retst = NELDTV_open_cryptodev()))
		goto err;
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	if(!EVP_EncryptInit_ex(ctx,EVP_aes_128_ecb(),NULL,key, NULL))
	    {
	    printf("EncryptInit failed\n");
	    goto err;
	    }
	EVP_CIPHER_CTX_set_padding(ctx,0);

	if(!EVP_EncryptUpdate(ctx,encryptedData,encryptedDataLength,plainData,plainDataLength))
	    {
	    printf("Encrypt failed\n");
	    goto err;
	    }
	
	int outl2;
	if(!EVP_EncryptFinal_ex(ctx,encryptedData+*encryptedDataLength,&outl2))
	    {
	    printf("EncryptFinal failed\n");
	    goto err;
	    }
	*encryptedDataLength += outl2;
	EVP_CIPHER_CTX_free(ctx);
err:
	
	return uni_retst;
 }

 T_ndn_Error
 ndn_AesAlgorithm_encrypt128Ecb_software
 (const uint8_t *key, size_t keyLength, const uint8_t *plainData,
  int plainDataLength, uint8_t *encryptedData, int *encryptedDataLength)
{
  unsigned int  uni_retst = M_NELDTVCR_OK;
 
	if ((uni_retst = NELDTV_close_cryptodev()))
		goto err;
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	if(!EVP_EncryptInit_ex(ctx,EVP_aes_128_ecb(),NULL,key, NULL))
	    {
	    printf("EncryptInit failed\n");
	    goto err;
	    }
	EVP_CIPHER_CTX_set_padding(ctx,0);

	if(!EVP_EncryptUpdate(ctx,encryptedData,encryptedDataLength,plainData,plainDataLength))
	    {
	    printf("Encrypt failed\n");
	    goto err;
	    }
	
	int outl2;
	if(!EVP_EncryptFinal_ex(ctx,encryptedData+*encryptedDataLength,&outl2))
	    {
	    printf("EncryptFinal failed\n");
	    goto err;
	    }
	*encryptedDataLength += outl2;
	EVP_CIPHER_CTX_free(ctx);
err:
	
	return uni_retst;
 }


 T_ndn_Error
 ndn_AesAlgorithm_decrypt128Ecb_hardware
(const uint8_t *key, size_t keyLength, const uint8_t *encryptedData,
 int encryptedDataLength, uint8_t *plainData, int *plainDataLength)
 {
  unsigned int  uni_retst = M_NELDTVCR_OK;
  
	if ((uni_retst = NELDTV_open_cryptodev()))
		goto err;
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
	    {
	    printf("EncryptInit failed\n");
	    goto err;
	    }
	EVP_CIPHER_CTX_set_padding(ctx,0);

	if(!EVP_DecryptUpdate(ctx,plainData,plainDataLength,encryptedData,encryptedDataLength))
	    {
	    printf("Encrypt failed\n");
	    goto err;
	    }
	
	int outl2;
	if(!EVP_DecryptFinal_ex(ctx,plainData+*plainDataLength,&outl2))
	    {
	    printf("EncryptFinal failed\n");
	    goto err;
	    }
	*plainDataLength += outl2;
	EVP_CIPHER_CTX_free(ctx);
err:
	
	return uni_retst;
}

 T_ndn_Error
 ndn_AesAlgorithm_decrypt128Ecb_software
(const uint8_t *key, size_t keyLength, const uint8_t *encryptedData,
 int encryptedDataLength, uint8_t *plainData, int *plainDataLength)
 {
  unsigned int  uni_retst = M_NELDTVCR_OK;
  
	if ((uni_retst = NELDTV_close_cryptodev()))
		goto err;
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
	    {
	    printf("EncryptInit failed\n");
	    goto err;
	    }
	EVP_CIPHER_CTX_set_padding(ctx,0);

	if(!EVP_DecryptUpdate(ctx,plainData,plainDataLength,encryptedData,encryptedDataLength))
	    {
	    printf("Encrypt failed\n");
	    goto err;
	    }
	
	int outl2;
	if(!EVP_DecryptFinal_ex(ctx,plainData+*plainDataLength,&outl2))
	    {
	    printf("EncryptFinal failed\n");
	    goto err;
	    }
	*plainDataLength += outl2;
	EVP_CIPHER_CTX_free(ctx);
err:
	
	return uni_retst;
}

T_ndn_Error
ndn_AesAlgorithm_encrypt256Cbc_hardware
  (const uint8_t *key, size_t keyLength, const uint8_t *initialVector,
   size_t initialVectorLength, const uint8_t *plainData,
   int plainDataLength, uint8_t *encryptedData, int *encryptedDataLength)
{
   unsigned int  uni_retst = M_NELDTVCR_OK;
	if ((uni_retst = NELDTV_open_cryptodev()))
		goto err;
//	const EVP_CIPHER *c = EVP_get_cipherbyname("aes_cbc");
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	if(!EVP_EncryptInit_ex(ctx,EVP_aes_256_cbc(),NULL,key,initialVector))
	    {
	    printf("EncryptInit failed\n");
	    goto err;
	    }
	EVP_CIPHER_CTX_set_padding(ctx,0);

	if(!EVP_EncryptUpdate(ctx,encryptedData,encryptedDataLength,plainData,plainDataLength))
	    {
	    printf("Encrypt failed\n");
	    goto err;
	    }
	
	int outl2;
	if(!EVP_EncryptFinal_ex(ctx,encryptedData+*encryptedDataLength,&outl2))
	    {
	    printf("EncryptFinal failed\n");
	    goto err;
	    }
	*encryptedDataLength += outl2;
	EVP_CIPHER_CTX_free(ctx);

err:
	return uni_retst;
}



T_ndn_Error
 ndn_AesAlgorithm_decrypt256Cbc_hardware
 (const uint8_t *key, size_t keyLength, const uint8_t *initialVector,
  size_t initialVectorLength, const uint8_t *encryptedData,
  int encryptedDataLength, uint8_t *plainData, int *plainDataLength)
  {
	  unsigned int  uni_retst = M_NELDTVCR_OK;
 
	if ((uni_retst = NELDTV_open_cryptodev()))
		goto err;
	
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, initialVector))
	    {
	    printf("EncryptInit failed\n");
	    goto err;
	    }
	EVP_CIPHER_CTX_set_padding(ctx,0);

	if(!EVP_DecryptUpdate(ctx,plainData,plainDataLength,encryptedData,encryptedDataLength))
	    {
	    printf("Encrypt failed\n");
	    goto err;
	    }
	
	int outl2;
	if(!EVP_DecryptFinal_ex(ctx,plainData+*plainDataLength,&outl2))
	    {
	    printf("EncryptFinal failed\n");
	    goto err;
	    }
	*plainDataLength += outl2;
	EVP_CIPHER_CTX_free(ctx);
err:
	
	return uni_retst;
 }



 T_ndn_Error
 ndn_AesAlgorithm_encrypt256Ecb_hardware
 (const uint8_t *key, size_t keyLength, const uint8_t *plainData,
  int plainDataLength, uint8_t *encryptedData, int *encryptedDataLength)
{
  unsigned int  uni_retst = M_NELDTVCR_OK;
 
	if ((uni_retst = NELDTV_open_cryptodev()))
		goto err;
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	if(!EVP_EncryptInit_ex(ctx,EVP_aes_256_ecb(),NULL,key, NULL))
	    {
	    printf("EncryptInit failed\n");
	    goto err;
	    }
	EVP_CIPHER_CTX_set_padding(ctx,0);

	if(!EVP_EncryptUpdate(ctx,encryptedData,encryptedDataLength,plainData,plainDataLength))
	    {
	    printf("Encrypt failed\n");
	    goto err;
	    }
	
	int outl2;
	if(!EVP_EncryptFinal_ex(ctx,encryptedData+*encryptedDataLength,&outl2))
	    {
	    printf("EncryptFinal failed\n");
	    goto err;
	    }
	*encryptedDataLength += outl2;
	EVP_CIPHER_CTX_free(ctx);
err:
	
	return uni_retst;
 }

 T_ndn_Error
 ndn_AesAlgorithm_decrypt256Ecb_hardware
(const uint8_t *key, size_t keyLength, const uint8_t *encryptedData,
 int encryptedDataLength, uint8_t *plainData, int *plainDataLength)
 {
  unsigned int  uni_retst = M_NELDTVCR_OK;
  
	if ((uni_retst = NELDTV_open_cryptodev()))
		goto err;
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL))
	    {
	    printf("EncryptInit failed\n");
	    goto err;
	    }
	EVP_CIPHER_CTX_set_padding(ctx,0);

	if(!EVP_DecryptUpdate(ctx,plainData,plainDataLength,encryptedData,encryptedDataLength))
	    {
	    printf("Encrypt failed\n");
	    goto err;
	    }
	
	int outl2;
	if(!EVP_DecryptFinal_ex(ctx,plainData+*plainDataLength,&outl2))
	    {
	    printf("EncryptFinal failed\n");
	    goto err;
	    }
	*plainDataLength += outl2;
	EVP_CIPHER_CTX_free(ctx);
err:
	
	return uni_retst;
}


T_ndn_Error
ndn_digestSha256_hardware(const uint8_t *data, size_t dataLength, uint8_t *digest)
{
   unsigned int  uni_retst = M_NELDTVCR_OK;
 
	if ((uni_retst = NELDTV_open_cryptodev()))
		goto err;
/*
	EVP_MD_CTX ctx;
	EVP_MD_CTX_init(&ctx);
	EVP_DigestInit_ex(&ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(&ctx, data, dataLength);
	EVP_DigestFinal_ex(&ctx, digest, NULL);
*/
	if (data == NULL)
		sw_sha256(data, dataLength, digest);
	else
		EVP_Digest(data, dataLength, digest, NULL, EVP_sha256(), NULL);

err:
//	EVP_MD_CTX_cleanup(&ctx);
	return uni_retst;
}

T_ndn_Error
ndn_digestSha256_software(const uint8_t *data, size_t dataLength, uint8_t *digest)
{
   unsigned int  uni_retst = M_NELDTVCR_OK;
 
/*
	EVP_MD_CTX ctx;
	EVP_MD_CTX_init(&ctx);
	EVP_DigestInit_ex(&ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(&ctx, data, dataLength);
	EVP_DigestFinal_ex(&ctx, digest, NULL);
*/	
	EVP_Digest(data, dataLength, digest, NULL, EVP_sha256(), NULL);

err:
//	EVP_MD_CTX_cleanup(&ctx);
	
	return uni_retst;


}

T_ndn_Error
ndn_digestSha1_hardware(const uint8_t *data, size_t dataLength, uint8_t *digest)
{
   unsigned int  uni_retst = M_NELDTVCR_OK;
 
	if ((uni_retst = NELDTV_open_cryptodev()))
		goto err;
/*
	EVP_MD_CTX ctx;
	EVP_MD_CTX_init(&ctx);
	EVP_DigestInit_ex(&ctx, EVP_sha1(), NULL);
	EVP_DigestUpdate(&ctx, data, dataLength);
	EVP_DigestFinal_ex(&ctx, digest, NULL);
*/	
	if (data == NULL)
		CL_hash(data, dataLength, digest);
	else
	EVP_Digest(data, dataLength, digest, NULL, EVP_sha1(), NULL);

err:
//	EVP_MD_CTX_cleanup(&ctx);
	
	return uni_retst;


}

// return output length
int RSA_public_encrypt_software	( 	int  	flen,
		const unsigned char *  	from,
		unsigned char *  	to,
		RSA *  	rsa,
		int  	padding 
	)
{
	unsigned int  uni_retst = M_NELDTVCR_OK;
	if ((uni_retst = NELDTV_close_cryptodev()))
		goto err;
	uni_retst = RSA_public_encrypt(flen, from, to, rsa, padding);
	if (uni_retst<0)
		{
		printf("RSA public encryption failed!\n");
		goto err;
		}

err:
	return uni_retst;

}


// return output length
int RSA_public_encrypt_hardware 	( 	int  	flen,
		const unsigned char *  	from,
		unsigned char *  	to,
		RSA *  	rsa,
		int  	padding 
	)
{
	unsigned int  uni_retst = M_NELDTVCR_OK;
	if ((uni_retst = NELDTV_open_cryptodev()))
		goto err;
	uni_retst = RSA_public_encrypt(flen, from, to, rsa, padding);
	if (uni_retst<0)
		{
		printf("RSA public encryption failed!\n");
		goto err;
		}

err:
	return uni_retst;

}



int RSA_verify_hardware 	( 	int  	type,
		const unsigned char *  	m,
		unsigned int  	m_length,
		const unsigned char *  	sigbuf,
		unsigned int  	siglen,
		RSA *  	rsa 
	)
{
		unsigned int  uni_retst = M_NELDTVCR_OK;
		if ((uni_retst = NELDTV_open_cryptodev()))
			goto err;
		if ((uni_retst=RSA_verify(type, m, m_length, sigbuf, siglen, rsa))!=1)
			{
			printf("RSA verify failed!\n");
			goto err;
			}
		
err:
		
		return uni_retst;

}		

int RSA_verify_software( 	int  	type,
		const unsigned char *  	m,
		unsigned int  	m_length,
		const unsigned char *  	sigbuf,
		unsigned int  	siglen,
		RSA *  	rsa 
	)
{
		unsigned int  uni_retst = M_NELDTVCR_OK;
		if ((uni_retst = NELDTV_close_cryptodev()))
			goto err;
		if ((uni_retst=RSA_verify(type, m, m_length, sigbuf, siglen, rsa))!=1)
			{
			printf("RSA verify failed!\n");
			goto err;
			}
		
err:
		
		return uni_retst;

}	


int RSA_sign_hardware 	( 	int  	type,
		const unsigned char *  	m,
		unsigned int  	m_length,
		unsigned char *  	sigret,
		unsigned int *  	siglen,
		RSA *  	rsa 
	)
{
		unsigned int  uni_retst = M_NELDTVCR_OK;
		if ((uni_retst = NELDTV_open_cryptodev()))
			goto err;
		if ((uni_retst=RSA_sign(type, m, m_length, sigret, siglen, rsa))!=1)
			{
			printf("RSA sign failed!\n");
			goto err;
			}
				
err:
				
		return uni_retst;
		
}		

int RSA_sign_software	( 	int  	type,
		const unsigned char *  	m,
		unsigned int  	m_length,
		unsigned char *  	sigret,
		unsigned int *  	siglen,
		RSA *  	rsa 
	)
{
		unsigned int  uni_retst = M_NELDTVCR_OK;
		if ((uni_retst = NELDTV_close_cryptodev()))
			goto err;
		if ((uni_retst=RSA_sign(type, m, m_length, sigret, siglen, rsa))!=1)
			{
			printf("RSA sign failed!\n");
			goto err;
			}
				
err:
				
		return uni_retst;
		
}	
// return output length
int RSA_private_decrypt_software 	( 	int  	flen,
		const unsigned char *  	from,
		unsigned char *  	to,
		RSA *  	rsa,
		int  	padding 
	)
{
		unsigned int  uni_retst = M_NELDTVCR_OK;
		if ((uni_retst = NELDTV_close_cryptodev()))
			goto err;
		uni_retst=RSA_private_decrypt(flen, from, to, rsa, padding);
		
		if (uni_retst<0)
			{
			printf("RSA private decryption failed!\n");
			goto err;
			}
err:
	
	return uni_retst;
}


// return output length
int RSA_private_decrypt_hardware 	( 	int  	flen,
		const unsigned char *  	from,
		unsigned char *  	to,
		RSA *  	rsa,
		int  	padding 
	)
{
		unsigned int  uni_retst = M_NELDTVCR_OK;
		if ((uni_retst = NELDTV_open_cryptodev()))
			goto err;
		uni_retst=RSA_private_decrypt(flen, from, to, rsa, padding);
		
		if (uni_retst<0)
			{
			printf("RSA private decryption failed!\n");
			goto err;
			}
err:
	
	return uni_retst;
}



int ECDSA_verify_hardware 	( 	int  	type,
		const unsigned char *  	dgst,
		int  	dgstlen,
		const unsigned char *  	sig,
		int  	siglen,
		EC_KEY *  	eckey 
	)
{
		unsigned int  uni_retst = M_NELDTVCR_OK;
		if ((uni_retst = NELDTV_open_cryptodev()))
			{
			uni_retst = -1;
			goto err;
			}
		if ((uni_retst=ECDSA_verify(type, dgst, dgstlen, sig, siglen, eckey))!=1)
			{
			printf("ECDSA verify failed!\n");
			goto err;
			}
		else
			uni_retst = 1;
				
err:
				
		return uni_retst;
			
}		




int ECDSA_sign_hardware 	( 	int  	type,
		const unsigned char *  	dgst,
		int  	dgstlen,
		unsigned char *  	sig,
		unsigned int *  	siglen,
		EC_KEY *  	eckey 
	) 

{
		unsigned int  uni_retst = M_NELDTVCR_OK;
		if ((uni_retst = NELDTV_open_cryptodev()))
			goto err;
		if ((uni_retst=ECDSA_sign(type, dgst, dgstlen, sig, siglen, eckey))!=1)
			{
			printf("ECDSA sign failed!\n");
			goto err;
			}
				
err:
				
		return uni_retst;
			
}		







