/* apps/speed.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The ECDH and ECDSA speed test software is originally written by
 * Sumit Gupta of Sun Microsystems Laboratories.
 *
 */

/* most of this code has been pilfered from my libdes speed.c program */

#ifndef OPENSSL_NO_SPEED

# undef SECONDS
# define SECONDS         3
# define RSA_SECONDS     10
# define DSA_SECONDS     10
# define ECDSA_SECONDS   10
# define ECDH_SECONDS    10

/* 11-Sep-92 Andrew Daviel   Support for Silicon Graphics IRIX added */
/* 06-Apr-92 Luke Brennan    Support for VMS and add extra signal calls */

# undef PROG
# define PROG speed_main

# include <stdio.h>
# include <stdlib.h>

# include <string.h>
# include <math.h>
# include "apps.h"
# ifdef OPENSSL_NO_STDIO
#  define APPS_WIN16
# endif
# include <openssl/crypto.h>
# include <openssl/rand.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <openssl/objects.h>
# if !defined(OPENSSL_SYS_MSDOS)
#  include OPENSSL_UNISTD
# endif

# ifndef OPENSSL_SYS_NETWARE
#  include <signal.h>
# endif
#   define COND(d) (count < 10000)
#   define COUNT(d) (d)

# if defined(_WIN32) || defined(__CYGWIN__)
#  include <windows.h>
#  if defined(__CYGWIN__) && !defined(_WIN32)
  /*
   * <windows.h> should define _WIN32, which normally is mutually exclusive
   * with __CYGWIN__, but if it didn't...
   */
#   define _WIN32
  /* this is done because Cygwin alarm() fails sometimes. */
#  endif
# endif

# include <openssl/bn.h>
# ifndef OPENSSL_NO_DES
#  include <openssl/des.h>
# endif
# ifndef OPENSSL_NO_AES
#  include <openssl/aes.h>
# endif
# ifndef OPENSSL_NO_CAMELLIA
#  include <openssl/camellia.h>
# endif
# ifndef OPENSSL_NO_MD2
#  include <openssl/md2.h>
# endif
# ifndef OPENSSL_NO_MDC2
#  include <openssl/mdc2.h>
# endif
# ifndef OPENSSL_NO_MD4
#  include <openssl/md4.h>
# endif
# ifndef OPENSSL_NO_MD5
#  include <openssl/md5.h>
# endif
# ifndef OPENSSL_NO_HMAC
#  include <openssl/hmac.h>
# endif
# include <openssl/evp.h>
# ifndef OPENSSL_NO_SHA
#  include <openssl/sha.h>
# endif
# ifndef OPENSSL_NO_RIPEMD
#  include <openssl/ripemd.h>
# endif
# ifndef OPENSSL_NO_WHIRLPOOL
#  include <openssl/whrlpool.h>
# endif
# ifndef OPENSSL_NO_RC4
#  include <openssl/rc4.h>
# endif
# ifndef OPENSSL_NO_RC5
#  include <openssl/rc5.h>
# endif
# ifndef OPENSSL_NO_RC2
#  include <openssl/rc2.h>
# endif
# ifndef OPENSSL_NO_IDEA
#  include <openssl/idea.h>
# endif
# ifndef OPENSSL_NO_SEED
#  include <openssl/seed.h>
# endif
# ifndef OPENSSL_NO_BF
#  include <openssl/blowfish.h>
# endif
# ifndef OPENSSL_NO_CAST
#  include <openssl/cast.h>
# endif
# ifndef OPENSSL_NO_RSA
#  include <openssl/rsa.h>
#  include "./testrsa.h"
# endif
# include <openssl/x509.h>
# ifndef OPENSSL_NO_DSA
#  include <openssl/dsa.h>
#  include "./testdsa.h"
# endif
# ifndef OPENSSL_NO_ECDSA
#  include <openssl/ecdsa.h>
# endif
# ifndef OPENSSL_NO_ECDH
#  include <openssl/ecdh.h>
# endif
# include <openssl/modes.h>

# ifdef OPENSSL_FIPS
#  ifdef OPENSSL_DOING_MAKEDEPEND
#   undef AES_set_encrypt_key
#   undef AES_set_decrypt_key
#   undef DES_set_key_unchecked
#  endif
#  define BF_set_key      private_BF_set_key
#  define CAST_set_key    private_CAST_set_key
#  define idea_set_encrypt_key    private_idea_set_encrypt_key
#  define SEED_set_key    private_SEED_set_key
#  define RC2_set_key     private_RC2_set_key
#  define RC4_set_key     private_RC4_set_key
#  define DES_set_key_unchecked   private_DES_set_key_unchecked
#  define AES_set_encrypt_key     private_AES_set_encrypt_key
#  define AES_set_decrypt_key     private_AES_set_decrypt_key
#  define Camellia_set_key        private_Camellia_set_key
# endif

# ifndef HAVE_FORK
#  if defined(OPENSSL_SYS_VMS) || defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MACINTOSH_CLASSIC) || defined(OPENSSL_SYS_OS2) || defined(OPENSSL_SYS_NETWARE)
#   define HAVE_FORK 0
#  else
#   define HAVE_FORK 1
#  endif
# endif

# if HAVE_FORK
#  undef NO_FORK
# else
#  define NO_FORK
# endif

# undef BUFSIZE
/* The buffer overhead allows GCM tag at the end of the encrypted data. This
   avoids buffer overflows from cryptodev since Linux kernel GCM
   implementation allways adds the tag - unlike e_aes.c:aes_gcm_cipher()
   which doesn't */
#define BUFSIZE	((long)1024*8 + EVP_GCM_TLS_TAG_LEN)
static volatile int run = 0;

static int mr = 0;
static int usertime = 1;

static double Time_F(int s);
static void print_message(const char *s, long num, int length);
static void pkey_print_message(const char *str, const char *str2,
                               long num, int bits, int sec);
static void print_result(int alg, int run_no, int count, double time_used);
# ifndef NO_FORK
static int do_multi(int multi);
# endif

# define ALGOR_NUM       30
# define SIZE_NUM        5
# define RSA_NUM         4
# define DSA_NUM         3

# define EC_NUM       16
# define MAX_ECDH_SIZE 256

static const char *names[ALGOR_NUM] = {
    "md2", "mdc2", "md4", "md5", "hmac(md5)", "sha1", "rmd160", "rc4",
    "des cbc", "des ede3", "idea cbc", "seed cbc",
    "rc2 cbc", "rc5-32/12 cbc", "blowfish cbc", "cast cbc",
    "aes-128 cbc", "aes-192 cbc", "aes-256 cbc",
    "camellia-128 cbc", "camellia-192 cbc", "camellia-256 cbc",
    "evp", "sha256", "sha512", "whirlpool",
    "aes-128 ige", "aes-192 ige", "aes-256 ige", "ghash"
};

static double results[ALGOR_NUM][SIZE_NUM];
static int lengths[SIZE_NUM] = { 16, 64, 256, 1024, 8 * 1024 };

# ifndef OPENSSL_NO_RSA
static double rsa_results[RSA_NUM][2];
# endif
# ifndef OPENSSL_NO_DSA
static double dsa_results[DSA_NUM][2];
# endif
# ifndef OPENSSL_NO_ECDSA
static double ecdsa_results[EC_NUM][2];
# endif
# ifndef OPENSSL_NO_ECDH
static double ecdh_results[EC_NUM][1];
# endif

# if defined(OPENSSL_NO_DSA) && !(defined(OPENSSL_NO_ECDSA) && defined(OPENSSL_NO_ECDH))
static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";
static int rnd_fake = 0;
# endif

# ifdef SIGALRM
#  if defined(__STDC__) || defined(sgi) || defined(_AIX)
#   define SIGRETTYPE void
#  else
#   define SIGRETTYPE int
#  endif

static SIGRETTYPE sig_done(int sig);
static SIGRETTYPE sig_done(int sig)
{
    signal(SIGALRM, sig_done);
    run = 0;
#  ifdef LINT
    sig = sig;
#  endif
}
# endif

# define START   0
# define STOP    1



static double Time_F(int s)
{
    return app_tminterval(s, usertime);
}

static double Time_F2(int s)
{
	double ret = 0;
	static long tmstart;
	struct timeval t_start;
	long cost_time = 0;
	//get start time
	gettimeofday(&t_start, NULL);
	long start = (((long)t_start.tv_sec)*1000+(long)t_start.tv_usec/1000)/1000;
	if (s == START)
		 tmstart = start;
	 else {
		 ret = (start - tmstart);
		  printf("Time_F2:%.2f\n",ret);
	 }
	
	return ret;
}



//# endif

# ifndef OPENSSL_NO_ECDH
static const int KDF1_SHA1_len = 20;
static void *KDF1_SHA1(const void *in, size_t inlen, void *out,
                       size_t *outlen)
{
#  ifndef OPENSSL_NO_SHA
    if (*outlen < SHA_DIGEST_LENGTH)
        return NULL;
    else
        *outlen = SHA_DIGEST_LENGTH;
    return SHA1(in, inlen, out);
#  else
    return NULL;
#  endif                        /* OPENSSL_NO_SHA */
}
# endif                         /* OPENSSL_NO_ECDH */

static void multiblock_speed(const EVP_CIPHER *evp_cipher);



static int test_ecdsa_speed(int times, int pthreadnum, boolean opendev)
{
	int ret = 0;
	const char message[] = "Hello World!";
	const char message2[] = "hello";
	unsigned char digest[32];
	unsigned char digest2[32];
	unsigned char sig[100];
	unsigned char sig2[100];
	unsigned int siglen;
	unsigned int siglen2;
	NELDTV_open_cryptodev();
	BIO * bio_err = BIO_new(BIO_s_file());
//	ndn_digestSha256_hardware(message, 12, digest);
	
//	ndn_digestSha256_hardware(message2, 5, digest2);
	size_t count;
	int i;
	count = 12;

	EVP_Digest(message, count, digest, NULL, EVP_sha256(), NULL);
	count = 5;
	EVP_Digest(message2, count, digest2, NULL, EVP_sha256(), NULL);


	printf("\n##########ECDSA TEST START###########\n");
	EC_KEY * ec_key_tmp = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	EC_KEY * ec_key_tmp2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (ec_key_tmp == NULL)
		{
		printf("\nEC key generate failed!\n");
		goto err;
		}
	if (ec_key_tmp2 == NULL)
		{
		printf("\nEC key generate failed!\n");
		goto err;
		}
	EC_KEY_generate_key(ec_key_tmp);
	EC_KEY_generate_key(ec_key_tmp2);
	
	

//	ECDSA_sign(0, digest, 32, sig, &siglen, ec_key_tmp);
//	ECDSA_sign(0, digest2, 32, sig2, &siglen2, ec_key_tmp2);
	Time_F2(START);
	for (i=0;i<times;i++){
		ECDSA_sign(0, digest, 32, sig, &siglen, ec_key_tmp);
	}
	double time_used = Time_F2(STOP);
	printf( " ECDSA_sign_hardware time_used:%.6f/s\n", times/time_used);
	printf("\nECDSA sign hardware succeed!\n");
	
	//NELDTV_close_cryptodev();//must close cryptodev before you call software method.
	Time_F2(START);
	for (i=0;i<times;i++){
		ECDSA_verify(0, digest, 32, sig, siglen, ec_key_tmp);
	}
	time_used = Time_F2(STOP);
	printf( " software verify time_used:%.6f/s\n",times/ time_used);
	printf("\nECDSA in software verify succeed!\n");

//	ECDSA_sign_hardware(0, digest, 32, sig, &siglen, ec_key_tmp);
	//NELDTV_close_cryptodev();//must close cryptodev before you call software method.
	Time_F2(START);
	for (i=0;i<times;i++){
		ECDSA_sign(0, digest, 32, sig, &siglen, ec_key_tmp);
	}
	time_used = Time_F2(STOP);;
	printf( "  sign software time_used:%.6f/s\n",times/ time_used);
	printf("\nECDSA sign software succeed!\n");
	
	Time_F2(START);
	for (i=0;i<times;i++){
		ECDSA_verify(0, digest, 32, sig, siglen, ec_key_tmp) ;
	}
	time_used = Time_F2(STOP);;
	ret = 1;
	printf( " hardware verify  time_used:%.6f/s\n", times/time_used);
	printf("\nECDSA in hardware verify succeed!\n");

	printf("\n##########ECDSA TEST END###########\n");
	EC_KEY_free(ec_key_tmp);
	EC_KEY_free(ec_key_tmp2);

err:
	return ret;
}
int main(int, char **);

int main(int argc, char **argv)
{
    unsigned char *buf = NULL, *buf2 = NULL;
    int mret = 1;
    long count = 0, save_count = 0;
    int i, j, k;
# if !defined(OPENSSL_NO_RSA) || !defined(OPENSSL_NO_DSA)
    long rsa_count;
# endif
# ifndef OPENSSL_NO_RSA
    unsigned rsa_num;
# endif
    unsigned char md[EVP_MAX_MD_SIZE];
# ifndef OPENSSL_NO_MD2
    unsigned char md2[MD2_DIGEST_LENGTH];
# endif
# ifndef OPENSSL_NO_MDC2
    unsigned char mdc2[MDC2_DIGEST_LENGTH];
# endif
# ifndef OPENSSL_NO_MD4
    unsigned char md4[MD4_DIGEST_LENGTH];
# endif
# ifndef OPENSSL_NO_MD5
    unsigned char md5[MD5_DIGEST_LENGTH];
    unsigned char hmac[MD5_DIGEST_LENGTH];
# endif
# ifndef OPENSSL_NO_SHA
    unsigned char sha[SHA_DIGEST_LENGTH];
#  ifndef OPENSSL_NO_SHA256
    unsigned char sha256[SHA256_DIGEST_LENGTH];
#  endif
#  ifndef OPENSSL_NO_SHA512
    unsigned char sha512[SHA512_DIGEST_LENGTH];
#  endif
# endif
# ifndef OPENSSL_NO_WHIRLPOOL
    unsigned char whirlpool[WHIRLPOOL_DIGEST_LENGTH];
# endif
# ifndef OPENSSL_NO_RIPEMD
    unsigned char rmd160[RIPEMD160_DIGEST_LENGTH];
# endif
# ifndef OPENSSL_NO_RC4
    RC4_KEY rc4_ks;
# endif
# ifndef OPENSSL_NO_RC5
    RC5_32_KEY rc5_ks;
# endif
# ifndef OPENSSL_NO_RC2
    RC2_KEY rc2_ks;
# endif
# ifndef OPENSSL_NO_IDEA
    IDEA_KEY_SCHEDULE idea_ks;
# endif
# ifndef OPENSSL_NO_SEED
    SEED_KEY_SCHEDULE seed_ks;
# endif
# ifndef OPENSSL_NO_BF
    BF_KEY bf_ks;
# endif
# ifndef OPENSSL_NO_CAST
    CAST_KEY cast_ks;
# endif
    static const unsigned char key16[16] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12
    };
    double d = 0.0;
    long c[ALGOR_NUM][SIZE_NUM];

# define R_EC_P160    0
# define R_EC_P192    1
# define R_EC_P224    2
# define R_EC_P256    3
# define R_EC_P384    4
# define R_EC_P521    5
# define R_EC_K163    6
# define R_EC_K233    7
# define R_EC_K283    8
# define R_EC_K409    9
# define R_EC_K571    10
# define R_EC_B163    11
# define R_EC_B233    12
# define R_EC_B283    13
# define R_EC_B409    14
# define R_EC_B571    15

# ifndef OPENSSL_NO_EC
    /*
     * We only test over the following curves as they are representative, To
     * add tests over more curves, simply add the curve NID and curve name to
     * the following arrays and increase the EC_NUM value accordingly.
     */
    static unsigned int test_curves[EC_NUM] = {
        /* Prime Curves */
        NID_secp160r1,
        NID_X9_62_prime192v1,
        NID_secp224r1,
        NID_X9_62_prime256v1,
        NID_secp384r1,
        NID_secp521r1,
        /* Binary Curves */
        NID_sect163k1,
        NID_sect233k1,
        NID_sect283k1,
        NID_sect409k1,
        NID_sect571k1,
        NID_sect163r2,
        NID_sect233r1,
        NID_sect283r1,
        NID_sect409r1,
        NID_sect571r1
    };
    static const char *test_curves_names[EC_NUM] = {
        /* Prime Curves */
        "secp160r1",
        "nistp192",
        "nistp224",
        "nistp256",
        "nistp384",
        "nistp521",
        /* Binary Curves */
        "nistk163",
        "nistk233",
        "nistk283",
        "nistk409",
        "nistk571",
        "nistb163",
        "nistb233",
        "nistb283",
        "nistb409",
        "nistb571"
    };
    static int test_curves_bits[EC_NUM] = {
        160, 192, 224, 256, 384, 521,
        163, 233, 283, 409, 571,
        163, 233, 283, 409, 571
    };

# endif

# ifndef OPENSSL_NO_ECDSA
    unsigned char ecdsasig[256];
    unsigned int ecdsasiglen;
    EC_KEY *ecdsa[EC_NUM];
    long ecdsa_c[EC_NUM][2];
# endif


    int rsa_doit[RSA_NUM];
    int dsa_doit[DSA_NUM];
# ifndef OPENSSL_NO_ECDSA
    int ecdsa_doit[EC_NUM];
# endif
    int doit[ALGOR_NUM];
    int pr_header = 0;
    const EVP_CIPHER *evp_cipher = NULL;
    const EVP_MD *evp_md = NULL;
    int decrypt = 0;
    int multiblock = 0;

# ifndef TIMES
    usertime = -1;
# endif

    apps_startup();
    memset(results, 0, sizeof(results));
# ifndef OPENSSL_NO_ECDSA
    for (i = 0; i < EC_NUM; i++)
        ecdsa[i] = NULL;
# endif

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;


    if ((buf = (unsigned char *)OPENSSL_malloc((int)BUFSIZE)) == NULL) {
        BIO_printf(bio_err, "out of memory\n");
        goto end;
    }
    if ((buf2 = (unsigned char *)OPENSSL_malloc((int)BUFSIZE)) == NULL) {
        BIO_printf(bio_err, "out of memory\n");
        goto end;
    }

    memset(c, 0, sizeof(c));

    for (i = 0; i < ALGOR_NUM; i++)
        doit[i] = 0;
    for (i = 0; i < RSA_NUM; i++)
        rsa_doit[i] = 0;
    for (i = 0; i < DSA_NUM; i++)
        dsa_doit[i] = 0;
# ifndef OPENSSL_NO_ECDSA
    for (i = 0; i < EC_NUM; i++)
        ecdsa_doit[i] = 0;
# endif

    j = 0;
    argc--;
    argv++;
    while (argc) {
        if ((argc > 0) && (strcmp(*argv, "-elapsed") == 0)) {
            usertime = 0;
            j--;                /* Otherwise, -elapsed gets confused with an
                                 * algorithm. */
        } else if (argc > 0 && !strcmp(*argv, "-mb")) {
            multiblock = 1;
            j--;
        } else
# ifndef OPENSSL_NO_ECDSA
        if (strcmp(*argv, "ecdsap160") == 0)
            ecdsa_doit[R_EC_P160] = 2;
        else if (strcmp(*argv, "ecdsap192") == 0)
            ecdsa_doit[R_EC_P192] = 2;
        else if (strcmp(*argv, "ecdsap224") == 0)
            ecdsa_doit[R_EC_P224] = 2;
        else if (strcmp(*argv, "ecdsap256") == 0)
            ecdsa_doit[R_EC_P256] = 2;
        else if (strcmp(*argv, "ecdsap384") == 0)
            ecdsa_doit[R_EC_P384] = 2;
        else if (strcmp(*argv, "ecdsap521") == 0)
            ecdsa_doit[R_EC_P521] = 2;
        else if (strcmp(*argv, "ecdsak163") == 0)
            ecdsa_doit[R_EC_K163] = 2;
        else if (strcmp(*argv, "ecdsak233") == 0)
            ecdsa_doit[R_EC_K233] = 2;
        else if (strcmp(*argv, "ecdsak283") == 0)
            ecdsa_doit[R_EC_K283] = 2;
        else if (strcmp(*argv, "ecdsak409") == 0)
            ecdsa_doit[R_EC_K409] = 2;
        else if (strcmp(*argv, "ecdsak571") == 0)
            ecdsa_doit[R_EC_K571] = 2;
        else if (strcmp(*argv, "ecdsab163") == 0)
            ecdsa_doit[R_EC_B163] = 2;
        else if (strcmp(*argv, "ecdsab233") == 0)
            ecdsa_doit[R_EC_B233] = 2;
        else if (strcmp(*argv, "ecdsab283") == 0)
            ecdsa_doit[R_EC_B283] = 2;
        else if (strcmp(*argv, "ecdsab409") == 0)
            ecdsa_doit[R_EC_B409] = 2;
        else if (strcmp(*argv, "ecdsab571") == 0)
            ecdsa_doit[R_EC_B571] = 2;
        else if (strcmp(*argv, "ecdsa") == 0) {
            for (i = 0; i < EC_NUM; i++)
                ecdsa_doit[i] = 1;
        } else
# endif
        {
            BIO_printf(bio_err, "Error: bad option or value\n");
            BIO_printf(bio_err, "\n");
            BIO_printf(bio_err, "Available values:\n");

            BIO_printf(bio_err, "\n");


# ifndef OPENSSL_NO_ECDSA
            BIO_printf(bio_err, "ecdsap160 ecdsap192 ecdsap224 "
                       "ecdsap256 ecdsap384 ecdsap521\n");
            BIO_printf(bio_err,
                       "ecdsak163 ecdsak233 ecdsak283 ecdsak409 ecdsak571\n");
            BIO_printf(bio_err,
                       "ecdsab163 ecdsab233 ecdsab283 ecdsab409 ecdsab571\n");
            BIO_printf(bio_err, "ecdsa\n");
# endif


            BIO_printf(bio_err, "\n");
            BIO_printf(bio_err, "Available options:\n");
            BIO_printf(bio_err, "-evp e          " "use EVP e.\n");
            BIO_printf(bio_err,
                       "-decrypt        "
                       "time decryption instead of encryption (only EVP).\n");
            BIO_printf(bio_err,
                       "-mr             "
                       "produce machine readable output.\n");
# ifndef NO_FORK
            BIO_printf(bio_err,
                       "-multi n        " "run n benchmarks in parallel.\n");
# endif
            goto end;
        }
        argc--;
        argv++;
        j++;
    }

    if (j == 0) {
# ifndef OPENSSL_NO_ECDSA
        for (i = 0; i < EC_NUM; i++)
            ecdsa_doit[i] = 1;
# endif
    }
    for (i = 0; i < ALGOR_NUM; i++)
        if (doit[i])
            pr_header++;

    if (usertime == 0 && !mr)
        BIO_printf(bio_err,
                   "You have chosen to measure elapsed time "
                   "instead of user CPU time.\n");


#   ifndef OPENSSL_NO_ECDSA
    ecdsa_c[R_EC_P160][0] = count / 1000;
    ecdsa_c[R_EC_P160][1] = count / 1000 / 2;
    for (i = R_EC_P192; i <= R_EC_P521; i++) {
        ecdsa_c[i][0] = ecdsa_c[i - 1][0] / 2;
        ecdsa_c[i][1] = ecdsa_c[i - 1][1] / 2;
        if ((ecdsa_doit[i] <= 1) && (ecdsa_c[i][0] == 0))
            ecdsa_doit[i] = 0;
        else {
            if (ecdsa_c[i] == 0) {
                ecdsa_c[i][0] = 1;
                ecdsa_c[i][1] = 1;
            }
        }
    }
    ecdsa_c[R_EC_K163][0] = count / 1000;
    ecdsa_c[R_EC_K163][1] = count / 1000 / 2;
    for (i = R_EC_K233; i <= R_EC_K571; i++) {
        ecdsa_c[i][0] = ecdsa_c[i - 1][0] / 2;
        ecdsa_c[i][1] = ecdsa_c[i - 1][1] / 2;
        if ((ecdsa_doit[i] <= 1) && (ecdsa_c[i][0] == 0))
            ecdsa_doit[i] = 0;
        else {
            if (ecdsa_c[i] == 0) {
                ecdsa_c[i][0] = 1;
                ecdsa_c[i][1] = 1;
            }
        }
    }
    ecdsa_c[R_EC_B163][0] = count / 1000;
    ecdsa_c[R_EC_B163][1] = count / 1000 / 2;
    for (i = R_EC_B233; i <= R_EC_B571; i++) {
        ecdsa_c[i][0] = ecdsa_c[i - 1][0] / 2;
        ecdsa_c[i][1] = ecdsa_c[i - 1][1] / 2;
        if ((ecdsa_doit[i] <= 1) && (ecdsa_c[i][0] == 0))
            ecdsa_doit[i] = 0;
        else {
            if (ecdsa_c[i] == 0) {
                ecdsa_c[i][0] = 1;
                ecdsa_c[i][1] = 1;
            }
        }
    }
#   endif

    RAND_pseudo_bytes(buf, 20);

# ifndef OPENSSL_NO_ECDSA
    if (RAND_status() != 1) {
        RAND_seed(rnd_seed, sizeof rnd_seed);
        rnd_fake = 1;
    }
    //test_ecdsa_speed(3000);
    //	NELDTV_open_cryptodev();
    for (j = 0; j < EC_NUM; j++) {
        int ret;

        if (!ecdsa_doit[j])
            continue;           /* Ignore Curve */
        ecdsa[j] = EC_KEY_new_by_curve_name(test_curves[j]);
        if (ecdsa[j] == NULL) {
            BIO_printf(bio_err, "ECDSA failure.\n");
            ERR_print_errors(bio_err);
            rsa_count = 1;
        } else {
#  if 1
            EC_KEY_precompute_mult(ecdsa[j], NULL);
#  endif
            /* Perform ECDSA signature test */
            EC_KEY_generate_key(ecdsa[j]);
            ret = ECDSA_sign(0, buf, 20, ecdsasig, &ecdsasiglen, ecdsa[j]);
            if (ret == 0) {
                BIO_printf(bio_err,
                           "ECDSA sign failure.  No ECDSA sign will be done.\n");
                ERR_print_errors(bio_err);
                rsa_count = 1;
            } else {
                pkey_print_message("sign", "ecdsa",
                                   ecdsa_c[j][0],
                                   test_curves_bits[j], ECDSA_SECONDS);

                Time_F2(START);
                for (count = 0, run = 1; COND(ecdsa_c[j][0]); count++) {
                    ret = ECDSA_sign(0, buf, 20,
                                     ecdsasig, &ecdsasiglen, ecdsa[j]);
                    if (ret == 0) {
                        BIO_printf(bio_err, "ECDSA sign failure\n");
                        ERR_print_errors(bio_err);
                        count = 1;
                        break;
                    }
                }
                d = Time_F2(STOP);

                BIO_printf(bio_err,
                           mr ? "+R5:%ld:%d:%.2f\n" :
                           "%ld %d bit ECDSA signs in %.2fs \n",
                           count, test_curves_bits[j], d);
                ecdsa_results[j][0] = d / (double)count;
                rsa_count = count;
            }

            /* Perform ECDSA verification test */
            ret = ECDSA_verify(0, buf, 20, ecdsasig, ecdsasiglen, ecdsa[j]);
            if (ret != 1) {
                BIO_printf(bio_err,
                           "ECDSA verify failure.  No ECDSA verify will be done.\n");
                ERR_print_errors(bio_err);
                ecdsa_doit[j] = 0;
            } else {
                pkey_print_message("verify", "ecdsa",
                                   ecdsa_c[j][1],
                                   test_curves_bits[j], ECDSA_SECONDS);
                Time_F2(START);
                for (count = 0, run = 1; COND(ecdsa_c[j][1]); count++) {
                    ret =
                        ECDSA_verify(0, buf, 20, ecdsasig, ecdsasiglen,
                                     ecdsa[j]);
                    if (ret != 1) {
                        BIO_printf(bio_err, "ECDSA verify failure\n");
                        ERR_print_errors(bio_err);
                        count = 1;
                        break;
                    }
                }
                d = Time_F2(STOP);
				
                BIO_printf(bio_err,
                           mr ? "+R6:%ld:%d:%.2f\n"
                           : "%ld %d bit ECDSA verify in %.2fs\n",
                           count, test_curves_bits[j], d);
                ecdsa_results[j][1] = d / (double)count;
            }

            if (rsa_count <= 1) {
                /* if longer than 10s, don't do any more */
                for (j++; j < EC_NUM; j++)
                    ecdsa_doit[j] = 0;
            }
        }
    }

#endif
    if (rnd_fake)
        RAND_cleanup();

# ifndef OPENSSL_NO_ECDSA
    j = 1;
    for (k = 0; k < EC_NUM; k++) {
        if (!ecdsa_doit[k])
            continue;
        if (j && !mr) {
            printf("%30ssign    verify    sign/s verify/s\n", " ");
            j = 0;
        }

        if (mr)
            fprintf(stdout, "+F4:%u:%u:%f:%f\n",
                    k, test_curves_bits[k],
                    ecdsa_results[k][0], ecdsa_results[k][1]);
        else
            fprintf(stdout,
                    "%4u bit ecdsa (%s) %8.4fs %8.4fs %8.1f %8.1f\n",
                    test_curves_bits[k],
                    test_curves_names[k],
                    ecdsa_results[k][0], ecdsa_results[k][1],
                    1.0 / ecdsa_results[k][0], 1.0 / ecdsa_results[k][1]);
    }
# endif


    mret = 0;

 end:
    ERR_print_errors(bio_err);
    if (buf != NULL)
        OPENSSL_free(buf);
    if (buf2 != NULL)
        OPENSSL_free(buf2);
# ifndef OPENSSL_NO_ECDSA
    for (i = 0; i < EC_NUM; i++)
        if (ecdsa[i] != NULL)
            EC_KEY_free(ecdsa[i]);
# endif
    apps_shutdown();
    OPENSSL_EXIT(mret);
}

static void print_message(const char *s, long num, int length)
{
# ifdef SIGALRM
    BIO_printf(bio_err,
               mr ? "+DT:%s:%d:%d\n"
               : "Doing %s for %ds on %d size blocks: ", s, SECONDS, length);
    (void)BIO_flush(bio_err);
    alarm(SECONDS);
# else
    BIO_printf(bio_err,
               mr ? "+DN:%s:%ld:%d\n"
               : "Doing %s %ld times on %d size blocks: ", s, num, length);
    (void)BIO_flush(bio_err);
# endif
# ifdef LINT
    num = num;
# endif
}

static void pkey_print_message(const char *str, const char *str2, long num,
                               int bits, int tm)
{
# ifdef SIGALRM
    BIO_printf(bio_err,
               mr ? "+DTP:%d:%s:%s:%d\n"
               : "Doing %d bit %s %s's for %ds: ", bits, str, str2, tm);
    (void)BIO_flush(bio_err);
    alarm(tm);
# else
    BIO_printf(bio_err,
               mr ? "+DNP:%ld:%d:%s:%s\n"
               : "Doing %ld %d bit %s %s's: ", num, bits, str, str2);
    (void)BIO_flush(bio_err);
# endif
# ifdef LINT
    num = num;
# endif
}

static void print_result(int alg, int run_no, int count, double time_used)
{
    BIO_printf(bio_err,
               mr ? "+R:%d:%s:%f\n"
               : "%d %s's in %.2fs\n", count, names[alg], time_used);
    results[alg][run_no] = ((double)count) / time_used * lengths[run_no];
}
#endif
