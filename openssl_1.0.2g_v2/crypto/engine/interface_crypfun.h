/*---------------------------------------------------------------------------
//
//	Copyright(C) NELDTV Corporation, 2011-2020.
//
//  File	:	interface_cryfun.h
//	Purpose	:
//	History :
//				2012-03-06 created by Bitter Chen
//				2017-04-13 modified by Bitter Chen
//				2017-08-13 added by Shiney Yu
//
---------------------------------------------------------------------------*/
#ifndef INTERFACE_CRYPFUN_H
#define INTERFACE_CRYPFUN_H

#ifdef __cplusplus
extern "C"{
#endif

typedef unsigned int NELDTVC_UINT;
typedef NELDTVC_UINT NELDTVC_RV;

typedef NELDTVC_UINT  T_ndn_Error;
typedef unsigned char uint8_t;
//typedef unsigned int size_t;  //standard

NELDTVC_RV  NELDTV_open_cryptodev(void);
//NELDTVC_RV  NELDTV_open_cryptodev_nodigst(void);
NELDTVC_RV  NELDTV_close_cryptodev(void);

char *  NELDTV_get_version_cryptodev(void);

#define M_HALG_MODESHA256    (1)
#define M_HALG_MODESHA1      (2)

#define M_HALG_RESLUTL_SHA1     (20)
#define M_HALG_RESLUTL_SHA256   (32)
#define M_HALG_RESLUTL_MAXLEN    M_HALG_RESLUTL_SHA256

#define M_NELDTVCR_OK           (0)
//#define M_NELDTVCR_EINPUTPARA   (0x8001)
#define M_NELDTVCR_ENOTOPENDEV  (0x8002)


#define M_NELDTVCR_WREOPEN      (0x9001)
#define M_RSA_PRVSING_NID_TYPE_UNDEF           (0xA004) 
#define M_RSA_PRVSING_NID_LEN_ERROR            (0xA005) 
#define M_RSA_PRVSING_CHGKEYTYPE               (0xA006) 
#define M_RSA_PRVSING_ADDPADDING_ERROR         (0xA007) 
#define M_RSA_PRVSING_UNKNOWN_PADDING          (0xA008) 
#define M_RSA_PRVSING_RUN_ALG_ERR              (0xA009) 

#define M_RSA_PUBVERI_NID_TYPE_UNDEF           (0xA104) 
#define M_RSA_PUBVERI_NID_LEN_ERROR            (0xA105) 
#define M_RSA_PUBVERI_CHGKEYTYPE               (0xA106) 
#define M_RSA_PUBVERI_CHECKPADDING_ERROR       (0xA107) 
#define M_RSA_PUBVERI_UNKNOWN_PADDING          (0xA108) 
#define M_RSA_PUBVERI_RUN_ALG_ERR              (0xA109) 
#define M_RSA_PUBVERI_NID_HEARDTAG_ERROR       (0xA10A) 
#define M_RSA_PUBVERI_NID_DIGEST_ERROR         (0xA10B)

#define M_RSA_PUBENC_UNKNOWN_PADDING           (0xA204) 
#define M_RSA_PUBENC_RUN_ALG_ERR               (0xA205) 
#define M_RSA_PUBENC_CHGKEYTYPE                (0xA206) 
#define M_RSA_PUBENC_ADDPADDING_ERROR          (0xA207) 

#define M_RSA_PRVDEC_PADDING_CHECK_FAILED      (0xA304) 
#define M_RSA_PRVDEC_RUN_ALG_ERR               (0xA305) 
#define M_RSA_PRVDEC_CHGKEYTYPE                (0xA306) 
#define M_RSA_PRVDEC_UNKNOWN_PADDING           (0xA307) 


#define M_SALG_MODE_AES_ENC_ECB     (0)
#define M_SALG_MODE_AES_DEC_ECB     (1)
#define M_SALG_MODE_DES_ENC_ECB     (2)
#define M_SALG_MODE_DES_DEC_ECB     (3)
#define M_SALG_MODE_TDES_ENC_ECB    (4)
#define M_SALG_MODE_TDES_DEC_ECB    (5)

#define M_SALG_MODE_AES_ENC_CBC     (6)
#define M_SALG_MODE_AES_DEC_CBC     (7)
#define M_SALG_MODE_DES_ENC_CBC     (8)
#define M_SALG_MODE_DES_DEC_CBC     (9)
#define M_SALG_MODE_TDES_ENC_CBC    (10)
#define M_SALG_MODE_TDES_DEC_CBC    (11)

/** \brief single call convenience function to compute AES128 encryption of given data in CBC mode with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
T_ndn_Error
ndn_AesAlgorithm_encrypt128Cbc_hardware
  (const uint8_t *key, size_t keyLength, const uint8_t *initialVector,
   size_t initialVectorLength, const uint8_t *plainData,
   int plainDataLength, uint8_t *encryptedData, int *encryptedDataLength);

/** \brief single call convenience function to compute AES128 decryption of given data in CBC mode with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
T_ndn_Error
ndn_AesAlgorithm_decrypt128Cbc_hardware
  (const uint8_t *key, size_t keyLength, const uint8_t *initialVector,
   size_t initialVectorLength, const uint8_t *encryptedData,
   int encryptedDataLength, uint8_t *plainData, int *plainDataLength);

/** \brief single call convenience function to compute AES128 encryption of given data in ECB mode with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
T_ndn_Error
ndn_AesAlgorithm_encrypt128Ecb_hardware
  (const uint8_t *key, size_t keyLength, const uint8_t *plainData,
   int plainDataLength, uint8_t *encryptedData, int *encryptedDataLength);

/** \brief single call convenience function to compute AES128 decryption of given data in ECB mode with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
T_ndn_Error
ndn_AesAlgorithm_decrypt128Ecb_hardware
  (const uint8_t *key, size_t keyLength, const uint8_t *encryptedData,
   int encryptedDataLength, uint8_t *plainData, int *plainDataLength);

/** \brief single call convenience function to compute AES128 encryption of given data in CBC mode without hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
T_ndn_Error
ndn_AesAlgorithm_encrypt128Cbc_software
  (const uint8_t *key, size_t keyLength, const uint8_t *initialVector,
   size_t initialVectorLength, const uint8_t *plainData,
   int plainDataLength, uint8_t *encryptedData, int *encryptedDataLength);

/** \brief single call convenience function to compute AES128 decryption of given data in CBC mode without hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
T_ndn_Error
ndn_AesAlgorithm_decrypt128Cbc_software
  (const uint8_t *key, size_t keyLength, const uint8_t *initialVector,
   size_t initialVectorLength, const uint8_t *encryptedData,
   int encryptedDataLength, uint8_t *plainData, int *plainDataLength);

/** \brief single call convenience function to compute AES128 encryption of given data in ECB mode without hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
T_ndn_Error
ndn_AesAlgorithm_encrypt128Ecb_software
  (const uint8_t *key, size_t keyLength, const uint8_t *plainData,
   int plainDataLength, uint8_t *encryptedData, int *encryptedDataLength);

/** \brief single call convenience function to compute AES128 decryption of given data in ECB mode without hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
T_ndn_Error
ndn_AesAlgorithm_decrypt128Ecb_software
  (const uint8_t *key, size_t keyLength, const uint8_t *encryptedData,
   int encryptedDataLength, uint8_t *plainData, int *plainDataLength);

/** \brief single call convenience function to compute AES256 encryption of given data in CBC mode with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
T_ndn_Error
ndn_AesAlgorithm_encrypt256Cbc_hardware
  (const uint8_t *key, size_t keyLength, const uint8_t *initialVector,
   size_t initialVectorLength, const uint8_t *plainData,
   int plainDataLength, uint8_t *encryptedData, int *encryptedDataLength);

/** \brief single call convenience function to compute AES256 decryption of given data in CBC mode with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
T_ndn_Error
ndn_AesAlgorithm_decrypt256Cbc_hardware
  (const uint8_t *key, size_t keyLength, const uint8_t *initialVector,
   size_t initialVectorLength, const uint8_t *encryptedData,
   int encryptedDataLength, uint8_t *plainData, int *plainDataLength);

/** \brief single call convenience function to compute AES256 encryption of given data in ECB mode with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
T_ndn_Error
ndn_AesAlgorithm_encrypt256Ecb_hardware
  (const uint8_t *key, size_t keyLength, const uint8_t *plainData,
   int plainDataLength, uint8_t *encryptedData, int *encryptedDataLength);

/** \brief single call convenience function to compute AES256 decryption of given data in ECB mode with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
T_ndn_Error
ndn_AesAlgorithm_decrypt256Ecb_hardware
  (const uint8_t *key, size_t keyLength, const uint8_t *encryptedData,
   int encryptedDataLength, uint8_t *plainData, int *plainDataLength);

/** \brief single call convenience function to compute SHA256 of given data with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
T_ndn_Error
ndn_digestSha256_hardware(const uint8_t *data, size_t dataLength, uint8_t *digest);

/** \brief single call convenience function to compute SHA1 of given data with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
T_ndn_Error
ndn_digestSha1_hardware(const uint8_t *data, size_t dataLength, uint8_t *digest);

/** \brief single call convenience function to compute RSA encryption of given data with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
int RSA_public_encrypt_hardware 	( 	int  	flen,
		const unsigned char *  	from,
		unsigned char *  	to,
		RSA *  	rsa,
		int  	padding 
	);

/** \brief single call convenience function to compute RSA sign of given data without hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
int RSA_sign_software	(	int 	type,
		const unsigned char *	m,
		unsigned int	m_length,
		unsigned char * 	sigret,
		unsigned int *		siglen,
		RSA *	rsa 
	);

/** \brief single call convenience function to compute RSA verify of given data without hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
int RSA_verify_software	(	int 	type,
		const unsigned char *	m,
		unsigned int	m_length,
		const unsigned char *	sigbuf,
		unsigned int	siglen,
		RSA *	rsa 
	);

/** \brief single call convenience function to compute RSA verify of given data with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
int RSA_verify_hardware 	(	int 	type,
		const unsigned char *	m,
		unsigned int	m_length,
		const unsigned char *	sigbuf,
		unsigned int	siglen,
		RSA *	rsa 
	);

/** \brief single call convenience function to compute RSA sign of given data with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
int RSA_sign_hardware	(	int 	type,
		const unsigned char *	m,
		unsigned int	m_length,
		unsigned char * 	sigret,
		unsigned int *		siglen,
		RSA *	rsa 
	);

/** \brief single call convenience function to compute RSA decryption of given data with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
int RSA_private_decrypt_hardware	(	int 	flen,
		const unsigned char *	from,
		unsigned char * 	to,
		RSA *	rsa,
		int 	padding 
	);

/** \brief single call convenience function to compute ECDSA verify of given data with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
int ECDSA_verify_hardware	(	int 	type,
		const unsigned char *	dgst,
		int 	dgstlen,
		const unsigned char *	sig,
		int 	siglen,
		EC_KEY *	eckey 
	);

/** \brief single call convenience function to compute ECDSA sign of given data with hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */

int ECDSA_sign_hardware 	(	int 	type,
		const unsigned char *	dgst,
		int 	dgstlen,
		unsigned char * 	sig,
		unsigned int *		siglen,
		EC_KEY *	eckey 
	);

/** \brief single call convenience function to compute RSA encryption of given data without hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */			
int RSA_public_encrypt_software (	int 	flen,
					const unsigned char *	from,
					unsigned char * 	to,
					RSA *	rsa,
					int 	padding 
	);


/** \brief single call convenience function to compute RSA decryption of given data without hardware acceleration
 * \description of parameters please refer to programming doc
 * \return T_ndn_Error
 */
int RSA_private_decrypt_software 	( 	int  	flen,
		const unsigned char *  	from,
		unsigned char *  	to,
		RSA *  	rsa,
		int  	padding 
	);



#ifdef __cplusplus
}
#endif

#endif /* interface_cryfun.h */
