#ifndef NEO_WOLFSSL_USER_ECC_H
#define NEO_WOLFSSL_USER_ECC_H

#ifndef __cplusplus
#define EXT_NEO_API
#else
#define EXT_NEO_API extern "C"
#endif
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/aes.h>

//START ECC_TYPEDEF
typedef int( * PF_WC_ECC_SHARED_SECRET)(ecc_key*   private_key,ecc_key*   public_key,byte*   out,word32*   outlen);
typedef int( * PF_WC_ECC_SIGN_HASH)(const byte*   in,word32 inlen,byte*   out,word32 *  outlen,WC_RNG*   rng,ecc_key*   key);
typedef int( * PF_WC_ECC_VERIFY_HASH)(const byte*   sig,word32 siglen,const byte*   hash,word32 hashlen,int*   stat,ecc_key*   key);
typedef int( * PF_WC_ECC_EXPORT_X963)(ecc_key*   key,byte*   out,word32*   outLen);
typedef int( * PF_WC_ECC_EXPORT_X963_EX)(ecc_key*   key,byte*   out,word32*   outLen,int compressed);
typedef int( * PF_WC_ECC_IMPORT_X963)(const byte*   in,word32 inLen,ecc_key*   key);
typedef int( * PF_WC_ECC_IMPORT_X963_EX)(const byte*   in,word32 inLen,ecc_key*   key,int curve_id);
typedef int( * PF_WC_ECC_IMPORT_PRIVATE_KEY)(const byte*   priv,word32 privSz,const byte*   pub,word32 pubSz,ecc_key*   key);
typedef int( * PF_WC_ECC_IMPORT_PRIVATE_KEY_EX)(const byte*   priv,word32 privSz,const byte*   pub,word32 pubSz,ecc_key*   key,int curve_id);
typedef int( * PF_WC_AESCBCENCRYPT)(Aes*  aes,byte*  out,const byte*  in,word32 sz);
typedef int( * PF_WC_AESCBCDECRYPT)(Aes*  aes,byte*  out,const byte*  in,word32 sz);
//END ECC_TYPEDEF


typedef struct _tagST_WC_ECC_FUNCTIONS{
	//START ECC_STR_COM
	PF_WC_ECC_SHARED_SECRET pf_wc_ecc_shared_secret;
	PF_WC_ECC_SIGN_HASH pf_wc_ecc_sign_hash;
	PF_WC_ECC_VERIFY_HASH pf_wc_ecc_verify_hash;
	PF_WC_ECC_EXPORT_X963 pf_wc_ecc_export_x963;
	PF_WC_ECC_EXPORT_X963_EX pf_wc_ecc_export_x963_ex;
	PF_WC_ECC_IMPORT_X963 pf_wc_ecc_import_x963;
	PF_WC_ECC_IMPORT_X963_EX pf_wc_ecc_import_x963_ex;
	PF_WC_ECC_IMPORT_PRIVATE_KEY pf_wc_ecc_import_private_key;
	PF_WC_ECC_IMPORT_PRIVATE_KEY_EX pf_wc_ecc_import_private_key_ex;
	PF_WC_AESCBCENCRYPT pf_wc_AesCbcEncrypt;
	PF_WC_AESCBCDECRYPT pf_wc_AesCbcDecrypt;
//END ECC_STR_COM
}ST_WC_ECC_FUNCTIONS, *LPST_WC_ECC_FUNCTIONS;




#ifdef __cplusplus
extern "C" {
#endif
	int ecc_Key_to_private(ecc_key* private_key, byte* out);
	int ecc_Key_to_public(ecc_key* public_key, byte* out);
	void set_user_wc_ecc_functions(const LPST_WC_ECC_FUNCTIONS lpst_wc_ecc_functions);
	void  get_user_wc_ecc_functions(LPST_WC_ECC_FUNCTIONS lpst_wc_ecc_functions);
	int make_sign_64_to_sign_asn1(const byte*  sign64, byte*  signasn1, word32 *psignasn1len);
	int make_sign_asn1_to_sign_64(const byte*  signasn1, word32 signasn1len, byte*  sign64);
	void dword_reverse(byte * buff, int byte_size);

#ifdef __cplusplus
}   /* extern "C" */
#endif



#endif //NEO_WOLFSSL_USER_ECC_H