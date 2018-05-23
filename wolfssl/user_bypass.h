#ifndef NEO_WOLFSSL_USER_ECC_H
#define NEO_WOLFSSL_USER_ECC_H

#ifndef __cplusplus
#define EXT_NEO_API
#else
#define EXT_NEO_API extern "C"
#endif
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/internal.h>

//START ECC_TYPEDEF
typedef const char* ( * PF_WC_ECC_GET_NAME)(int curve_id);
typedef int( * PF_ECC_PROJECTIVE_ADD_POINT)(ecc_point* P,ecc_point* Q,ecc_point* R,mp_int* a,mp_int* modulus,mp_digit mp);
typedef int( * PF_ECC_PROJECTIVE_DBL_POINT)(ecc_point* P,ecc_point* R,mp_int* a,mp_int* modulus,mp_digit mp);
typedef int( * PF_WC_ECC_MAKE_KEY)(WC_RNG* rng,int keysize,ecc_key* key);
typedef int( * PF_WC_ECC_MAKE_KEY_EX)(WC_RNG* rng,int keysize,ecc_key* key,int curve_id);
typedef int( * PF_WC_ECC_MAKE_PUB)(ecc_key* key,ecc_point* pubOut);
typedef int( * PF_WC_ECC_CHECK_KEY)(ecc_key* key);
typedef int( * PF_WC_ECC_IS_POINT)(ecc_point* ecp,mp_int* a,mp_int* b,mp_int* prime);
typedef int( * PF_WC_ECC_SHARED_SECRET)(ecc_key* private_key,ecc_key* public_key,byte* out,word32* outlen);
typedef int( * PF_WC_ECC_SHARED_SECRET_GEN)(ecc_key* private_key,ecc_point* point,byte* out,word32 * outlen);
typedef int( * PF_WC_ECC_SHARED_SECRET_EX)(ecc_key* private_key,ecc_point* point,byte* out,word32 * outlen);
typedef int( * PF_WC_ECC_SIGN_HASH)(const byte* in,word32 inlen,byte* out,word32 * outlen,WC_RNG* rng,ecc_key* key);
typedef int( * PF_WC_ECC_SIGN_HASH_EX)(const byte* in,word32 inlen,WC_RNG* rng,ecc_key* key,mp_int * r,mp_int * s);
typedef int( * PF_WC_ECC_VERIFY_HASH)(const byte* sig,word32 siglen,const byte* hash,word32 hashlen,int* stat,ecc_key* key);
typedef int( * PF_WC_ECC_VERIFY_HASH_EX)(mp_int * r,mp_int * s,const byte* hash,word32 hashlen,int* stat,ecc_key* key);
typedef int( * PF_WC_ECC_INIT)(ecc_key* key);
typedef int( * PF_WC_ECC_INIT_EX)(ecc_key* key,void* heap,int devId);
typedef void( * PF_WC_ECC_FREE)(ecc_key* key);
typedef int( * PF_WC_ECC_SET_FLAGS)(ecc_key* key,word32 flags);
typedef int( * PF_WC_ECC_SET_CURVE)(ecc_key* key,int keysize,int curve_id);
typedef int( * PF_WC_ECC_IS_VALID_IDX)(int n);
typedef int( * PF_WC_ECC_GET_CURVE_IDX)(int curve_id);
typedef int( * PF_WC_ECC_GET_CURVE_ID)(int curve_idx);
typedef int( * PF_WC_ECC_GET_CURVE_SIZE_FROM_ID)(int curve_id);
typedef int( * PF_WC_ECC_GET_CURVE_IDX_FROM_NAME)(const char* curveName);
typedef int( * PF_WC_ECC_GET_CURVE_SIZE_FROM_NAME)(const char* curveName);
typedef int( * PF_WC_ECC_GET_CURVE_ID_FROM_NAME)(const char* curveName);
typedef int( * PF_WC_ECC_GET_CURVE_ID_FROM_PARAMS)(int fieldSize,const byte* prime,word32 primeSz,const byte* Af,word32 AfSz,const byte* Bf,word32 BfSz,const byte* order,word32 orderSz,const byte* Gx,word32 GxSz,const byte* Gy,word32 GySz,int cofactor);
typedef ecc_point* ( * PF_WC_ECC_NEW_POINT)();
typedef ecc_point* ( * PF_WC_ECC_NEW_POINT_H)(void* h);
typedef void( * PF_WC_ECC_DEL_POINT)(ecc_point* p);
typedef void( * PF_WC_ECC_DEL_POINT_H)(ecc_point* p,void* h);
typedef int( * PF_WC_ECC_COPY_POINT)(ecc_point* p,ecc_point * r);
typedef int( * PF_WC_ECC_CMP_POINT)(ecc_point* a,ecc_point * b);
typedef int( * PF_WC_ECC_POINT_IS_AT_INFINITY)(ecc_point * p);
typedef int( * PF_WC_ECC_MULMOD)(mp_int* k,ecc_point * G,ecc_point * R,mp_int* a,mp_int* modulus,int map);
typedef int( * PF_WC_ECC_MULMOD_EX)(mp_int* k,ecc_point * G,ecc_point * R,mp_int* a,mp_int* modulus,int map,void* heap);
typedef int( * PF_WC_ECC_EXPORT_X963)(ecc_key* key,byte* out,word32* outLen);
typedef int( * PF_WC_ECC_EXPORT_X963_EX)(ecc_key* key,byte* out,word32* outLen,int compressed);
typedef int( * PF_WC_ECC_IMPORT_X963)(const byte* in,word32 inLen,ecc_key* key);
typedef int( * PF_WC_ECC_IMPORT_X963_EX)(const byte* in,word32 inLen,ecc_key* key,int curve_id);
typedef int( * PF_WC_ECC_IMPORT_PRIVATE_KEY)(const byte* priv,word32 privSz,const byte* pub,word32 pubSz,ecc_key* key);
typedef int( * PF_WC_ECC_IMPORT_PRIVATE_KEY_EX)(const byte* priv,word32 privSz,const byte* pub,word32 pubSz,ecc_key* key,int curve_id);
typedef int( * PF_WC_ECC_RS_TO_SIG)(const char* r,const char* s,byte* out,word32* outlen);
typedef int( * PF_WC_ECC_SIG_TO_RS)(const byte* sig,word32 sigLen,byte* r,word32* rLen,byte* s,word32* sLen);
typedef int( * PF_WC_ECC_IMPORT_RAW)(ecc_key* key,const char* qx,const char* qy,const char* d,const char* curveName);
typedef int( * PF_WC_ECC_IMPORT_RAW_EX)(ecc_key* key,const char* qx,const char* qy,const char* d,int curve_id);
typedef int( * PF_WC_ECC_EXPORT_PRIVATE_ONLY)(ecc_key* key,byte* out,word32* outLen);
typedef int( * PF_WC_ECC_EXPORT_PUBLIC_RAW)(ecc_key* key,byte* qx,word32* qxLen,byte* qy,word32* qyLen);
typedef int( * PF_WC_ECC_EXPORT_PRIVATE_RAW)(ecc_key* key,byte* qx,word32* qxLen,byte* qy,word32* qyLen,byte* d,word32* dLen);
typedef int( * PF_WC_ECC_EXPORT_POINT_DER)(const int curve_idx,ecc_point* point,byte* out,word32* outLen);
typedef int( * PF_WC_ECC_IMPORT_POINT_DER)(byte* in,word32 inLen,const int curve_idx,ecc_point* point);
typedef int( * PF_WC_ECC_SIZE)(ecc_key* key);
typedef int( * PF_WC_ECC_SIG_SIZE)(ecc_key* key);
typedef int( * PF_WC_ECC_GET_OID)(word32 oidSum,const byte* * oid,word32* oidSz);
typedef int( * PF_WC_AESCBCENCRYPT)(Aes* aes,byte* out,const byte* in,word32 sz);
typedef int( * PF_WC_AESCBCDECRYPT)(Aes* aes,byte* out,const byte* in,word32 sz);
typedef void( * PF_NEO_API_CHANGE_4_KEY_EXCHANGE)(byte* out,word32 outLen);
typedef void( * PF_NEO_API_SET_INNER_HEADER)(const byte* innerheader,word32 innerheader_size);
typedef void( * PF_NEO_API_SET_SC_RANDOM)(const byte* client_random,const byte* server_random);
typedef void( * PF_NEO_API_CHANGE_IV)(byte* client_iv,byte* server_iv);
typedef int( * PF_NEO_API_VERIFY_MAC)(int ssl_ret);
typedef int( * PF_NEO_API_GET_PADSIZE)(int * pad_size);
typedef int( * PF_NEO_SSL_INIT)(WOLFSSL* ssl);
typedef int( * PF_NEO_SSL_IMPORT_CERT)(int cert_type,byte* cert,int* pcert_size);
typedef int( * PF_NEO_SSL_CLIENT_HELLO)(const byte * random);
typedef int( * PF_NEO_SSL_SERVER_HELLO)(const byte * random);
typedef int( * PF_NEO_SSL_SERVER_CERTIFICATE_SET_ECDSA_PUBKEY)(const byte* pubkey_asn1,int size);
typedef int( * PF_NEO_SSL_SERVER_CERTIFICATE_VERIFY)(const byte* cert_pubkey_asn1,int pub_size,const byte * hash_cert,const byte * sign_asn1,int sign_size,int * pverify);
typedef int( * PF_NEO_SSL_SERVER_KEY_EXCHANGE_SET_PEER_PUBKEY)(const byte* peer_pubkey_asn1,int pub_size);
typedef int( * PF_NEO_SSL_SERVER_KEY_EXCHANGE_VERIFY)(const byte* hash,const byte * sign_asn1,int sign_size,int* pverify);
typedef int( * PF_NEO_SSL_CLIENT_CERTIFICATE)(const byte * hash_cert,byte * sign_asn1,int * psign_size);
typedef int( * PF_NEO_SSL_CLIENT_KEY_EXCHANGE)(byte* chip_peer_pubkey,int* ppub_key);
typedef int( * PF_NEO_SSL_CLIENT_KEY_EXCHANGE_EXPORT_PREMASTER_KEY)(byte* pre_master_key,int* pkey_size);
typedef int( * PF_NEO_SSL_CLIENT_CERTIFICATE_VERIFY_SIGN)(const byte * hash,byte* sign,int* psign_size);
typedef int( * PF_NEO_SSL_DO_FINISH_GET_PRF)(const char* label,const byte * hand_shake_hash,byte* prf,int* pprf_size);
typedef int( * PF_NEO_SSL_CLIENT_ENCRYPT)(const byte * orgmsg,byte* out,int* pout_size);
typedef int( * PF_NEO_SSL_SERVER_DECRYPT)(const byte * orgmsg,byte* out,int* pout_size);
//END ECC_TYPEDEF


typedef struct _tagST_WC_ECC_FUNCTIONS{
	//START ECC_STR_COM
	PF_WC_AESCBCENCRYPT pf_wc_AesCbcEncrypt;
	PF_WC_AESCBCDECRYPT pf_wc_AesCbcDecrypt;
	PF_NEO_API_SET_INNER_HEADER pf_neo_api_set_inner_header;
	PF_NEO_API_VERIFY_MAC pf_neo_api_verify_mac;
	PF_NEO_API_GET_PADSIZE pf_neo_api_get_padsize;
	PF_NEO_SSL_IMPORT_CERT pf_neo_ssl_import_cert;
	PF_NEO_SSL_CLIENT_HELLO pf_neo_ssl_client_hello;
	PF_NEO_SSL_SERVER_HELLO pf_neo_ssl_server_hello;
	PF_NEO_SSL_SERVER_CERTIFICATE_SET_ECDSA_PUBKEY pf_neo_ssl_server_certificate_set_ecdsa_pubkey;
	PF_NEO_SSL_SERVER_CERTIFICATE_VERIFY pf_neo_ssl_server_certificate_verify;
	PF_NEO_SSL_SERVER_KEY_EXCHANGE_SET_PEER_PUBKEY pf_neo_ssl_server_key_exchange_set_peer_pubkey;
	PF_NEO_SSL_SERVER_KEY_EXCHANGE_VERIFY pf_neo_ssl_server_key_exchange_verify;
	PF_NEO_SSL_CLIENT_CERTIFICATE pf_neo_ssl_client_certificate;
	PF_NEO_SSL_CLIENT_KEY_EXCHANGE pf_neo_ssl_client_key_exchange;
	PF_NEO_SSL_CLIENT_KEY_EXCHANGE_EXPORT_PREMASTER_KEY pf_neo_ssl_client_key_exchange_export_premaster_key;
	PF_NEO_SSL_CLIENT_CERTIFICATE_VERIFY_SIGN pf_neo_ssl_client_certificate_verify_sign;
	PF_NEO_SSL_DO_FINISH_GET_PRF pf_neo_ssl_do_finish_get_prf;
	PF_NEO_SSL_CLIENT_ENCRYPT pf_neo_ssl_client_encrypt;
	PF_NEO_SSL_SERVER_DECRYPT pf_neo_ssl_server_decrypt;
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