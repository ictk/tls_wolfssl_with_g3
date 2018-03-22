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
typedef int( * PF_NEO_API_VERIFY_MAC)(WOLFSSL* ssl,int ssl_ret);
typedef int( * PF_NEO_SSL_INIT)(WOLFSSL* ssl);
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
typedef int( * PF_NEO_SSL_CLIENT_APPLICATION_DATA)(const byte * orgmsg,byte* out,int* pout_size);
typedef int( * PF_NEO_SSL_SERVER_APPLICATION_DATA)(const byte * orgmsg,byte* out,int* pout_size);
//END ECC_TYPEDEF


typedef struct _tagST_WC_ECC_FUNCTIONS{
	//START ECC_STR_COM
	PF_WC_ECC_GET_NAME pf_wc_ecc_get_name;
	PF_ECC_PROJECTIVE_ADD_POINT pf_ecc_projective_add_point;
	PF_ECC_PROJECTIVE_DBL_POINT pf_ecc_projective_dbl_point;
	PF_WC_ECC_MAKE_KEY pf_wc_ecc_make_key;
	PF_WC_ECC_MAKE_KEY_EX pf_wc_ecc_make_key_ex;
	PF_WC_ECC_MAKE_PUB pf_wc_ecc_make_pub;
	PF_WC_ECC_CHECK_KEY pf_wc_ecc_check_key;
	PF_WC_ECC_IS_POINT pf_wc_ecc_is_point;
	PF_WC_ECC_SHARED_SECRET pf_wc_ecc_shared_secret;
	PF_WC_ECC_SHARED_SECRET_GEN pf_wc_ecc_shared_secret_gen;
	PF_WC_ECC_SHARED_SECRET_EX pf_wc_ecc_shared_secret_ex;
	PF_WC_ECC_SIGN_HASH pf_wc_ecc_sign_hash;
	PF_WC_ECC_SIGN_HASH_EX pf_wc_ecc_sign_hash_ex;
	PF_WC_ECC_VERIFY_HASH pf_wc_ecc_verify_hash;
	PF_WC_ECC_VERIFY_HASH_EX pf_wc_ecc_verify_hash_ex;
	PF_WC_ECC_INIT pf_wc_ecc_init;
	PF_WC_ECC_INIT_EX pf_wc_ecc_init_ex;
	PF_WC_ECC_FREE pf_wc_ecc_free;
	PF_WC_ECC_SET_FLAGS pf_wc_ecc_set_flags;
	PF_WC_ECC_SET_CURVE pf_wc_ecc_set_curve;
	PF_WC_ECC_IS_VALID_IDX pf_wc_ecc_is_valid_idx;
	PF_WC_ECC_GET_CURVE_IDX pf_wc_ecc_get_curve_idx;
	PF_WC_ECC_GET_CURVE_ID pf_wc_ecc_get_curve_id;
	PF_WC_ECC_GET_CURVE_SIZE_FROM_ID pf_wc_ecc_get_curve_size_from_id;
	PF_WC_ECC_GET_CURVE_IDX_FROM_NAME pf_wc_ecc_get_curve_idx_from_name;
	PF_WC_ECC_GET_CURVE_SIZE_FROM_NAME pf_wc_ecc_get_curve_size_from_name;
	PF_WC_ECC_GET_CURVE_ID_FROM_NAME pf_wc_ecc_get_curve_id_from_name;
	PF_WC_ECC_GET_CURVE_ID_FROM_PARAMS pf_wc_ecc_get_curve_id_from_params;
	PF_WC_ECC_NEW_POINT pf_wc_ecc_new_point;
	PF_WC_ECC_NEW_POINT_H pf_wc_ecc_new_point_h;
	PF_WC_ECC_DEL_POINT pf_wc_ecc_del_point;
	PF_WC_ECC_DEL_POINT_H pf_wc_ecc_del_point_h;
	PF_WC_ECC_COPY_POINT pf_wc_ecc_copy_point;
	PF_WC_ECC_CMP_POINT pf_wc_ecc_cmp_point;
	PF_WC_ECC_POINT_IS_AT_INFINITY pf_wc_ecc_point_is_at_infinity;
	PF_WC_ECC_MULMOD pf_wc_ecc_mulmod;
	PF_WC_ECC_MULMOD_EX pf_wc_ecc_mulmod_ex;
	PF_WC_ECC_EXPORT_X963 pf_wc_ecc_export_x963;
	PF_WC_ECC_EXPORT_X963_EX pf_wc_ecc_export_x963_ex;
	PF_WC_ECC_IMPORT_X963 pf_wc_ecc_import_x963;
	PF_WC_ECC_IMPORT_X963_EX pf_wc_ecc_import_x963_ex;
	PF_WC_ECC_IMPORT_PRIVATE_KEY pf_wc_ecc_import_private_key;
	PF_WC_ECC_IMPORT_PRIVATE_KEY_EX pf_wc_ecc_import_private_key_ex;
	PF_WC_ECC_RS_TO_SIG pf_wc_ecc_rs_to_sig;
	PF_WC_ECC_SIG_TO_RS pf_wc_ecc_sig_to_rs;
	PF_WC_ECC_IMPORT_RAW pf_wc_ecc_import_raw;
	PF_WC_ECC_IMPORT_RAW_EX pf_wc_ecc_import_raw_ex;
	PF_WC_ECC_EXPORT_PRIVATE_ONLY pf_wc_ecc_export_private_only;
	PF_WC_ECC_EXPORT_PUBLIC_RAW pf_wc_ecc_export_public_raw;
	PF_WC_ECC_EXPORT_PRIVATE_RAW pf_wc_ecc_export_private_raw;
	PF_WC_ECC_EXPORT_POINT_DER pf_wc_ecc_export_point_der;
	PF_WC_ECC_IMPORT_POINT_DER pf_wc_ecc_import_point_der;
	PF_WC_ECC_SIZE pf_wc_ecc_size;
	PF_WC_ECC_SIG_SIZE pf_wc_ecc_sig_size;
	PF_WC_ECC_GET_OID pf_wc_ecc_get_oid;
	PF_WC_AESCBCENCRYPT pf_wc_AesCbcEncrypt;
	PF_WC_AESCBCDECRYPT pf_wc_AesCbcDecrypt;
	PF_NEO_API_CHANGE_4_KEY_EXCHANGE pf_neo_api_change_4_key_exchange;
	PF_NEO_API_SET_INNER_HEADER pf_neo_api_set_inner_header;
	PF_NEO_API_SET_SC_RANDOM pf_neo_api_set_sc_random;
	PF_NEO_API_CHANGE_IV pf_neo_api_change_iv;
	PF_NEO_API_VERIFY_MAC pf_neo_api_verify_mac;
	PF_NEO_SSL_INIT pf_neo_ssl_init;
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
	PF_NEO_SSL_CLIENT_APPLICATION_DATA pf_neo_ssl_client_application_data;
	PF_NEO_SSL_SERVER_APPLICATION_DATA pf_neo_ssl_server_application_data;
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