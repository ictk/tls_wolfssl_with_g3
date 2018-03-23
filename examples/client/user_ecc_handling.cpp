#include <wolfssl/wolfcrypt/ecc.h>
#include "neoDebug.h"
#include "neoCoLib.h"
#include "wolfssl/debug_util.h"
#include "wolfssl/user_bypass.h"
#include "sample_def.h"
#include"g3_api.h"


#define KEY_SECTOR_DEVICE_PUB_KEY 8
#define KEY_SECTOR_DEVICE_PRV_KEY 10

const unsigned char passwd[] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};


extern "C" void init_user_ecc(const char * st_com);
ST_WC_ECC_FUNCTIONS _wc_ecc_functions_org;
LPST_WC_ECC_FUNCTIONS _lpwc = &_wc_ecc_functions_org;

PF_WC_ECC_VERIFY_HASH _org_pf_wc_ecc_verify_hash;
WOLFSSL* _ssl;

//START DEC_NEW
const char*  wc_ecc_get_name_new(int curve_id);
int ecc_projective_add_point_new(ecc_point* P,ecc_point* Q,ecc_point* R,mp_int* a,mp_int* modulus,mp_digit mp);
int ecc_projective_dbl_point_new(ecc_point* P,ecc_point* R,mp_int* a,mp_int* modulus,mp_digit mp);
int wc_ecc_make_key_new(WC_RNG* rng,int keysize,ecc_key* key);
int wc_ecc_make_key_ex_new(WC_RNG* rng,int keysize,ecc_key* key,int curve_id);
int wc_ecc_make_pub_new(ecc_key* key,ecc_point* pubOut);
int wc_ecc_check_key_new(ecc_key* key);
int wc_ecc_is_point_new(ecc_point* ecp,mp_int* a,mp_int* b,mp_int* prime);
int wc_ecc_shared_secret_new(ecc_key* private_key,ecc_key* public_key,byte* out,word32* outlen);
int wc_ecc_shared_secret_gen_new(ecc_key* private_key,ecc_point* point,byte* out,word32 * outlen);
int wc_ecc_shared_secret_ex_new(ecc_key* private_key,ecc_point* point,byte* out,word32 * outlen);
int wc_ecc_sign_hash_new(const byte* in,word32 inlen,byte* out,word32 * outlen,WC_RNG* rng,ecc_key* key);
int wc_ecc_sign_hash_ex_new(const byte* in,word32 inlen,WC_RNG* rng,ecc_key* key,mp_int * r,mp_int * s);
int wc_ecc_verify_hash_new(const byte* sig,word32 siglen,const byte* hash,word32 hashlen,int* stat,ecc_key* key);
int wc_ecc_verify_hash_ex_new(mp_int * r,mp_int * s,const byte* hash,word32 hashlen,int* stat,ecc_key* key);
int wc_ecc_init_new(ecc_key* key);
int wc_ecc_init_ex_new(ecc_key* key,void* heap,int devId);
void wc_ecc_free_new(ecc_key* key);
int wc_ecc_set_flags_new(ecc_key* key,word32 flags);
int wc_ecc_set_curve_new(ecc_key* key,int keysize,int curve_id);
int wc_ecc_is_valid_idx_new(int n);
int wc_ecc_get_curve_idx_new(int curve_id);
int wc_ecc_get_curve_id_new(int curve_idx);
int wc_ecc_get_curve_size_from_id_new(int curve_id);
int wc_ecc_get_curve_idx_from_name_new(const char* curveName);
int wc_ecc_get_curve_size_from_name_new(const char* curveName);
int wc_ecc_get_curve_id_from_name_new(const char* curveName);
int wc_ecc_get_curve_id_from_params_new(int fieldSize,const byte* prime,word32 primeSz,const byte* Af,word32 AfSz,const byte* Bf,word32 BfSz,const byte* order,word32 orderSz,const byte* Gx,word32 GxSz,const byte* Gy,word32 GySz,int cofactor);
ecc_point*  wc_ecc_new_point_new();
ecc_point*  wc_ecc_new_point_h_new(void* h);
void wc_ecc_del_point_new(ecc_point* p);
void wc_ecc_del_point_h_new(ecc_point* p,void* h);
int wc_ecc_copy_point_new(ecc_point* p,ecc_point * r);
int wc_ecc_cmp_point_new(ecc_point* a,ecc_point * b);
int wc_ecc_point_is_at_infinity_new(ecc_point * p);
int wc_ecc_mulmod_new(mp_int* k,ecc_point * G,ecc_point * R,mp_int* a,mp_int* modulus,int map);
int wc_ecc_mulmod_ex_new(mp_int* k,ecc_point * G,ecc_point * R,mp_int* a,mp_int* modulus,int map,void* heap);
int wc_ecc_export_x963_new(ecc_key* key,byte* out,word32* outLen);
int wc_ecc_export_x963_ex_new(ecc_key* key,byte* out,word32* outLen,int compressed);
int wc_ecc_import_x963_new(const byte* in,word32 inLen,ecc_key* key);
int wc_ecc_import_x963_ex_new(const byte* in,word32 inLen,ecc_key* key,int curve_id);
int wc_ecc_import_private_key_new(const byte* priv,word32 privSz,const byte* pub,word32 pubSz,ecc_key* key);
int wc_ecc_import_private_key_ex_new(const byte* priv,word32 privSz,const byte* pub,word32 pubSz,ecc_key* key,int curve_id);
int wc_ecc_rs_to_sig_new(const char* r,const char* s,byte* out,word32* outlen);
int wc_ecc_sig_to_rs_new(const byte* sig,word32 sigLen,byte* r,word32* rLen,byte* s,word32* sLen);
int wc_ecc_import_raw_new(ecc_key* key,const char* qx,const char* qy,const char* d,const char* curveName);
int wc_ecc_import_raw_ex_new(ecc_key* key,const char* qx,const char* qy,const char* d,int curve_id);
int wc_ecc_export_private_only_new(ecc_key* key,byte* out,word32* outLen);
int wc_ecc_export_public_raw_new(ecc_key* key,byte* qx,word32* qxLen,byte* qy,word32* qyLen);
int wc_ecc_export_private_raw_new(ecc_key* key,byte* qx,word32* qxLen,byte* qy,word32* qyLen,byte* d,word32* dLen);
int wc_ecc_export_point_der_new(const int curve_idx,ecc_point* point,byte* out,word32* outLen);
int wc_ecc_import_point_der_new(byte* in,word32 inLen,const int curve_idx,ecc_point* point);
int wc_ecc_size_new(ecc_key* key);
int wc_ecc_sig_size_new(ecc_key* key);
int wc_ecc_get_oid_new(word32 oidSum,const byte* * oid,word32* oidSz);
int wc_AesCbcEncrypt_new(Aes* aes,byte* out,const byte* in,word32 sz);
int wc_AesCbcDecrypt_new(Aes* aes,byte* out,const byte* in,word32 sz);
void neo_api_change_4_key_exchange_new(byte* out,word32 outLen);
void neo_api_set_inner_header_new(const byte* innerheader,word32 innerheader_size);
void neo_api_set_sc_random_new(const byte* client_random,const byte* server_random);
void neo_api_change_iv_new(byte* client_iv,byte* server_iv);
int neo_api_verify_mac_new(WOLFSSL* ssl,int ssl_ret);
int neo_ssl_init_new(WOLFSSL* ssl);
int neo_ssl_import_cert_new(int cert_type,byte* cert,int* pcert_size);
int neo_ssl_client_hello_new(const byte * random);
int neo_ssl_server_hello_new(const byte * random);
int neo_ssl_server_certificate_set_ecdsa_pubkey_new(const byte* pubkey_asn1,int size);
int neo_ssl_server_certificate_verify_new(const byte* cert_pubkey_asn1,int pub_size,const byte * hash_cert,const byte * sign_asn1,int sign_size,int * pverify);
int neo_ssl_server_key_exchange_set_peer_pubkey_new(const byte* peer_pubkey_asn1,int pub_size);
int neo_ssl_server_key_exchange_verify_new(const byte* hash,const byte * sign_asn1,int sign_size,int* pverify);
int neo_ssl_client_certificate_new(const byte * hash_cert,byte * sign_asn1,int * psign_size);
int neo_ssl_client_key_exchange_new(byte* chip_peer_pubkey,int* ppub_key);
int neo_ssl_client_key_exchange_export_premaster_key_new(byte* pre_master_key,int* pkey_size);
int neo_ssl_client_certificate_verify_sign_new(const byte * hash,byte* sign,int* psign_size);
int neo_ssl_do_finish_get_prf_new(const char* label,const byte * hand_shake_hash,byte* prf,int* pprf_size);
int neo_ssl_client_application_data_new(const byte * orgmsg,byte* out,int* pout_size);
int neo_ssl_server_application_data_new(const byte * orgmsg,byte* out,int* pout_size);
//END DEC_NEW

//int neo_api_verify_mac_new(int ssl_ret);
int neo_api_verify_mac_new(WOLFSSL* ssl, int ssl_ret);
//#define USE_ORG_DEC


ST_ECDH_RANDOM _st_ecdh_random;
ST_ECDH_IV _st_iv;
byte _inner[WOLFSSL_TLS_HMAC_INNER_SZ];
int _ret_verify = 0;
int _pad_size = 0;
//ST_ECC_PUBLIC _st_ecc_public_4_verify;
ST_ECC_PUBLIC _st_public_ecdsa_key;
ST_ECC_PUBLIC _st_chip_public_peer_key;
ST_ECC_PUBLIC _st_public_peer_key;
ST_ECDH_PRE_MASTER_SECRET _st_ecdh_pre_master_secret;;
ST_DATA_32 hand_shake_hash;

#pragma pack(push, 1)



typedef struct _CERTINFO {
	byte type;
	byte stindex;
	word size;
}CERTINFO;
#pragma pack(pop)  
void swap_bytes(void* value, int size)
{
	unsigned char * pvalue = (unsigned char *)value;
	unsigned char * pnewvalue = (unsigned char *)malloc(size);

	for (int i = 0; i < size; i++){
		*(pnewvalue + size - 1 - i) = *(pvalue + i);
	}
	memcpy(value, pnewvalue, size);
	free(pnewvalue);

}

SAMPLE_FUNCTIONS _cursamplefunction;
void get_functions_ieb100cdc(LPSAMPLE_FUNCTIONS lpsamplefunction);
void init_user_ecc(const char * st_com)
{

	get_functions_ieb100cdc(&_cursamplefunction);

	_cursamplefunction.init_sample((void*)st_com);
	_cursamplefunction.wake_up_and_convert_mode();



	//make_sign_asn1_from_sign_64();



	ST_WC_ECC_FUNCTIONS wc_ecc_functions;
	get_user_wc_ecc_functions(&wc_ecc_functions);
	memcpy(&_wc_ecc_functions_org, &wc_ecc_functions, sizeof(ST_WC_ECC_FUNCTIONS));
	/*wc_ecc_functions.pf_wc_ecc_verify_hash = wc_ecc_verify_hash_new;
	wc_ecc_functions.pf_wc_ecc_sign_hash = wc_ecc_sign_hash_new;
	wc_ecc_functions.pf_wc_ecc_import_x963 = wc_ecc_import_x963_new;
	wc_ecc_functions.pf_wc_ecc_import_x963_ex = wc_ecc_import_x963_ex_new;
	wc_ecc_functions.pf_wc_ecc_shared_secret = wc_ecc_shared_secret_new;*/

	wc_ecc_functions.pf_wc_AesCbcDecrypt = wc_AesCbcDecrypt_new;
	wc_ecc_functions.pf_wc_AesCbcEncrypt = wc_AesCbcEncrypt_new;

	//wc_ecc_functions.pf_neo_api_change_4_key_exchange = neo_api_change_4_key_exchange_new;
	
	wc_ecc_functions.pf_neo_api_set_inner_header = neo_api_set_inner_header_new;
	wc_ecc_functions.pf_neo_api_set_sc_random = neo_api_set_sc_random_new;
	wc_ecc_functions.pf_neo_api_change_iv = neo_api_change_iv_new;
	wc_ecc_functions.pf_neo_api_verify_mac = neo_api_verify_mac_new;
	//START SET_EXTERN_PF
	wc_ecc_functions.pf_neo_ssl_init = neo_ssl_init_new;
	wc_ecc_functions.pf_neo_ssl_import_cert = neo_ssl_import_cert_new;
	wc_ecc_functions.pf_neo_ssl_client_hello = neo_ssl_client_hello_new;
	wc_ecc_functions.pf_neo_ssl_server_hello = neo_ssl_server_hello_new;
	wc_ecc_functions.pf_neo_ssl_server_certificate_set_ecdsa_pubkey = neo_ssl_server_certificate_set_ecdsa_pubkey_new;
	wc_ecc_functions.pf_neo_ssl_server_certificate_verify = neo_ssl_server_certificate_verify_new;
	wc_ecc_functions.pf_neo_ssl_server_key_exchange_set_peer_pubkey = neo_ssl_server_key_exchange_set_peer_pubkey_new;
	wc_ecc_functions.pf_neo_ssl_server_key_exchange_verify = neo_ssl_server_key_exchange_verify_new;
	wc_ecc_functions.pf_neo_ssl_client_certificate = neo_ssl_client_certificate_new;
	wc_ecc_functions.pf_neo_ssl_client_key_exchange = neo_ssl_client_key_exchange_new;
	wc_ecc_functions.pf_neo_ssl_client_key_exchange_export_premaster_key = neo_ssl_client_key_exchange_export_premaster_key_new;
	wc_ecc_functions.pf_neo_ssl_client_certificate_verify_sign = neo_ssl_client_certificate_verify_sign_new;
	wc_ecc_functions.pf_neo_ssl_do_finish_get_prf = neo_ssl_do_finish_get_prf_new;
	wc_ecc_functions.pf_neo_ssl_client_application_data = neo_ssl_client_application_data_new;
	wc_ecc_functions.pf_neo_ssl_server_application_data = neo_ssl_server_application_data_new;
//END SET_EXTERN_PF
	
	//wc_ecc_shared_secret_new

	set_user_wc_ecc_functions(&wc_ecc_functions);

	
	unsigned char buff[32];
	int res_chall_size = 32;
	g3api_get_chellange(32, buff, &res_chall_size);
	print_bin("g3api_get_chellange", buff, res_chall_size);

	dword_reverse(buff, res_chall_size);
	print_bin("g3api_get_chellange dword reverse", buff, res_chall_size);
	

	int ret = g3api_verify_passwd(3, passwd, sizeof(passwd));


}

int verify_hash_with_extern_pubkey_with_g3(const ST_ECC_PUBLIC * pubkey, const byte*  hash,  const byte*  sig, word32 siglen, int*  stat)
{

	byte tmppubkey[65];
	word32 tmppubkey_size = 65;

	print_bin("FUCK sig", sig, siglen);
	print_bin("FUCK hash", hash, 32);
	print_bin("FUCK pubkey", pubkey, sizeof(ST_ECC_PUBLIC));

	byte sign64[64] = { 0, };
	int err = make_sign_asn1_to_sign_64(sig, siglen, sign64);
	print_bin("sign64 ", sign64, 64);
	ST_DATA_32 st_data_32;
	g3api_set_extern_public_key(pubkey, sizeof(ST_ECC_PUBLIC), &st_data_32);


	int ret_api = g3api_verify(KEY_SECTOR_DEVICE_PUB_KEY, EN_VERIFY_OPTION::VERYFY_EXT_PUB_ECDSA_EXT_SHA256, hash, 32, sign64, 64);

	printf("0x%x \n", ret_api);

	*stat = (ret_api == 0);
	if (ret_api == 1) return -1;

	//int ret = _wc_ecc_functions_org.pf_wc_ecc_verify_hash(sig, siglen, hash, hashlen, stat, key);
	return ret_api <0 ? ret_api : 0;
}




int wc_AesCbcEncrypt_new(Aes*  aes, byte*  out, const byte*  in, word32 sz)
{
	
	byte tmppubkey[16];
	word32 tmppubkey_size = 16;
	memcpy(tmppubkey, aes->key, tmppubkey_size);
	
	dword_reverse(tmppubkey, tmppubkey_size);
	print_bin("wc_AesCbcEncrypt_new key", tmppubkey, tmppubkey_size);
	int outsize = sz+20;
	byte* ptempbuff = (byte*)malloc(sz+20);
	int paddsize = in[sz - 1];
	ST_DATA_16 randome = {0,};
	print_bin("real in in ", in + 16, sz - 16 - 1 - paddsize - 32);
	int reta = g3api_tls_mac_encrypt((ST_TLS_INTER_HEADER_WITHOUT_SIZE*)_inner, (ST_IV*)_st_iv.client_iv, 
		(ST_DATA_16*)&randome, in + 16, sz - 16 - 1 - paddsize - 32, ptempbuff, &outsize);
	
	print_bin("g3api_tls_mac_encrypt ptempbuff key", ptempbuff, outsize);
	memcpy(out, ptempbuff, outsize);

	memcpy(&_st_iv.client_iv, &ptempbuff[outsize-1-16],16);
	return reta;
	int ret = _wc_ecc_functions_org.pf_wc_AesCbcEncrypt(aes, out, in, sz);

	print_bin("pf_wc_AesCbcEncrypt out", out, sz);
	return ret;
}

int wc_AesCbcDecrypt_new(Aes*  aes, byte*  out, const byte*  in, word32 sz)
{
	byte tmppubkey[16];
	word32 tmppubkey_size = 16;
	memcpy(tmppubkey, aes->key, tmppubkey_size);
	print_bin("wc_AesCbcDecrypt_new key", tmppubkey, tmppubkey_size);
	
	//return ret;

	int outsize = sz + 20;
	byte* ptempbuff = (byte*)malloc(sz + 20);
	memcpy(ptempbuff,in,sz);

	int ret = 0;
	
	#ifdef USE_ORG_DEC
	ret = _wc_ecc_functions_org.pf_wc_AesCbcDecrypt(aes, out, in, sz);
	#else
	int reta = g3api_tls_decrypt_verify((ST_TLS_INTER_HEADER_WITHOUT_SIZE*)_inner, (ST_IV*)_st_iv.server_iv,
		in, sz,
		(ST_DATA_16*)ptempbuff,
		ptempbuff + 16, &outsize);

	_ret_verify = reta == 1 ? -1 : reta;


	print_bin("wc_AesCbcDecrypt_new ptempbuff", ptempbuff, outsize + 16);

	_pad_size = 16 - outsize % 16 - 1;
	
	memcpy(out, ptempbuff,sz);

	memcpy(&_st_iv.server_iv, &in[sz - 1 - 16], 16);
	out[sz - 1] = _pad_size;
	ret = reta;
	#endif
	
	print_bin("wc_AesCbcDecrypt_new out", out, sz);

	return ret;
	
}


void neo_api_change_4_key_exchange_new(byte*   out, word32   outLen)
{
	byte tmpprvkey[32];
	word32 tmpprvkey_size = 32;
	//ecc_Key_to_private(key, tmpprvkey);
	//print_bin("neo_api_export_4_key_exchange_new FUCK private_key", tmpprvkey, 32);
	print_bin("neo_api_export_4_key_exchange_new  pub key", out, outLen);
	//memcpy(&out[1], &_st_ecc_public, sizeof(ST_ECC_PUBLIC));
	print_bin("neo_api_export_4_key_exchange_new mypub pub key", out, outLen);




}


void neo_api_set_inner_header_new(const byte*    innerheader, word32   innerheader_size)
{
	print_bin("neo_api_set_inner_header_new innerheader", innerheader, innerheader_size);
	memcpy(_inner, innerheader, innerheader_size);
}

void neo_api_set_sc_random_new(const byte*    client_random, const byte*    server_random)
{
	print_bin("neo_api_set_sc_random_new client_random", client_random, 32);
	print_bin("neo_api_set_sc_random_new server_random", server_random, 32);
	//memcpy(_st_ecdh_random.server, server_random, 32);
	//memcpy(_st_ecdh_random.client, client_random, 32);

}

void neo_api_change_iv_new(byte*    client_iv, byte*    server_iv)
{
	print_bin("neo_api_change_iv_new client_iv", client_iv, 16);
	print_bin("neo_api_change_iv_new server_iv", server_iv, 16);
	/*memcpy(client_iv, _st_iv.client_iv, 16);
	memcpy(server_iv, _st_iv.server_iv, 32);*/
	
}


int neo_api_verify_mac_new(WOLFSSL* ssl, int ssl_ret)
{
	fprintf(stderr, "ssl->keys.padSz:%d\n", ssl->keys.padSz);

#ifdef USE_ORG_DEC
	return ssl_ret;
#endif
	ssl->keys.padSz = 0x20+_pad_size+1;
	return _ret_verify;
}

int neo_ssl_client_hello_new(const byte * random)
{
	print_bin("neo_ssl_client_hello_new random", random, 32);
	
	memcpy(_st_ecdh_random.client, random, 32);
	return 0;
}
int neo_ssl_server_hello_new(const byte * random)
{
	print_bin("neo_ssl_server_hello_new random", random, 32);
	memcpy(_st_ecdh_random.server, random, 32);
	return 0;
}
int neo_ssl_server_certificate_set_ecdsa_pubkey_new(const byte* pubkey_asn1, int size)
{
	print_bin("neo_ssl_server_certificate_set_ecdsa_pubkey_new pubkey_asn1", pubkey_asn1, size);
	
	memcpy(&_st_public_ecdsa_key, &pubkey_asn1[1], size - 1);

	return 0;
}
int neo_ssl_server_certificate_verify_new(const byte* cert_pubkey_asn1, int pub_size, const byte * hash_cert, const byte * sign_asn1, int sign_size, int * pverify)
{
	print_bin("neo_ssl_server_certificate_verify_new cert_pubkey_asn1", cert_pubkey_asn1, pub_size);
	print_bin("neo_ssl_server_certificate_verify_new hash_cert", hash_cert, 32);
	print_bin("neo_ssl_server_certificate_verify_new sign_asn1", sign_asn1, sign_size);
	ST_ECC_PUBLIC st_ecc_public_4_verify;
	memcpy(&st_ecc_public_4_verify, &cert_pubkey_asn1[1], pub_size - 1);

	return verify_hash_with_extern_pubkey_with_g3(&st_ecc_public_4_verify, hash_cert, sign_asn1, sign_size, pverify);


}

int neo_ssl_server_key_exchange_set_peer_pubkey_new(const byte* peer_pubkey_asn1, int pub_size)
{
	print_bin("neo_ssl_server_certificate_verify_new peer_pubkey_asn1", peer_pubkey_asn1, pub_size);
	memcpy(&_st_public_peer_key, &peer_pubkey_asn1[1], pub_size - 1);
	return 0;
}

int neo_ssl_server_key_exchange_verify_new(const byte* hash, const byte * sign_asn1, int sign_size, int* pverify)
{
	print_bin("neo_ssl_server_key_exchange_verify_new hash", hash, 32);
	print_bin("neo_ssl_server_key_exchange_verify_new sign_asn1", sign_asn1, sign_size);
	print_bin("neo_ssl_server_key_exchange_verify_new _st_public_ecdsa_key", &_st_public_ecdsa_key, sizeof(ST_ECC_PUBLIC));

	return verify_hash_with_extern_pubkey_with_g3(&_st_public_ecdsa_key, hash, sign_asn1, sign_size, pverify);
}


int neo_ssl_client_certificate_verify_sign_new(const byte * hash, byte* sign, int* psign_size)
{
	print_bin("neo_ssl_client_certificate_verify_sign_new hash", hash, 32);

	ST_SIGN_ECDSA signecdsa = { 0, };
	int ret = g3api_sign(KEY_SECTOR_DEVICE_PRV_KEY, EN_SIGN_OPTION::SIGN_ECDSA_EXT_SHA256, hash, 32, &signecdsa, sizeof(ST_SIGN_ECDSA));


	//byte sign64[64] = { 0, };
	byte signasn1[80] = { 0. };
	word32 signasn1len = 80;

	//int err = make_sign_asn1_to_sign_64(out, *outlen, sign64);
	print_bin("sign64 ", (const unsigned char*)&signecdsa, sizeof(ST_SIGN_ECDSA));

	int err = make_sign_64_to_sign_asn1((const byte*)&signecdsa, sign,(word32*) psign_size);

	/*int err = make_sign_64_to_sign_asn1((const byte*)&signecdsa, out, outlen);
	print_bin("signasn1 ", signasn1, signasn1len);*/


	//int ret_api = g3api_verify(KEY_SECTOR_DEVICE_PUB_KEY, EN_VERIFY_OPTION::VERYFY_ECDSA_EXT_SHA256, in, inlen, sign64, 64);

	//printf("0x%x \n", ret_api);
	print_bin("neo_ssl_client_certificate_verify_sign_new sign", sign, *psign_size);



	return ret;
}
int neo_ssl_client_key_exchange_new(byte* chip_peer_pubkey, int* ppub_key)
{


	
	ST_ECDH_KEY_BLOCK st_ecdh_key_block;

	//_st_public_ecdsa_key

	//g3api_ecdh(EN_ECDH_MODE::NORMAL_ECDH, &_st_public_peer_key, 64, NULL, &_st_chip_public_peer_key, &_st_ecdh_pre_master_secret, sizeof(ST_ECDH_PRE_MASTER_SECRET));
	//g3api_ecdh(EN_ECDH_MODE::GEN_TLS_BLOCK, &_st_public_peer_key, 64, &_st_ecdh_random, &_st_chip_public_peer_key, &st_ecdh_key_block, sizeof(ST_ECDH_KEY_BLOCK));
	g3api_ecdh(EN_ECDH_MODE::SET_TLS_SESSION_KEY, &_st_public_peer_key, 64, &_st_ecdh_random, &_st_chip_public_peer_key, &_st_iv, sizeof(ST_ECDH_IV));



	print_bin("_st_public_ecdsa_key", &_st_public_peer_key, sizeof(ST_ECC_PUBLIC));
	print_bin("_st_chip_public_peer_key", &_st_chip_public_peer_key, sizeof(ST_ECC_PUBLIC));
	print_bin("_st_iv", &_st_iv, sizeof(ST_ECDH_IV));
	print_bin("st_ecdh_key_block", &st_ecdh_key_block, sizeof(ST_ECDH_KEY_BLOCK));

	print_bin("st_ecdh_pre_master_secret", &_st_ecdh_pre_master_secret, sizeof(ST_ECDH_PRE_MASTER_SECRET));
	//int ret = _wc_ecc_functions_org.pf_wc_ecc_shared_secret(private_key, public_key, out, outlen);
	chip_peer_pubkey[0] = 0x04;
	memcpy(chip_peer_pubkey + 1, &_st_chip_public_peer_key, sizeof(ST_ECC_PUBLIC));
	*ppub_key = sizeof(ST_ECC_PUBLIC)+1;
	//int ret = _wc_ecc_functions_org.pf_wc_ecc_shared_secret(private_key, public_key, out, outlen);
	print_bin("neo_ssl_client_key_exchange_new FUCK chip_peer_pubkey", chip_peer_pubkey, *ppub_key);


	return 0;
}
int neo_ssl_client_key_exchange_export_premaster_key_new(byte* pre_master_key, int* pkey_size)
{
	//memcpy(pre_master_key, &_st_ecdh_pre_master_secret, sizeof(ST_ECDH_PRE_MASTER_SECRET));
	*pkey_size = sizeof(ST_ECDH_PRE_MASTER_SECRET);
	return 0;
}
int neo_ssl_client_do_finish_set_handshake_hash_new(const byte * hash)
{
	print_bin("neo_ssl_client_do_finish_set_handshake_hash_new", hash, 32);
	memcpy(&hand_shake_hash, hash, sizeof(ST_DATA_32));
	
	return 0;
}


extern "C" int p_hash(byte* result, word32 resLen, const byte* secret,
	word32 secLen, const byte* seed, word32 seedLen, int hash,
	void* heap, int devId);


int neo_ssl_client_do_finish_encyrpt_new(const byte * header, int header_size, byte* out, int* pout_size)
{
	print_bin("neo_ssl_client_do_finish_encyrpt_new header", header, header_size);
	


	return 0;
}

int neo_ssl_do_finish_get_prf_new(const char* label, const byte * hand_shake_hash, byte* prf, int* pprf_size)
{
	fprintf(stderr, "neo_ssl_do_finish_get_prf_new %s %d\n", label, *pprf_size);
	print_bin("neo_ssl_do_finish_get_prf_new hand_shake_hash", hand_shake_hash, 32);
	ST_TLS_HAND_HANDSHAKE_DIGEST st_tls_hand_handshake_digest;

#if 0






	byte seed[128];
	byte master_secret[48];
	byte keyblock[128];
	_st_ecdh_random.client;
	_st_ecdh_random.server;
	const char * lable = "master secret";
	int lable_len = strlen(lable);
	memcpy(seed, lable, lable_len);
	memcpy(seed + lable_len, &_st_ecdh_random.client, 32);
	memcpy(seed + lable_len + 32, &_st_ecdh_random.server, 32);

	print_bin("neo_ssl_do_finish_get_prf_new seed", seed, lable_len + 32 + 32);

	p_hash(master_secret, 48,
		(const byte*)&_st_ecdh_pre_master_secret, sizeof(_st_ecdh_pre_master_secret),
		seed, lable_len + 32 + 32,
		sha256_mac, 0, 0);
	print_bin("neo_ssl_do_finish_get_prf_new master_secret", master_secret, 48);

	lable = "key expansion";
	lable_len = strlen(lable);
	memcpy(seed, lable, lable_len);
	memcpy(seed + lable_len, &_st_ecdh_random.server, 32);
	memcpy(seed + lable_len + 32, &_st_ecdh_random.client, 32);
	print_bin("neo_ssl_do_finish_get_prf_new seed", seed, lable_len + 32 + 32);
	p_hash(keyblock, 128,
		(const byte*)master_secret, sizeof(master_secret),
		seed, lable_len + 32 + 32,
		sha256_mac, 0, 0);
	print_bin("neo_ssl_do_finish_get_prf_new keyblock", keyblock, 128);

	lable = label;
	lable_len = strlen(lable);
	memcpy(seed, lable, lable_len);
	memcpy(seed + lable_len, hand_shake_hash, 32);

	print_bin("neo_ssl_do_finish_get_prf_new seed", seed, lable_len + 32);

	p_hash(prf, 12,
		(const byte*)master_secret, sizeof(master_secret),
		seed, lable_len + 32,
		sha256_mac, 0, 0);
	print_bin("neo_ssl_do_finish_get_prf_new keyblock", prf, 12);
#endif // 0

	EN_HANDSHAKE_MODE mode;
	if (!strcmp(label, "client finished")){
		mode = EN_HANDSHAKE_MODE::HSM_CLIENT;
	}
	else if (!strcmp(label, "server finished")){
		mode = EN_HANDSHAKE_MODE::HSM_SERVER;
	}
	else {
		return -1;
	}


	int ret = g3api_tls_get_handshake_digest(mode, (ST_DATA_32*)hand_shake_hash, &st_tls_hand_handshake_digest);
	print_bin("neo_ssl_do_finish_get_prf_new st_tls_hand_handshake_digest", &st_tls_hand_handshake_digest, sizeof(ST_TLS_HAND_HANDSHAKE_DIGEST));

	memcpy(prf, &st_tls_hand_handshake_digest, sizeof(ST_TLS_HAND_HANDSHAKE_DIGEST));
	*pprf_size = sizeof(st_tls_hand_handshake_digest);
	
	return ret;
}
int neo_ssl_import_cert_new(int cert_type, byte* cert, int* pcert_size)
{
	int cert_index = -1;
	switch (cert_type)
	{
	case CERT_TYPE:
		cert_index = 1;
		break;
	case CA_TYPE:
		cert_index = 0;
		break;

	default:
		return -1;

	}
	
	ST_RW_DATA st_rwdata;
	g3api_read_key_value(0, EN_AREA_TYPE::DATA_AREA_1, EN_RW_INST_OPTION::PLAIN_TEXT, &st_rwdata, sizeof(ST_RW_DATA));
	print_bin("neo_ssl_import_cert_new st_rwdata", &st_rwdata, sizeof(ST_RW_DATA));
	CERTINFO *certinfo = (CERTINFO *)&st_rwdata;

	fprintf(stderr, "CERTINFO %d \n", sizeof(CERTINFO));
	for (int i = 0; i < 8; i++){
		
		fprintf(stderr, "CERT %d %d %d \n", certinfo[i].type, certinfo[i].stindex, certinfo[i].size);
	}
	CERTINFO *pcertinfo = &certinfo[cert_index];

	*pcert_size = pcertinfo->size;
	if (!cert) return 0;
	;
	int slot_size = (int)(pcertinfo->size / 32) +1;


	byte *pbytre = cert;
	int remain_size = pcertinfo->size;
	for (int i = 0; i < slot_size; i++){

		ST_RW_DATA st_temptdata;
		int realdata = min(remain_size, 32);
		if (realdata <= 0) break;
		g3api_read_key_value(pcertinfo->stindex+i, EN_AREA_TYPE::DATA_AREA_1, EN_RW_INST_OPTION::PLAIN_TEXT, &st_temptdata, sizeof(ST_RW_DATA));
		memcpy(pbytre, &st_temptdata, realdata);
		print_bin("neo_ssl_import_cert_new st_temptdata", &st_temptdata, sizeof(ST_RW_DATA));
		pbytre += 32;
		remain_size -=32 ;
	}
	print_bin("neo_ssl_import_cert_new cert", cert, pcertinfo->size);



	return 0;
}
//START DEF_NEW_EMPTY
int neo_ssl_init_new(WOLFSSL* ssl)
{
	return 0;
}

int neo_ssl_client_certificate_new(const byte * hash_cert,byte * sign_asn1,int * psign_size)
{
	return 0;
}
int neo_ssl_client_application_data_new(const byte * orgmsg,byte* out,int* pout_size)
{
	return 0;
}
int neo_ssl_server_application_data_new(const byte * orgmsg,byte* out,int* pout_size)
{
	return 0;
}
//END DEF_NEW_EMPTY




int wc_ecc_verify_hash_new(const byte*  sig, word32 siglen, const byte*  hash, word32 hashlen, int*  stat, ecc_key*  key)
{
	return 0;
	//PRT_TITLE prttitle("wc_ecc_verify_hash");
#if 0
	key->pubkey;

	byte tmppubkey[65];
	word32 tmppubkey_size = 65;

	//_wc_ecc_functions_org.pf_wc_ecc_export_x963(key, tmppubkey, &tmppubkey_size);
	//ecc_Key_to_public(key, tmppubkey);

	print_bin("FUCK sig", sig, siglen);
	print_bin("FUCK hash", hash, hashlen);
	print_bin("FUCK _st_ecc_public_4_verify", &_st_ecc_public_4_verify, sizeof(ST_ECC_PUBLIC));
	byte sign64[64] = { 0, };
	int err = make_sign_asn1_to_sign_64(sig, siglen, sign64);
	print_bin("sign64 ", sign64, 64);
	ST_DATA_32 st_data_32;
	g3api_set_extern_public_key(&_st_ecc_public_4_verify, sizeof(ST_ECC_PUBLIC), &st_data_32);


	int ret_api = g3api_verify(KEY_SECTOR_DEVICE_PUB_KEY, EN_VERIFY_OPTION::VERYFY_EXT_PUB_ECDSA_EXT_SHA256, hash, hashlen, sign64, 64);

	printf("0x%x \n", ret_api);

	*stat = (ret_api == 0);


	//int ret = _wc_ecc_functions_org.pf_wc_ecc_verify_hash(sig, siglen, hash, hashlen, stat, key);
	return ret_api <0 ? ret_api : 0;
#endif
}





int wc_ecc_sign_hash_new(const byte*  in, word32 inlen, byte*  out, word32 * outlen, WC_RNG*  rng, ecc_key*  key)
{

	return 0;
#if 0
	print_bin("FUCK hash in", in, inlen);

	int ret = _wc_ecc_functions_org.pf_wc_ecc_sign_hash(in, inlen, out, outlen, rng, key);
	ST_SIGN_ECDSA signecdsa = { 0, };
	g3api_sign(KEY_SECTOR_DEVICE_PRV_KEY, EN_SIGN_OPTION::SIGN_ECDSA_EXT_SHA256, in, inlen, &signecdsa, sizeof(ST_SIGN_ECDSA));


	//byte sign64[64] = { 0, };
	byte signasn1[80] = { 0. };
	word32 signasn1len = 80;

	//int err = make_sign_asn1_to_sign_64(out, *outlen, sign64);
	print_bin("sign64 ", (const unsigned char*)&signecdsa, sizeof(ST_SIGN_ECDSA));

	/*int err = make_sign_64_to_sign_asn1((const byte*)&signecdsa, out, outlen);
	print_bin("signasn1 ", signasn1, signasn1len);*/


	//int ret_api = g3api_verify(KEY_SECTOR_DEVICE_PUB_KEY, EN_VERIFY_OPTION::VERYFY_ECDSA_EXT_SHA256, in, inlen, sign64, 64);

	//printf("0x%x \n", ret_api);

	print_bin("FUCK out", out, *outlen);
	return ret;
#endif

}


int wc_ecc_import_x963_new(const byte*   in, word32 inLen, ecc_key*   key)
{
	print_bin("FUCK pubkey", in, inLen);


	//memcpy(&_st_ecc_public_4_verify, &in[1], inLen - 1);
	//int ret = _wc_ecc_functions_org.pf_wc_ecc_import_x963(in, inLen, key);

	return 0;
}
int wc_ecc_import_x963_ex_new(const byte*  in, word32 inLen, ecc_key*  key, int curve_id)
{
	return wc_ecc_import_x963_new(in, inLen, key);

}

int wc_ecc_shared_secret_new(ecc_key*   private_key, ecc_key*   public_key, byte*   out, word32*   outlen)
{
	return 0;
#if 0

	byte tmppubkey[65];
	word32 tmppubkey_size = 65;
	byte tmpprvkey[32];
	word32 tmpprvkey_size = 32;

	ST_ECDH_PRE_MASTER_SECRET st_ecdh_pre_master_secret;
	ST_ECDH_KEY_BLOCK st_ecdh_key_block;
	ecc_Key_to_public(public_key, tmppubkey);
	print_bin("wc_ecc_shared_secret_new FUCK public_key", tmppubkey, 64);
	ecc_Key_to_private(private_key, tmpprvkey);
	print_bin("wc_ecc_shared_secret_new FUCK private_key", tmpprvkey, 32);



	g3api_ecdh(EN_ECDH_MODE::NORMAL_ECDH, tmppubkey, 64, NULL, &_st_ecc_public, &st_ecdh_pre_master_secret, sizeof(ST_ECDH_PRE_MASTER_SECRET));
	g3api_ecdh(EN_ECDH_MODE::GEN_TLS_BLOCK, tmppubkey, 64, &_st_ecdh_random, &_st_ecc_public, &st_ecdh_key_block, sizeof(ST_ECDH_KEY_BLOCK));

	g3api_ecdh(EN_ECDH_MODE::SET_TLS_SESSION_KEY, tmppubkey, 64, &_st_ecdh_random, &_st_ecc_public, &_st_iv, sizeof(ST_ECDH_IV));



	print_bin("st_ecc_public", &_st_ecc_public, sizeof(ST_ECC_PUBLIC));
	print_bin("_st_iv", &_st_iv, sizeof(ST_ECDH_IV));
	print_bin("st_ecdh_key_block", &st_ecdh_key_block, sizeof(ST_ECDH_KEY_BLOCK));

	print_bin("st_ecdh_pre_master_secret", &st_ecdh_pre_master_secret, sizeof(ST_ECDH_PRE_MASTER_SECRET));
	//int ret = _wc_ecc_functions_org.pf_wc_ecc_shared_secret(private_key, public_key, out, outlen);
	memcpy(out, &st_ecdh_pre_master_secret, sizeof(ST_ECDH_PRE_MASTER_SECRET));
	*outlen = sizeof(ST_ECDH_PRE_MASTER_SECRET);
	//int ret = _wc_ecc_functions_org.pf_wc_ecc_shared_secret(private_key, public_key, out, outlen);
	print_bin("wc_ecc_shared_secret_new FUCK out", out, *outlen);

#endif // 0

	return 0;
}