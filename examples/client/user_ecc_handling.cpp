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

int wc_ecc_verify_hash_new(const byte*  sig, word32 siglen, const byte*  hash, word32 hashlen, int*  stat, ecc_key*  key);
int wc_ecc_sign_hash_new(const byte*  in, word32 inlen, byte*  out, word32 * outlen, WC_RNG*  rng, ecc_key*  key);
int wc_ecc_import_x963_new(const byte*   in, word32 inLen, ecc_key*   key);
int wc_ecc_import_x963_ex_new(const byte*  in, word32 inLen, ecc_key*  key, int curve_id);
int wc_ecc_shared_secret_new(ecc_key*   private_key, ecc_key*   public_key, byte*   out, word32*   outlen);
int wc_AesCbcEncrypt_new(Aes*  aes, byte*  out, const byte*  in, word32 sz);
int wc_AesCbcDecrypt_new(Aes*  aes, byte*  out, const byte*  in, word32 sz);
int init_sample_ieb100cdc(void *param);
void neo_api_export_4_key_exchange_new( byte*   out, word32   outLen);
void neo_api_set_inner_header_new(const byte*    innerheader, word32   innerheader_size);
void neo_api_set_sc_random_new(const byte*    client_random, const byte*    server_random);
void neo_api_change_iv_new(byte*    client_iv, byte*    server_iv);
//int neo_api_verify_mac_new(int ssl_ret);
int neo_api_verify_mac_new(WOLFSSL* ssl, int ssl_ret);
//#define USE_ORG_DEC

ST_ECC_PUBLIC _st_ecc_public;
ST_ECDH_RANDOM _st_ecdh_random;
ST_ECDH_IV _st_iv;
byte _inner[WOLFSSL_TLS_HMAC_INNER_SZ];
int _ret_verify = 0;
int _pad_size = 0;
ST_ECC_PUBLIC _st_ecc_public_4_verify;





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
	wc_ecc_functions.pf_wc_ecc_verify_hash = wc_ecc_verify_hash_new;
	wc_ecc_functions.pf_wc_ecc_sign_hash = wc_ecc_sign_hash_new;
	wc_ecc_functions.pf_wc_ecc_import_x963 = wc_ecc_import_x963_new;
	wc_ecc_functions.pf_wc_ecc_import_x963_ex = wc_ecc_import_x963_ex_new;
	wc_ecc_functions.pf_wc_ecc_shared_secret = wc_ecc_shared_secret_new;
	wc_ecc_functions.pf_wc_AesCbcDecrypt = wc_AesCbcDecrypt_new;
	wc_ecc_functions.pf_wc_AesCbcEncrypt = wc_AesCbcEncrypt_new;
	wc_ecc_functions.pf_neo_api_change_4_key_exchange = neo_api_export_4_key_exchange_new;
	wc_ecc_functions.pf_neo_api_set_inner_header = neo_api_set_inner_header_new;
	wc_ecc_functions.pf_neo_api_set_sc_random = neo_api_set_sc_random_new;
	wc_ecc_functions.pf_neo_api_change_iv = neo_api_change_iv_new;
	wc_ecc_functions.pf_neo_api_verify_mac = neo_api_verify_mac_new;
	
	
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

int wc_ecc_verify_hash_new(const byte*  sig, word32 siglen, const byte*  hash, word32 hashlen, int*  stat, ecc_key*  key)
{
	//PRT_TITLE prttitle("wc_ecc_verify_hash");
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
	return ret_api <0 ? ret_api : 0 ;
}





int wc_ecc_sign_hash_new(const byte*  in, word32 inlen, byte*  out, word32 * outlen, WC_RNG*  rng, ecc_key*  key)
{


	print_bin( "FUCK hash in", in, inlen);

	int ret = _wc_ecc_functions_org.pf_wc_ecc_sign_hash(in, inlen, out, outlen, rng, key);
	ST_SIGN_ECDSA signecdsa = { 0, };
	g3api_sign(KEY_SECTOR_DEVICE_PRV_KEY, EN_SIGN_OPTION::SIGN_ECDSA_EXT_SHA256, in ,inlen, &signecdsa, sizeof(ST_SIGN_ECDSA));

	
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
}


int wc_ecc_import_x963_new(const byte*   in, word32 inLen, ecc_key*   key)
{
	print_bin("FUCK pubkey", in, inLen);
	
	
	memcpy(&_st_ecc_public_4_verify, &in[1], inLen - 1);
	//int ret = _wc_ecc_functions_org.pf_wc_ecc_import_x963(in, inLen, key);

	return 0;
}
int wc_ecc_import_x963_ex_new(const byte*  in, word32 inLen, ecc_key*  key, int curve_id)
{
	return wc_ecc_import_x963_new(in,inLen,key);

}
int wc_ecc_shared_secret_new(ecc_key*   private_key, ecc_key*   public_key, byte*   out, word32*   outlen)
{
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

	return 0;
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
	out[sz - 1] = _pad_size;
	ret = reta;
	#endif
	
	print_bin("wc_AesCbcDecrypt_new out", out, sz);

	return ret;
	
}


void neo_api_export_4_key_exchange_new( byte*   out, word32   outLen)
{
	byte tmpprvkey[32];
	word32 tmpprvkey_size = 32;
	//ecc_Key_to_private(key, tmpprvkey);
	//print_bin("neo_api_export_4_key_exchange_new FUCK private_key", tmpprvkey, 32);
	print_bin("neo_api_export_4_key_exchange_new  pub key", out, outLen);
	memcpy(&out[1], &_st_ecc_public, sizeof(ST_ECC_PUBLIC));
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
	memcpy(_st_ecdh_random.server, server_random, 32);
	memcpy(_st_ecdh_random.client, client_random, 32);

}

void neo_api_change_iv_new(byte*    client_iv, byte*    server_iv)
{
	print_bin("neo_api_change_iv_new client_iv", client_iv, 16);
	print_bin("neo_api_change_iv_new server_iv", server_iv, 16);
	memcpy(client_iv, _st_iv.client_iv, 16);
	memcpy(server_iv, _st_iv.server_iv, 32);
	
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