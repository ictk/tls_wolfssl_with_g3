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
int wc_ecc_verify_hash_new(const byte*  sig, word32 siglen, const byte*  hash, word32 hashlen, int*  stat, ecc_key*  key);
int wc_ecc_sign_hash_new(const byte*  in, word32 inlen, byte*  out, word32 * outlen, WC_RNG*  rng, ecc_key*  key);
int wc_ecc_import_x963_new(const byte*   in, word32 inLen, ecc_key*   key);
int wc_ecc_shared_secret_new(ecc_key*   private_key, ecc_key*   public_key, byte*   out, word32*   outlen);
int wc_AesCbcEncrypt_new(Aes*  aes, byte*  out, const byte*  in, word32 sz);
int wc_AesCbcDecrypt_new(Aes*  aes, byte*  out, const byte*  in, word32 sz);
int init_sample_ieb100cdc(void *param);
void neo_api_export_4_key_exchange_new( byte*   out, word32   outLen);

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
	wc_ecc_functions.pf_wc_ecc_shared_secret = wc_ecc_shared_secret_new;
	wc_ecc_functions.pf_wc_AesCbcDecrypt = wc_AesCbcDecrypt_new;
	wc_ecc_functions.pf_wc_AesCbcEncrypt = wc_AesCbcEncrypt_new;
	wc_ecc_functions.pf_neo_api_export_4_key_exchange = neo_api_export_4_key_exchange_new;
	
	
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

	_wc_ecc_functions_org.pf_wc_ecc_export_x963(key, tmppubkey, &tmppubkey_size);

	print_bin("FUCK sig", sig, siglen);
	print_bin("FUCK hash", hash, hashlen);
	print_bin("FUCK tmppubkey", tmppubkey, tmppubkey_size);
	byte sign64[64] = { 0, };
	int err = make_sign_asn1_to_sign_64(sig, siglen, sign64);
	print_bin("sign64 ", sign64, 64);
	ST_DATA_32 st_data_32;
	g3api_set_extern_public_key(tmppubkey + 1, tmppubkey_size - 1, &st_data_32);


	int ret_api = g3api_verify(KEY_SECTOR_DEVICE_PUB_KEY, EN_VERIFY_OPTION::VERYFY_EXT_PUB_ECDSA_EXT_SHA256, hash, hashlen, sign64, 64);

	printf("0x%x \n", ret_api);


	int ret = _wc_ecc_functions_org.pf_wc_ecc_verify_hash(sig, siglen, hash, hashlen, stat, key);
	return ret;
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
	
	

	int ret = _wc_ecc_functions_org.pf_wc_ecc_import_x963(in, inLen, key);

	return ret;
}

int wc_ecc_shared_secret_new(ecc_key*   private_key, ecc_key*   public_key, byte*   out, word32*   outlen)
{
	byte tmppubkey[65];
	word32 tmppubkey_size = 65;
	byte tmpprvkey[32];
	word32 tmpprvkey_size = 32;
	ST_ECC_PUBLIC st_ecc_public;
	ST_ECDH_PRE_MASTER_SECRET st_ecdh_pre_master_secret;
	ecc_Key_to_public(public_key, tmppubkey);
	print_bin("wc_ecc_shared_secret_new FUCK public_key", tmppubkey, 64);
	ecc_Key_to_private(private_key, tmpprvkey);
	print_bin("wc_ecc_shared_secret_new FUCK private_key", tmpprvkey, 32);
	g3api_ecdh(EN_ECDH_MODE::NORMAL_ECDH, &tmppubkey[1], 64, NULL, &st_ecc_public, &st_ecdh_pre_master_secret, sizeof(ST_ECDH_PRE_MASTER_SECRET));
	
	print_bin("st_ecc_public", &st_ecc_public, sizeof(ST_ECC_PUBLIC));

	print_bin("st_ecdh_pre_master_secret", &st_ecdh_pre_master_secret, sizeof(ST_ECDH_PRE_MASTER_SECRET));

	int ret = _wc_ecc_functions_org.pf_wc_ecc_shared_secret(private_key, public_key, out, outlen);
	print_bin("wc_ecc_shared_secret_new FUCK out", out, *outlen);

	return ret;
}

int wc_AesCbcEncrypt_new(Aes*  aes, byte*  out, const byte*  in, word32 sz)
{
	
	byte tmppubkey[16];
	word32 tmppubkey_size = 16;
	memcpy(tmppubkey, aes->key, tmppubkey_size);
	
	dword_reverse(tmppubkey, tmppubkey_size);
	print_bin("wc_AesCbcEncrypt_new key", tmppubkey, tmppubkey_size);

	int ret = _wc_ecc_functions_org.pf_wc_AesCbcEncrypt(aes, out, in, sz);
	return ret;
}

int wc_AesCbcDecrypt_new(Aes*  aes, byte*  out, const byte*  in, word32 sz)
{
	byte tmppubkey[16];
	word32 tmppubkey_size = 16;
	memcpy(tmppubkey, aes->key, tmppubkey_size);
	print_bin("wc_AesCbcDecrypt_new key", tmppubkey, tmppubkey_size);
	int ret = _wc_ecc_functions_org.pf_wc_AesCbcDecrypt(aes, out, in, sz);
	return ret;
}


void neo_api_export_4_key_exchange_new( byte*   out, word32   outLen)
{
	byte tmpprvkey[32];
	word32 tmpprvkey_size = 32;
	//ecc_Key_to_private(key, tmpprvkey);
	//print_bin("neo_api_export_4_key_exchange_new FUCK private_key", tmpprvkey, 32);
	print_bin("neo_api_export_4_key_exchange_new FUCK pub key", out, outLen);




}