/* ecc.c
*
* Copyright (C) 2006-2017 wolfSSL Inc.
*
* This file is part of wolfSSL.
*
* wolfSSL is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* wolfSSL is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
*/



#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* in case user set HAVE_ECC there */
#include <wolfssl/wolfcrypt/settings.h>
#include "wolfssl/debug_util.h"
#include "wolfssl/user_bypass.h"

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef HAVE_ECC

#include <wolfssl/wolfcrypt/ecc.h>
#include "wolfssl/user_bypass.h"
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/ssl.h>
#include <wolfssl/ssl.h>


#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>
extern "C" void test_g3_api()
{
	/*const char * aaa = g3api_get_lib_version();
	print_msg("g3api_get_lib_version",aaa);*/
	
}

	

#define TAG_ECC "\n*TAG_ECC:%s (size:%d):\n%s\n"
//print_bin_ext(TAG_ECC
#define TAG_ECC_TITLE_FMT "\n===================================\n@@@@@@@NEO_ECC_API:%s\n"
#define TAG_ECC_TITLE_FMT_LEAVE "END NEO_ECC_API:%s@@@@@@@\n===================================\n"
class PRT_TITLE
{
public:
	char m_title[64];
	PRT_TITLE(const char *title){
		strcpy(m_title, title);
		print_title_ext(TAG_ECC_TITLE_FMT, m_title);

	}
	~PRT_TITLE(){
		print_title_ext(TAG_ECC_TITLE_FMT_LEAVE, m_title);
	}

private:

};




extern "C"{
	//START ECC_ORG_DEC
int wc_ecc_shared_secret_org(ecc_key*   private_key,ecc_key*   public_key,byte*   out,word32*   outlen);
int wc_ecc_sign_hash_org(const byte*   in,word32 inlen,byte*   out,word32 *  outlen,WC_RNG*   rng,ecc_key*   key);
int wc_ecc_verify_hash_org(const byte*   sig,word32 siglen,const byte*   hash,word32 hashlen,int*   stat,ecc_key*   key);
int wc_ecc_export_x963_org(ecc_key*   key,byte*   out,word32*   outLen);
int wc_ecc_export_x963_ex_org(ecc_key*   key,byte*   out,word32*   outLen,int compressed);
int wc_ecc_import_x963_org(const byte*   in,word32 inLen,ecc_key*   key);
int wc_ecc_import_x963_ex_org(const byte*   in,word32 inLen,ecc_key*   key,int curve_id);
int wc_ecc_import_private_key_org(const byte*   priv,word32 privSz,const byte*   pub,word32 pubSz,ecc_key*   key);
int wc_ecc_import_private_key_ex_org(const byte*   priv,word32 privSz,const byte*   pub,word32 pubSz,ecc_key*   key,int curve_id);
int wc_AesCbcEncrypt_org(Aes*  aes,byte*  out,const byte*  in,word32 sz);
int wc_AesCbcDecrypt_org(Aes*  aes,byte*  out,const byte*  in,word32 sz);
void neo_api_change_4_key_exchange_org(byte*    out,word32   outLen);
void neo_api_set_inner_header_org(const byte*    innerheader,word32   innerheader_size);
void neo_api_set_sc_random_org(const byte*    client_random,const byte*    server_random);
void neo_api_change_iv_org(byte*    client_iv,byte*    server_iv);
int neo_api_verify_mac_org(WOLFSSL* ssl,int ssl_ret);
//END ECC_ORG_DEC
}

ST_WC_ECC_FUNCTIONS _wc_ecc_functions = {
	//START SET_ECC_ORG_DEC
	wc_ecc_shared_secret_org,
	wc_ecc_sign_hash_org,
	wc_ecc_verify_hash_org,
	wc_ecc_export_x963_org,
	wc_ecc_export_x963_ex_org,
	wc_ecc_import_x963_org,
	wc_ecc_import_x963_ex_org,
	wc_ecc_import_private_key_org,
	wc_ecc_import_private_key_ex_org,
	wc_AesCbcEncrypt_org,
	wc_AesCbcDecrypt_org,
	neo_api_change_4_key_exchange_org,
	neo_api_set_inner_header_org,
	neo_api_set_sc_random_org,
	neo_api_change_iv_org,
	neo_api_verify_mac_org,
//END SET_ECC_ORG_DEC




};


LPST_WC_ECC_FUNCTIONS _cur_pwc_ecc_functions = &_wc_ecc_functions;


void set_user_wc_ecc_functions(const LPST_WC_ECC_FUNCTIONS lpst_wc_ecc_functions)
{
	memcpy(&_wc_ecc_functions, lpst_wc_ecc_functions, sizeof(ST_WC_ECC_FUNCTIONS));
	//_ur_pwc_ecc_functions = lpst_wc_ecc_functions;
}

void  get_user_wc_ecc_functions(LPST_WC_ECC_FUNCTIONS lpst_wc_ecc_functions)
{
	memcpy(lpst_wc_ecc_functions, &_wc_ecc_functions, sizeof(ST_WC_ECC_FUNCTIONS));
}

int make_sign_64_to_sign_asn1(const byte*  sign64, byte*  signasn1, word32 *psignasn1len)
{

	int err;
	mp_int r_lcl, s_lcl;
	//err = wc_ecc_alloc_rs(NULL, &r, &s);
	memset(&r_lcl, 0, sizeof(mp_int));
	memset(&s_lcl, 0, sizeof(mp_int));

	if ((err = mp_init_multi(&r_lcl, &s_lcl, NULL, NULL, NULL, NULL)) != MP_OKAY){
		return err;
	}

	int size = mp_read_unsigned_bin(&r_lcl, sign64,32);
	//print_hexdumpbin("r just hex", buff, 32);

	//memset(buff, 0, 64);
	size = mp_read_unsigned_bin(&s_lcl, sign64 + 32, 32);
	//print_hexdumpbin("s just hex", buff, 32);


	err = StoreECC_DSA_Sig(signasn1, psignasn1len, &r_lcl, &s_lcl);


	mp_clear(&r_lcl);
	mp_clear(&s_lcl);
	return err;
}


int make_sign_asn1_to_sign_64(const byte*  signasn1, word32 signasn1len, byte*  sign64)
{

	int err;
	mp_int r_lcl, s_lcl;
	//err = wc_ecc_alloc_rs(NULL, &r, &s);
	memset(&r_lcl, 0, sizeof(mp_int));
	memset(&s_lcl, 0, sizeof(mp_int));

	
	err = DecodeECC_DSA_Sig(signasn1, signasn1len, &r_lcl, &s_lcl);

	int size = mp_to_unsigned_bin(&r_lcl, sign64);
	size = mp_to_unsigned_bin(&s_lcl, sign64 + 32);


	mp_clear(&r_lcl);
	mp_clear(&s_lcl);
	return err;
}


int ecc_Key_to_public( ecc_key* public_key, byte* out)
{

	if ( public_key == NULL || out == NULL ) {
		return ECC_BAD_ARG_E;
	}

	/* type valid? */
	/* Verify domain params supplied */
	if (wc_ecc_is_valid_idx(public_key->idx) == 0) {
		return ECC_BAD_ARG_E;
	}

	
	
	int tmppubkey_size = 0;
	


	tmppubkey_size = mp_unsigned_bin_size(public_key->pubkey.x);
	int ret = mp_to_unsigned_bin(public_key->pubkey.x, out);



	tmppubkey_size = mp_unsigned_bin_size(public_key->pubkey.y);
	ret = mp_to_unsigned_bin(public_key->pubkey.y, out + 32);

	
	
	return 0;
}

int ecc_Key_to_private(ecc_key* private_key, byte* out)
{
	print_title("wc_ecc_shared_secret_org");
	int err;

	if (private_key == NULL ||  out == NULL ) {
		return BAD_FUNC_ARG;
	}

	/* type valid? */
	if (private_key->type != ECC_PRIVATEKEY &&
		private_key->type != ECC_PRIVATEKEY_ONLY) {
		return ECC_BAD_ARG_E;
	}

	/* Verify domain params supplied */
	if (wc_ecc_is_valid_idx(private_key->idx) == 0 ) {
		return ECC_BAD_ARG_E;
	}

	/* Verify curve id matches */


	int tmppubkey_size = mp_unsigned_bin_size(&private_key->k);
	int ret = mp_to_unsigned_bin(&private_key->k, out);
	
	
	return 0;
}


void dword_reverse(byte * buff,int byte_size)
{
	ByteReverseWords((word32*)buff, (word32*)buff, byte_size);
}

#define SEQ_SZ 2
#define ENUM_LEN 1
#define VERSION_SZ 2


//START EMPTY_FUNCTION

void neo_api_change_4_key_exchange_org(byte*    out,word32   outLen)
{

}

void neo_api_set_inner_header_org(const byte*    innerheader,word32   innerheader_size)
{

}

void neo_api_set_sc_random_org(const byte*    client_random,const byte*    server_random)
{

}

void neo_api_change_iv_org(byte*    client_iv,byte*    server_iv)
{

}

int neo_api_verify_mac_org(WOLFSSL* ssl,int ssl_ret)
{
	return 0;
}
//END EMPTY_FUNCTION
int neo_api_verify_mac_org(int ssl_ret)
{
	return ssl_ret;
}


//
//
//int wc_ecc_verify_hash(const byte*  sig, word32 siglen, const byte*  hash, word32 hashlen, int*  stat, ecc_key*  key)
//{
//	PRT_TITLE prttitle("wc_ecc_verify_hash");
//	print_bin_ext(TAG_ECC, "sig", sig, siglen);
//	print_bin_ext(TAG_ECC, "hash", hash, hashlen);
//
//	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_verify_hash(sig, siglen, hash, hashlen, stat, key);
//	return ret;
//}
//
//int wc_ecc_export_x963_ex(ecc_key*  key, byte*  out, word32*  outLen, int compressed)
//{
//	PRT_TITLE prttitle("wc_ecc_export_x963_ex");
//	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_export_x963_ex(key, out, outLen, compressed);
//	print_bin_ext(TAG_ECC, "out", out, *outLen);
//	return ret;
//}
//
//
//
//
//
//int wc_ecc_sign_hash(const byte*  in,word32 inlen,byte*  out,word32 * outlen,WC_RNG*  rng,ecc_key*  key)
//{
//	PRT_TITLE prttitle("wc_ecc_sign_hash");
//
//	print_bin_ext(TAG_ECC,"in",in,  inlen);
//	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_sign_hash(in, inlen, out, outlen, rng, key);
//
//	print_bin_ext(TAG_ECC,"out", out, *outlen);
//	return ret;
//}
//
//
//
//
//int wc_ecc_import_x963_ex(const byte*  in,word32 inLen,ecc_key*  key,int curve_id)
//{
//	PRT_TITLE prttitle("wc_ecc_import_x963_ex");
//	
//	print_bin_ext(TAG_ECC,"in", in, inLen);
//	return  _cur_pwc_ecc_functions->pf_wc_ecc_import_x963_ex(in, inLen, key, curve_id);
//}
//
//
//int wc_ecc_import_private_key_ex(const byte*  priv,word32 privSz,const byte*  pub,word32 pubSz,ecc_key*  key,int curve_id)
//{
//	PRT_TITLE prttitle("wc_ecc_import_private_key_ex");
//	print_bin_ext(TAG_ECC,"priv", priv, privSz);
//	print_bin_ext(TAG_ECC,"pub", pub, pubSz);
//	return  _cur_pwc_ecc_functions->pf_wc_ecc_import_private_key_ex(priv, privSz, pub, pubSz, key, curve_id);
//}

//START ECC_BYPASS

int wc_ecc_shared_secret(ecc_key*   private_key,ecc_key*   public_key,byte*   out,word32*   outlen)
{
	PRT_TITLE prttitle("wc_ecc_shared_secret");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_shared_secret(private_key,public_key,out,outlen);
	return ret;
}

int wc_ecc_sign_hash(const byte*   in,word32 inlen,byte*   out,word32 *  outlen,WC_RNG*   rng,ecc_key*   key)
{
	PRT_TITLE prttitle("wc_ecc_sign_hash");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_sign_hash(in,inlen,out,outlen,rng,key);
	return ret;
}

int wc_ecc_verify_hash(const byte*   sig,word32 siglen,const byte*   hash,word32 hashlen,int*   stat,ecc_key*   key)
{
	PRT_TITLE prttitle("wc_ecc_verify_hash");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_verify_hash(sig,siglen,hash,hashlen,stat,key);
	return ret;
}

int wc_ecc_export_x963(ecc_key*   key,byte*   out,word32*   outLen)
{
	PRT_TITLE prttitle("wc_ecc_export_x963");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_export_x963(key,out,outLen);
	return ret;
}

int wc_ecc_export_x963_ex(ecc_key*   key,byte*   out,word32*   outLen,int compressed)
{
	PRT_TITLE prttitle("wc_ecc_export_x963_ex");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_export_x963_ex(key,out,outLen,compressed);
	return ret;
}

int wc_ecc_import_x963(const byte*   in,word32 inLen,ecc_key*   key)
{
	PRT_TITLE prttitle("wc_ecc_import_x963");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_import_x963(in,inLen,key);
	return ret;
}

int wc_ecc_import_x963_ex(const byte*   in,word32 inLen,ecc_key*   key,int curve_id)
{
	PRT_TITLE prttitle("wc_ecc_import_x963_ex");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_import_x963_ex(in,inLen,key,curve_id);
	return ret;
}

int wc_ecc_import_private_key(const byte*   priv,word32 privSz,const byte*   pub,word32 pubSz,ecc_key*   key)
{
	PRT_TITLE prttitle("wc_ecc_import_private_key");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_import_private_key(priv,privSz,pub,pubSz,key);
	return ret;
}

int wc_ecc_import_private_key_ex(const byte*   priv,word32 privSz,const byte*   pub,word32 pubSz,ecc_key*   key,int curve_id)
{
	PRT_TITLE prttitle("wc_ecc_import_private_key_ex");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_import_private_key_ex(priv,privSz,pub,pubSz,key,curve_id);
	return ret;
}

int wc_AesCbcEncrypt(Aes*  aes,byte*  out,const byte*  in,word32 sz)
{
	PRT_TITLE prttitle("wc_AesCbcEncrypt");
	int ret = _cur_pwc_ecc_functions->pf_wc_AesCbcEncrypt(aes,out,in,sz);
	return ret;
}

int wc_AesCbcDecrypt(Aes*  aes,byte*  out,const byte*  in,word32 sz)
{
	PRT_TITLE prttitle("wc_AesCbcDecrypt");
	int ret = _cur_pwc_ecc_functions->pf_wc_AesCbcDecrypt(aes,out,in,sz);
	return ret;
}

void neo_api_change_4_key_exchange(byte*    out,word32   outLen)
{
	PRT_TITLE prttitle("neo_api_change_4_key_exchange");
	_cur_pwc_ecc_functions->pf_neo_api_change_4_key_exchange(out,outLen);
}

void neo_api_set_inner_header(const byte*    innerheader,word32   innerheader_size)
{
	PRT_TITLE prttitle("neo_api_set_inner_header");
	_cur_pwc_ecc_functions->pf_neo_api_set_inner_header(innerheader,innerheader_size);
}

void neo_api_set_sc_random(const byte*    client_random,const byte*    server_random)
{
	PRT_TITLE prttitle("neo_api_set_sc_random");
	_cur_pwc_ecc_functions->pf_neo_api_set_sc_random(client_random,server_random);
}

void neo_api_change_iv(byte*    client_iv,byte*    server_iv)
{
	PRT_TITLE prttitle("neo_api_change_iv");
	_cur_pwc_ecc_functions->pf_neo_api_change_iv(client_iv,server_iv);
}

int neo_api_verify_mac(WOLFSSL* ssl,int ssl_ret)
{
	PRT_TITLE prttitle("neo_api_verify_mac");
	int ret = _cur_pwc_ecc_functions->pf_neo_api_verify_mac(ssl,ssl_ret);
	return ret;
}
//END ECC_BYPASS

int neo_tls_init(WOLFSSL *ssl)
{
	return 0;
}

#endif /* HAVE_ECC */