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
const char*  wc_ecc_get_name_org(int curve_id);
int ecc_projective_add_point_org(ecc_point* P,ecc_point* Q,ecc_point* R,mp_int* a,mp_int* modulus,mp_digit mp);
int ecc_projective_dbl_point_org(ecc_point* P,ecc_point* R,mp_int* a,mp_int* modulus,mp_digit mp);
int wc_ecc_make_key_org(WC_RNG* rng,int keysize,ecc_key* key);
int wc_ecc_make_key_ex_org(WC_RNG* rng,int keysize,ecc_key* key,int curve_id);
int wc_ecc_make_pub_org(ecc_key* key,ecc_point* pubOut);
int wc_ecc_check_key_org(ecc_key* key);
int wc_ecc_is_point_org(ecc_point* ecp,mp_int* a,mp_int* b,mp_int* prime);
int wc_ecc_shared_secret_org(ecc_key* private_key,ecc_key* public_key,byte* out,word32* outlen);
int wc_ecc_shared_secret_gen_org(ecc_key* private_key,ecc_point* point,byte* out,word32 * outlen);
int wc_ecc_shared_secret_ex_org(ecc_key* private_key,ecc_point* point,byte* out,word32 * outlen);
int wc_ecc_sign_hash_org(const byte* in,word32 inlen,byte* out,word32 * outlen,WC_RNG* rng,ecc_key* key);
int wc_ecc_sign_hash_ex_org(const byte* in,word32 inlen,WC_RNG* rng,ecc_key* key,mp_int * r,mp_int * s);
int wc_ecc_verify_hash_org(const byte* sig,word32 siglen,const byte* hash,word32 hashlen,int* stat,ecc_key* key);
int wc_ecc_verify_hash_ex_org(mp_int * r,mp_int * s,const byte* hash,word32 hashlen,int* stat,ecc_key* key);
int wc_ecc_init_org(ecc_key* key);
int wc_ecc_init_ex_org(ecc_key* key,void* heap,int devId);
void wc_ecc_free_org(ecc_key* key);
int wc_ecc_set_flags_org(ecc_key* key,word32 flags);
int wc_ecc_set_curve_org(ecc_key* key,int keysize,int curve_id);
int wc_ecc_is_valid_idx_org(int n);
int wc_ecc_get_curve_idx_org(int curve_id);
int wc_ecc_get_curve_id_org(int curve_idx);
int wc_ecc_get_curve_size_from_id_org(int curve_id);
int wc_ecc_get_curve_idx_from_name_org(const char* curveName);
int wc_ecc_get_curve_size_from_name_org(const char* curveName);
int wc_ecc_get_curve_id_from_name_org(const char* curveName);
int wc_ecc_get_curve_id_from_params_org(int fieldSize,const byte* prime,word32 primeSz,const byte* Af,word32 AfSz,const byte* Bf,word32 BfSz,const byte* order,word32 orderSz,const byte* Gx,word32 GxSz,const byte* Gy,word32 GySz,int cofactor);
ecc_point*  wc_ecc_new_point_org();
ecc_point*  wc_ecc_new_point_h_org(void* h);
void wc_ecc_del_point_org(ecc_point* p);
void wc_ecc_del_point_h_org(ecc_point* p,void* h);
int wc_ecc_copy_point_org(ecc_point* p,ecc_point * r);
int wc_ecc_cmp_point_org(ecc_point* a,ecc_point * b);
int wc_ecc_point_is_at_infinity_org(ecc_point * p);
int wc_ecc_mulmod_org(mp_int* k,ecc_point * G,ecc_point * R,mp_int* a,mp_int* modulus,int map);
int wc_ecc_mulmod_ex_org(mp_int* k,ecc_point * G,ecc_point * R,mp_int* a,mp_int* modulus,int map,void* heap);
int wc_ecc_export_x963_org(ecc_key* key,byte* out,word32* outLen);
int wc_ecc_export_x963_ex_org(ecc_key* key,byte* out,word32* outLen,int compressed);
int wc_ecc_import_x963_org(const byte* in,word32 inLen,ecc_key* key);
int wc_ecc_import_x963_ex_org(const byte* in,word32 inLen,ecc_key* key,int curve_id);
int wc_ecc_import_private_key_org(const byte* priv,word32 privSz,const byte* pub,word32 pubSz,ecc_key* key);
int wc_ecc_import_private_key_ex_org(const byte* priv,word32 privSz,const byte* pub,word32 pubSz,ecc_key* key,int curve_id);
int wc_ecc_rs_to_sig_org(const char* r,const char* s,byte* out,word32* outlen);
int wc_ecc_sig_to_rs_org(const byte* sig,word32 sigLen,byte* r,word32* rLen,byte* s,word32* sLen);
int wc_ecc_import_raw_org(ecc_key* key,const char* qx,const char* qy,const char* d,const char* curveName);
int wc_ecc_import_raw_ex_org(ecc_key* key,const char* qx,const char* qy,const char* d,int curve_id);
int wc_ecc_export_private_only_org(ecc_key* key,byte* out,word32* outLen);
int wc_ecc_export_public_raw_org(ecc_key* key,byte* qx,word32* qxLen,byte* qy,word32* qyLen);
int wc_ecc_export_private_raw_org(ecc_key* key,byte* qx,word32* qxLen,byte* qy,word32* qyLen,byte* d,word32* dLen);
int wc_ecc_export_point_der_org(const int curve_idx,ecc_point* point,byte* out,word32* outLen);
int wc_ecc_import_point_der_org(byte* in,word32 inLen,const int curve_idx,ecc_point* point);
int wc_ecc_size_org(ecc_key* key);
int wc_ecc_sig_size_org(ecc_key* key);
int wc_ecc_get_oid_org(word32 oidSum,const byte* * oid,word32* oidSz);
int wc_AesCbcEncrypt_org(Aes* aes,byte* out,const byte* in,word32 sz);
int wc_AesCbcDecrypt_org(Aes* aes,byte* out,const byte* in,word32 sz);
void neo_api_change_4_key_exchange_org(byte* out,word32 outLen);
void neo_api_set_inner_header_org(const byte* innerheader,word32 innerheader_size);
void neo_api_set_sc_random_org(const byte* client_random,const byte* server_random);
void neo_api_change_iv_org(byte* client_iv,byte* server_iv);
int neo_api_verify_mac_org(WOLFSSL* ssl,int ssl_ret);
int neo_ssl_init_org(WOLFSSL* ssl);
int neo_ssl_client_hello_org(const byte * random);
int neo_ssl_server_hello_org(const byte * random);
int neo_ssl_server_certificate_set_ecdsa_pubkey_org(const byte* pubkey_asn1,int size);
int neo_ssl_server_certificate_verify_org(const byte* cert_pubkey_asn1,int pub_size,const byte * hash_cert,const byte * sign_asn1,int sign_size,int * pverify);
int neo_ssl_server_key_exchange_set_peer_pubkey_org(const byte* peer_pubkey_asn1,int pub_size);
int neo_ssl_server_key_exchange_verify_org(const byte* hash,const byte * sign_asn1,int sign_size,int* pverify);
int neo_ssl_client_certificate_org(const byte * hash_cert,byte * sign_asn1,int * psign_size);
int neo_ssl_client_key_exchange_org(byte* chip_peer_pubkey,int* ppub_key);
int neo_ssl_client_key_exchange_export_premaster_key_org(byte* pre_master_key,int* pkey_size);
int neo_ssl_client_certificate_verify_sign_org(const byte * hash,byte* sign,int* psign_size);
int neo_ssl_client_encrypted_handshake_message_org(const byte * hash,byte* out,int* pout_size);
int neo_ssl_server_encrypted_handshake_message_org(const byte * hash);
int neo_ssl_client_application_data_org(const byte * orgmsg,byte* out,int* pout_size);
int neo_ssl_server_application_data_org(const byte * orgmsg,byte* out,int* pout_size);
//END ECC_ORG_DEC
}

ST_WC_ECC_FUNCTIONS _wc_ecc_functions = {
	//START SET_ECC_ORG_DEC
	wc_ecc_get_name_org,
	ecc_projective_add_point_org,
	ecc_projective_dbl_point_org,
	wc_ecc_make_key_org,
	wc_ecc_make_key_ex_org,
	wc_ecc_make_pub_org,
	wc_ecc_check_key_org,
	wc_ecc_is_point_org,
	wc_ecc_shared_secret_org,
	wc_ecc_shared_secret_gen_org,
	wc_ecc_shared_secret_ex_org,
	wc_ecc_sign_hash_org,
	wc_ecc_sign_hash_ex_org,
	wc_ecc_verify_hash_org,
	wc_ecc_verify_hash_ex_org,
	wc_ecc_init_org,
	wc_ecc_init_ex_org,
	wc_ecc_free_org,
	wc_ecc_set_flags_org,
	wc_ecc_set_curve_org,
	wc_ecc_is_valid_idx_org,
	wc_ecc_get_curve_idx_org,
	wc_ecc_get_curve_id_org,
	wc_ecc_get_curve_size_from_id_org,
	wc_ecc_get_curve_idx_from_name_org,
	wc_ecc_get_curve_size_from_name_org,
	wc_ecc_get_curve_id_from_name_org,
	wc_ecc_get_curve_id_from_params_org,
	wc_ecc_new_point_org,
	wc_ecc_new_point_h_org,
	wc_ecc_del_point_org,
	wc_ecc_del_point_h_org,
	wc_ecc_copy_point_org,
	wc_ecc_cmp_point_org,
	wc_ecc_point_is_at_infinity_org,
	wc_ecc_mulmod_org,
	wc_ecc_mulmod_ex_org,
	wc_ecc_export_x963_org,
	wc_ecc_export_x963_ex_org,
	wc_ecc_import_x963_org,
	wc_ecc_import_x963_ex_org,
	wc_ecc_import_private_key_org,
	wc_ecc_import_private_key_ex_org,
	wc_ecc_rs_to_sig_org,
	wc_ecc_sig_to_rs_org,
	wc_ecc_import_raw_org,
	wc_ecc_import_raw_ex_org,
	wc_ecc_export_private_only_org,
	wc_ecc_export_public_raw_org,
	wc_ecc_export_private_raw_org,
	wc_ecc_export_point_der_org,
	wc_ecc_import_point_der_org,
	wc_ecc_size_org,
	wc_ecc_sig_size_org,
	wc_ecc_get_oid_org,
	wc_AesCbcEncrypt_org,
	wc_AesCbcDecrypt_org,
	neo_api_change_4_key_exchange_org,
	neo_api_set_inner_header_org,
	neo_api_set_sc_random_org,
	neo_api_change_iv_org,
	neo_api_verify_mac_org,
	neo_ssl_init_org,
	neo_ssl_client_hello_org,
	neo_ssl_server_hello_org,
	neo_ssl_server_certificate_set_ecdsa_pubkey_org,
	neo_ssl_server_certificate_verify_org,
	neo_ssl_server_key_exchange_set_peer_pubkey_org,
	neo_ssl_server_key_exchange_verify_org,
	neo_ssl_client_certificate_org,
	neo_ssl_client_key_exchange_org,
	neo_ssl_client_key_exchange_export_premaster_key_org,
	neo_ssl_client_certificate_verify_sign_org,
	neo_ssl_client_encrypted_handshake_message_org,
	neo_ssl_server_encrypted_handshake_message_org,
	neo_ssl_client_application_data_org,
	neo_ssl_server_application_data_org,
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
	_wc_ecc_functions.pf_wc_ecc_sign_hash = wc_ecc_sign_hash;
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
void neo_api_change_4_key_exchange_org(byte* out,word32 outLen)
{

}
void neo_api_set_inner_header_org(const byte* innerheader,word32 innerheader_size)
{

}
void neo_api_set_sc_random_org(const byte* client_random,const byte* server_random)
{

}
void neo_api_change_iv_org(byte* client_iv,byte* server_iv)
{

}
int neo_api_verify_mac_org(WOLFSSL* ssl,int ssl_ret)
{
	return 0;
}
int neo_ssl_init_org(WOLFSSL* ssl)
{
	return 0;
}
int neo_ssl_client_hello_org(const byte * random)
{
	return 0;
}
int neo_ssl_server_hello_org(const byte * random)
{
	return 0;
}
int neo_ssl_server_certificate_set_ecdsa_pubkey_org(const byte* pubkey_asn1,int size)
{
	return 0;
}
int neo_ssl_server_certificate_verify_org(const byte* cert_pubkey_asn1,int pub_size,const byte * hash_cert,const byte * sign_asn1,int sign_size,int * pverify)
{
	return 0;
}
int neo_ssl_server_key_exchange_set_peer_pubkey_org(const byte* peer_pubkey_asn1,int pub_size)
{
	return 0;
}
int neo_ssl_server_key_exchange_verify_org(const byte* hash,const byte * sign_asn1,int sign_size,int* pverify)
{
	return 0;
}
int neo_ssl_client_certificate_org(const byte * hash_cert,byte * sign_asn1,int * psign_size)
{
	return 0;
}
int neo_ssl_client_key_exchange_org(byte* chip_peer_pubkey,int* ppub_key)
{
	return 0;
}
int neo_ssl_client_key_exchange_export_premaster_key_org(byte* pre_master_key,int* pkey_size)
{
	return 0;
}
int neo_ssl_client_certificate_verify_sign_org(const byte * hash,byte* sign,int* psign_size)
{
	return 0;
}
int neo_ssl_client_encrypted_handshake_message_org(const byte * hash,byte* out,int* pout_size)
{
	return 0;
}
int neo_ssl_server_encrypted_handshake_message_org(const byte * hash)
{
	return 0;
}
int neo_ssl_client_application_data_org(const byte * orgmsg,byte* out,int* pout_size)
{
	return 0;
}
int neo_ssl_server_application_data_org(const byte * orgmsg,byte* out,int* pout_size)
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
const char*  wc_ecc_get_name(int curve_id)
{
	PRT_TITLE prttitle("wc_ecc_get_name");
	const char*  ret = _cur_pwc_ecc_functions->pf_wc_ecc_get_name(curve_id);
	return ret;
}
int ecc_projective_add_point(ecc_point* P,ecc_point* Q,ecc_point* R,mp_int* a,mp_int* modulus,mp_digit mp)
{
	PRT_TITLE prttitle("ecc_projective_add_point");
	int ret = _cur_pwc_ecc_functions->pf_ecc_projective_add_point(P,Q,R,a,modulus,mp);
	return ret;
}
int ecc_projective_dbl_point(ecc_point* P,ecc_point* R,mp_int* a,mp_int* modulus,mp_digit mp)
{
	PRT_TITLE prttitle("ecc_projective_dbl_point");
	int ret = _cur_pwc_ecc_functions->pf_ecc_projective_dbl_point(P,R,a,modulus,mp);
	return ret;
}
int wc_ecc_make_key(WC_RNG* rng,int keysize,ecc_key* key)
{
	PRT_TITLE prttitle("wc_ecc_make_key");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_make_key(rng,keysize,key);
	return ret;
}
int wc_ecc_make_key_ex(WC_RNG* rng,int keysize,ecc_key* key,int curve_id)
{
	PRT_TITLE prttitle("wc_ecc_make_key_ex");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_make_key_ex(rng,keysize,key,curve_id);
	return ret;
}
int wc_ecc_make_pub(ecc_key* key,ecc_point* pubOut)
{
	PRT_TITLE prttitle("wc_ecc_make_pub");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_make_pub(key,pubOut);
	return ret;
}
int wc_ecc_check_key(ecc_key* key)
{
	PRT_TITLE prttitle("wc_ecc_check_key");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_check_key(key);
	return ret;
}
int wc_ecc_is_point(ecc_point* ecp,mp_int* a,mp_int* b,mp_int* prime)
{
	PRT_TITLE prttitle("wc_ecc_is_point");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_is_point(ecp,a,b,prime);
	return ret;
}
int wc_ecc_shared_secret(ecc_key* private_key,ecc_key* public_key,byte* out,word32* outlen)
{
	PRT_TITLE prttitle("wc_ecc_shared_secret");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_shared_secret(private_key,public_key,out,outlen);
	return ret;
}
int wc_ecc_shared_secret_gen(ecc_key* private_key,ecc_point* point,byte* out,word32 * outlen)
{
	PRT_TITLE prttitle("wc_ecc_shared_secret_gen");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_shared_secret_gen(private_key,point,out,outlen);
	return ret;
}
int wc_ecc_shared_secret_ex(ecc_key* private_key,ecc_point* point,byte* out,word32 * outlen)
{
	PRT_TITLE prttitle("wc_ecc_shared_secret_ex");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_shared_secret_ex(private_key,point,out,outlen);
	return ret;
}
int wc_ecc_sign_hash(const byte* in,word32 inlen,byte* out,word32 * outlen,WC_RNG* rng,ecc_key* key)
{
	PRT_TITLE prttitle("wc_ecc_sign_hash");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_sign_hash(in,inlen,out,outlen,rng,key);
	return ret;
}
int wc_ecc_sign_hash_ex(const byte* in,word32 inlen,WC_RNG* rng,ecc_key* key,mp_int * r,mp_int * s)
{
	PRT_TITLE prttitle("wc_ecc_sign_hash_ex");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_sign_hash_ex(in,inlen,rng,key,r,s);
	return ret;
}
int wc_ecc_verify_hash(const byte* sig,word32 siglen,const byte* hash,word32 hashlen,int* stat,ecc_key* key)
{
	PRT_TITLE prttitle("wc_ecc_verify_hash");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_verify_hash(sig,siglen,hash,hashlen,stat,key);
	return ret;
}
int wc_ecc_verify_hash_ex(mp_int * r,mp_int * s,const byte* hash,word32 hashlen,int* stat,ecc_key* key)
{
	PRT_TITLE prttitle("wc_ecc_verify_hash_ex");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_verify_hash_ex(r,s,hash,hashlen,stat,key);
	return ret;
}
int wc_ecc_init(ecc_key* key)
{
	PRT_TITLE prttitle("wc_ecc_init");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_init(key);
	return ret;
}
int wc_ecc_init_ex(ecc_key* key,void* heap,int devId)
{
	PRT_TITLE prttitle("wc_ecc_init_ex");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_init_ex(key,heap,devId);
	return ret;
}
void wc_ecc_free(ecc_key* key)
{
	PRT_TITLE prttitle("wc_ecc_free");
	_cur_pwc_ecc_functions->pf_wc_ecc_free(key);
}
int wc_ecc_set_flags(ecc_key* key,word32 flags)
{
	PRT_TITLE prttitle("wc_ecc_set_flags");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_set_flags(key,flags);
	return ret;
}
int wc_ecc_set_curve(ecc_key* key,int keysize,int curve_id)
{
	PRT_TITLE prttitle("wc_ecc_set_curve");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_set_curve(key,keysize,curve_id);
	return ret;
}
int wc_ecc_is_valid_idx(int n)
{
	PRT_TITLE prttitle("wc_ecc_is_valid_idx");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_is_valid_idx(n);
	return ret;
}
int wc_ecc_get_curve_idx(int curve_id)
{
	PRT_TITLE prttitle("wc_ecc_get_curve_idx");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_get_curve_idx(curve_id);
	return ret;
}
int wc_ecc_get_curve_id(int curve_idx)
{
	PRT_TITLE prttitle("wc_ecc_get_curve_id");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_get_curve_id(curve_idx);
	return ret;
}
int wc_ecc_get_curve_size_from_id(int curve_id)
{
	PRT_TITLE prttitle("wc_ecc_get_curve_size_from_id");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_get_curve_size_from_id(curve_id);
	return ret;
}
int wc_ecc_get_curve_idx_from_name(const char* curveName)
{
	PRT_TITLE prttitle("wc_ecc_get_curve_idx_from_name");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_get_curve_idx_from_name(curveName);
	return ret;
}
int wc_ecc_get_curve_size_from_name(const char* curveName)
{
	PRT_TITLE prttitle("wc_ecc_get_curve_size_from_name");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_get_curve_size_from_name(curveName);
	return ret;
}
int wc_ecc_get_curve_id_from_name(const char* curveName)
{
	PRT_TITLE prttitle("wc_ecc_get_curve_id_from_name");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_get_curve_id_from_name(curveName);
	return ret;
}
int wc_ecc_get_curve_id_from_params(int fieldSize,const byte* prime,word32 primeSz,const byte* Af,word32 AfSz,const byte* Bf,word32 BfSz,const byte* order,word32 orderSz,const byte* Gx,word32 GxSz,const byte* Gy,word32 GySz,int cofactor)
{
	PRT_TITLE prttitle("wc_ecc_get_curve_id_from_params");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_get_curve_id_from_params(fieldSize,prime,primeSz,Af,AfSz,Bf,BfSz,order,orderSz,Gx,GxSz,Gy,GySz,cofactor);
	return ret;
}
ecc_point*  wc_ecc_new_point()
{
	PRT_TITLE prttitle("wc_ecc_new_point");
	ecc_point*  ret = _cur_pwc_ecc_functions->pf_wc_ecc_new_point();
	return ret;
}
ecc_point*  wc_ecc_new_point_h(void* h)
{
	PRT_TITLE prttitle("wc_ecc_new_point_h");
	ecc_point*  ret = _cur_pwc_ecc_functions->pf_wc_ecc_new_point_h(h);
	return ret;
}
void wc_ecc_del_point(ecc_point* p)
{
	PRT_TITLE prttitle("wc_ecc_del_point");
	_cur_pwc_ecc_functions->pf_wc_ecc_del_point(p);
}
void wc_ecc_del_point_h(ecc_point* p,void* h)
{
	PRT_TITLE prttitle("wc_ecc_del_point_h");
	_cur_pwc_ecc_functions->pf_wc_ecc_del_point_h(p,h);
}
int wc_ecc_copy_point(ecc_point* p,ecc_point * r)
{
	PRT_TITLE prttitle("wc_ecc_copy_point");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_copy_point(p,r);
	return ret;
}
int wc_ecc_cmp_point(ecc_point* a,ecc_point * b)
{
	PRT_TITLE prttitle("wc_ecc_cmp_point");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_cmp_point(a,b);
	return ret;
}
int wc_ecc_point_is_at_infinity(ecc_point * p)
{
	PRT_TITLE prttitle("wc_ecc_point_is_at_infinity");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_point_is_at_infinity(p);
	return ret;
}
int wc_ecc_mulmod(mp_int* k,ecc_point * G,ecc_point * R,mp_int* a,mp_int* modulus,int map)
{
	PRT_TITLE prttitle("wc_ecc_mulmod");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_mulmod(k,G,R,a,modulus,map);
	return ret;
}
int wc_ecc_mulmod_ex(mp_int* k,ecc_point * G,ecc_point * R,mp_int* a,mp_int* modulus,int map,void* heap)
{
	PRT_TITLE prttitle("wc_ecc_mulmod_ex");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_mulmod_ex(k,G,R,a,modulus,map,heap);
	return ret;
}
int wc_ecc_export_x963(ecc_key* key,byte* out,word32* outLen)
{
	PRT_TITLE prttitle("wc_ecc_export_x963");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_export_x963(key,out,outLen);
	return ret;
}
int wc_ecc_export_x963_ex(ecc_key* key,byte* out,word32* outLen,int compressed)
{
	PRT_TITLE prttitle("wc_ecc_export_x963_ex");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_export_x963_ex(key,out,outLen,compressed);
	return ret;
}
int wc_ecc_import_x963(const byte* in,word32 inLen,ecc_key* key)
{
	PRT_TITLE prttitle("wc_ecc_import_x963");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_import_x963(in,inLen,key);
	return ret;
}
int wc_ecc_import_x963_ex(const byte* in,word32 inLen,ecc_key* key,int curve_id)
{
	PRT_TITLE prttitle("wc_ecc_import_x963_ex");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_import_x963_ex(in,inLen,key,curve_id);
	return ret;
}
int wc_ecc_import_private_key(const byte* priv,word32 privSz,const byte* pub,word32 pubSz,ecc_key* key)
{
	PRT_TITLE prttitle("wc_ecc_import_private_key");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_import_private_key(priv,privSz,pub,pubSz,key);
	return ret;
}
int wc_ecc_import_private_key_ex(const byte* priv,word32 privSz,const byte* pub,word32 pubSz,ecc_key* key,int curve_id)
{
	PRT_TITLE prttitle("wc_ecc_import_private_key_ex");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_import_private_key_ex(priv,privSz,pub,pubSz,key,curve_id);
	return ret;
}
int wc_ecc_rs_to_sig(const char* r,const char* s,byte* out,word32* outlen)
{
	PRT_TITLE prttitle("wc_ecc_rs_to_sig");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_rs_to_sig(r,s,out,outlen);
	return ret;
}
int wc_ecc_sig_to_rs(const byte* sig,word32 sigLen,byte* r,word32* rLen,byte* s,word32* sLen)
{
	PRT_TITLE prttitle("wc_ecc_sig_to_rs");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_sig_to_rs(sig,sigLen,r,rLen,s,sLen);
	return ret;
}
int wc_ecc_import_raw(ecc_key* key,const char* qx,const char* qy,const char* d,const char* curveName)
{
	PRT_TITLE prttitle("wc_ecc_import_raw");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_import_raw(key,qx,qy,d,curveName);
	return ret;
}
int wc_ecc_import_raw_ex(ecc_key* key,const char* qx,const char* qy,const char* d,int curve_id)
{
	PRT_TITLE prttitle("wc_ecc_import_raw_ex");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_import_raw_ex(key,qx,qy,d,curve_id);
	return ret;
}
int wc_ecc_export_private_only(ecc_key* key,byte* out,word32* outLen)
{
	PRT_TITLE prttitle("wc_ecc_export_private_only");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_export_private_only(key,out,outLen);
	return ret;
}
int wc_ecc_export_public_raw(ecc_key* key,byte* qx,word32* qxLen,byte* qy,word32* qyLen)
{
	PRT_TITLE prttitle("wc_ecc_export_public_raw");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_export_public_raw(key,qx,qxLen,qy,qyLen);
	return ret;
}
int wc_ecc_export_private_raw(ecc_key* key,byte* qx,word32* qxLen,byte* qy,word32* qyLen,byte* d,word32* dLen)
{
	PRT_TITLE prttitle("wc_ecc_export_private_raw");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_export_private_raw(key,qx,qxLen,qy,qyLen,d,dLen);
	return ret;
}
int wc_ecc_export_point_der(const int curve_idx,ecc_point* point,byte* out,word32* outLen)
{
	PRT_TITLE prttitle("wc_ecc_export_point_der");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_export_point_der(curve_idx,point,out,outLen);
	return ret;
}
int wc_ecc_import_point_der(byte* in,word32 inLen,const int curve_idx,ecc_point* point)
{
	PRT_TITLE prttitle("wc_ecc_import_point_der");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_import_point_der(in,inLen,curve_idx,point);
	return ret;
}
int wc_ecc_size(ecc_key* key)
{
	PRT_TITLE prttitle("wc_ecc_size");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_size(key);
	return ret;
}
int wc_ecc_sig_size(ecc_key* key)
{
	PRT_TITLE prttitle("wc_ecc_sig_size");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_sig_size(key);
	return ret;
}
int wc_ecc_get_oid(word32 oidSum,const byte* * oid,word32* oidSz)
{
	PRT_TITLE prttitle("wc_ecc_get_oid");
	int ret = _cur_pwc_ecc_functions->pf_wc_ecc_get_oid(oidSum,oid,oidSz);
	return ret;
}
int wc_AesCbcEncrypt(Aes* aes,byte* out,const byte* in,word32 sz)
{
	PRT_TITLE prttitle("wc_AesCbcEncrypt");
	int ret = _cur_pwc_ecc_functions->pf_wc_AesCbcEncrypt(aes,out,in,sz);
	return ret;
}
int wc_AesCbcDecrypt(Aes* aes,byte* out,const byte* in,word32 sz)
{
	PRT_TITLE prttitle("wc_AesCbcDecrypt");
	int ret = _cur_pwc_ecc_functions->pf_wc_AesCbcDecrypt(aes,out,in,sz);
	return ret;
}
void neo_api_change_4_key_exchange(byte* out,word32 outLen)
{
	PRT_TITLE prttitle("neo_api_change_4_key_exchange");
	_cur_pwc_ecc_functions->pf_neo_api_change_4_key_exchange(out,outLen);
}
void neo_api_set_inner_header(const byte* innerheader,word32 innerheader_size)
{
	PRT_TITLE prttitle("neo_api_set_inner_header");
	_cur_pwc_ecc_functions->pf_neo_api_set_inner_header(innerheader,innerheader_size);
}
void neo_api_set_sc_random(const byte* client_random,const byte* server_random)
{
	PRT_TITLE prttitle("neo_api_set_sc_random");
	_cur_pwc_ecc_functions->pf_neo_api_set_sc_random(client_random,server_random);
}
void neo_api_change_iv(byte* client_iv,byte* server_iv)
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
int neo_ssl_init(WOLFSSL* ssl)
{
	PRT_TITLE prttitle("neo_ssl_init");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_init(ssl);
	return ret;
}
int neo_ssl_client_hello(const byte * random)
{
	PRT_TITLE prttitle("neo_ssl_client_hello");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_client_hello(random);
	return ret;
}
int neo_ssl_server_hello(const byte * random)
{
	PRT_TITLE prttitle("neo_ssl_server_hello");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_server_hello(random);
	return ret;
}
int neo_ssl_server_certificate_set_ecdsa_pubkey(const byte* pubkey_asn1,int size)
{
	PRT_TITLE prttitle("neo_ssl_server_certificate_set_ecdsa_pubkey");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_server_certificate_set_ecdsa_pubkey(pubkey_asn1,size);
	return ret;
}
int neo_ssl_server_certificate_verify(const byte* cert_pubkey_asn1,int pub_size,const byte * hash_cert,const byte * sign_asn1,int sign_size,int * pverify)
{
	PRT_TITLE prttitle("neo_ssl_server_certificate_verify");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_server_certificate_verify(cert_pubkey_asn1,pub_size,hash_cert,sign_asn1,sign_size,pverify);
	return ret;
}
int neo_ssl_server_key_exchange_set_peer_pubkey(const byte* peer_pubkey_asn1,int pub_size)
{
	PRT_TITLE prttitle("neo_ssl_server_key_exchange_set_peer_pubkey");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_server_key_exchange_set_peer_pubkey(peer_pubkey_asn1,pub_size);
	return ret;
}
int neo_ssl_server_key_exchange_verify(const byte* hash,const byte * sign_asn1,int sign_size,int* pverify)
{
	PRT_TITLE prttitle("neo_ssl_server_key_exchange_verify");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_server_key_exchange_verify(hash,sign_asn1,sign_size,pverify);
	return ret;
}
int neo_ssl_client_certificate(const byte * hash_cert,byte * sign_asn1,int * psign_size)
{
	PRT_TITLE prttitle("neo_ssl_client_certificate");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_client_certificate(hash_cert,sign_asn1,psign_size);
	return ret;
}
int neo_ssl_client_key_exchange(byte* chip_peer_pubkey,int* ppub_key)
{
	PRT_TITLE prttitle("neo_ssl_client_key_exchange");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_client_key_exchange(chip_peer_pubkey,ppub_key);
	return ret;
}
int neo_ssl_client_key_exchange_export_premaster_key(byte* pre_master_key,int* pkey_size)
{
	PRT_TITLE prttitle("neo_ssl_client_key_exchange_export_premaster_key");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_client_key_exchange_export_premaster_key(pre_master_key,pkey_size);
	return ret;
}
int neo_ssl_client_certificate_verify_sign(const byte * hash,byte* sign,int* psign_size)
{
	PRT_TITLE prttitle("neo_ssl_client_certificate_verify_sign");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_client_certificate_verify_sign(hash,sign,psign_size);
	return ret;
}
int neo_ssl_client_encrypted_handshake_message(const byte * hash,byte* out,int* pout_size)
{
	PRT_TITLE prttitle("neo_ssl_client_encrypted_handshake_message");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_client_encrypted_handshake_message(hash,out,pout_size);
	return ret;
}
int neo_ssl_server_encrypted_handshake_message(const byte * hash)
{
	PRT_TITLE prttitle("neo_ssl_server_encrypted_handshake_message");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_server_encrypted_handshake_message(hash);
	return ret;
}
int neo_ssl_client_application_data(const byte * orgmsg,byte* out,int* pout_size)
{
	PRT_TITLE prttitle("neo_ssl_client_application_data");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_client_application_data(orgmsg,out,pout_size);
	return ret;
}
int neo_ssl_server_application_data(const byte * orgmsg,byte* out,int* pout_size)
{
	PRT_TITLE prttitle("neo_ssl_server_application_data");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_server_application_data(orgmsg,out,pout_size);
	return ret;
}
//END ECC_BYPASS

int neo_tls_init(WOLFSSL *ssl)
{
	return 0;
}



#endif /* HAVE_ECC */

