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

//START NEO_API_DEC
int wc_AesCbcEncrypt(Aes* aes,byte* out,const byte* in,word32 sz);
int wc_AesCbcDecrypt(Aes* aes,byte* out,const byte* in,word32 sz);
void neo_api_set_inner_header(const byte* innerheader,word32 innerheader_size);
int neo_api_verify_mac(int ssl_ret);
int neo_api_get_padsize(int * pad_size);
int neo_ssl_import_cert(int cert_type,byte* cert,int* pcert_size);
int neo_ssl_client_hello(const byte * random);
int neo_ssl_server_hello(const byte * random);
int neo_ssl_server_certificate_set_ecdsa_pubkey(const byte* pubkey_asn1,int size);
int neo_ssl_server_certificate_verify(const byte* cert_pubkey_asn1,int pub_size,const byte * hash_cert,const byte * sign_asn1,int sign_size,int * pverify);
int neo_ssl_server_key_exchange_set_peer_pubkey(const byte* peer_pubkey_asn1,int pub_size);
int neo_ssl_server_key_exchange_verify(const byte* hash,const byte * sign_asn1,int sign_size,int* pverify);
int neo_ssl_client_certificate(const byte * hash_cert,byte * sign_asn1,int * psign_size);
int neo_ssl_client_key_exchange(byte* chip_peer_pubkey,int* ppub_key);
int neo_ssl_client_key_exchange_export_premaster_key(byte* pre_master_key,int* pkey_size);
int neo_ssl_client_certificate_verify_sign(const byte * hash,byte* sign,int* psign_size);
int neo_ssl_do_finish_get_prf(const char* label,const byte * hand_shake_hash,byte* prf,int* pprf_size);
int neo_ssl_client_encrypt(const byte * orgmsg,byte* out,int* pout_size);
int neo_ssl_server_decrypt(const byte * orgmsg,byte* out,int* pout_size);
//END NEO_API_DEC
	
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
int neo_api_verify_mac_org(int ssl_ret);
int neo_api_get_padsize_org(int * pad_size);
int neo_ssl_init_org(WOLFSSL* ssl);
int neo_ssl_import_cert_org(int cert_type,byte* cert,int* pcert_size);
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
int neo_ssl_do_finish_get_prf_org(const char* label,const byte * hand_shake_hash,byte* prf,int* pprf_size);
int neo_ssl_client_encrypt_org(const byte * orgmsg,byte* out,int* pout_size);
int neo_ssl_server_decrypt_org(const byte * orgmsg,byte* out,int* pout_size);
//END ECC_ORG_DEC
}

ST_WC_ECC_FUNCTIONS _wc_ecc_functions = {
	//START SET_ECC_ORG_DEC
	wc_AesCbcEncrypt_org,
	wc_AesCbcDecrypt_org,
	neo_api_set_inner_header_org,
	neo_api_verify_mac_org,
	neo_api_get_padsize_org,
	neo_ssl_import_cert_org,
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
	neo_ssl_do_finish_get_prf_org,
	neo_ssl_client_encrypt_org,
	neo_ssl_server_decrypt_org,
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
	//_wc_ecc_functions.pf_wc_ecc_sign_hash = wc_ecc_sign_hash;
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
void neo_api_set_inner_header_org(const byte* innerheader,word32 innerheader_size)
{

}
int neo_api_verify_mac_org(int ssl_ret)
{
	return 0;
}
int neo_api_get_padsize_org(int * pad_size)
{
	return 0;
}
int neo_ssl_import_cert_org(int cert_type,byte* cert,int* pcert_size)
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
int neo_ssl_do_finish_get_prf_org(const char* label,const byte * hand_shake_hash,byte* prf,int* pprf_size)
{
	return 0;
}
int neo_ssl_client_encrypt_org(const byte * orgmsg,byte* out,int* pout_size)
{
	return 0;
}
int neo_ssl_server_decrypt_org(const byte * orgmsg,byte* out,int* pout_size)
{
	return 0;
}
//END EMPTY_FUNCTION


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


//START ECC_RETURN_EMPTY
//END ECC_RETURN_EMPTY


//START ECC_BYPASS
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
void neo_api_set_inner_header(const byte* innerheader,word32 innerheader_size)
{
	PRT_TITLE prttitle("neo_api_set_inner_header");
	_cur_pwc_ecc_functions->pf_neo_api_set_inner_header(innerheader,innerheader_size);
}
int neo_api_verify_mac(int ssl_ret)
{
	PRT_TITLE prttitle("neo_api_verify_mac");
	int ret = _cur_pwc_ecc_functions->pf_neo_api_verify_mac(ssl_ret);
	return ret;
}
int neo_api_get_padsize(int * pad_size)
{
	PRT_TITLE prttitle("neo_api_get_padsize");
	int ret = _cur_pwc_ecc_functions->pf_neo_api_get_padsize(pad_size);
	return ret;
}
int neo_ssl_import_cert(int cert_type,byte* cert,int* pcert_size)
{
	PRT_TITLE prttitle("neo_ssl_import_cert");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_import_cert(cert_type,cert,pcert_size);
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
int neo_ssl_do_finish_get_prf(const char* label,const byte * hand_shake_hash,byte* prf,int* pprf_size)
{
	PRT_TITLE prttitle("neo_ssl_do_finish_get_prf");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_do_finish_get_prf(label,hand_shake_hash,prf,pprf_size);
	return ret;
}
int neo_ssl_client_encrypt(const byte * orgmsg,byte* out,int* pout_size)
{
	PRT_TITLE prttitle("neo_ssl_client_encrypt");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_client_encrypt(orgmsg,out,pout_size);
	return ret;
}
int neo_ssl_server_decrypt(const byte * orgmsg,byte* out,int* pout_size)
{
	PRT_TITLE prttitle("neo_ssl_server_decrypt");
	int ret = _cur_pwc_ecc_functions->pf_neo_ssl_server_decrypt(orgmsg,out,pout_size);
	return ret;
}
//END ECC_BYPASS

int neo_tls_init(WOLFSSL *ssl)
{
	return 0;
}



#endif /* HAVE_ECC */

