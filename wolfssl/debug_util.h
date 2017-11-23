

#ifndef NEO_WOLFSSL_DEBUG_UTIL_H
#define NEO_WOLFSSL_DEBUG_UTIL_H

#ifndef __cplusplus
#define EXT_NEO_API
#else
#define EXT_NEO_API extern "C"
#endif

#ifdef __cplusplus
extern "C" {
#endif
	void print_bin(const char * title, const unsigned char * buff, int size);
	void print_hexdumpbin(const char * title, const unsigned char * buff, int size);
	void print_title(const char * title);
	void print_msg(const char * title, const char * msg);

#ifdef __cplusplus
}   /* extern "C" */
#endif

#endif //NEO_WOLFSSL_DEBUG_UTIL_H