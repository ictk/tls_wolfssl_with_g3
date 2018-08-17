
###############################################
# neo_wolf_ssl
###############################################


#------------------------------------------------------------------------#
# main definition
#------------------------------------------------------------------------#
#CC = gcc
#CXX = g++
#AR = ar

CC = gcc
CXX = g++
AR = ar


LD = $(CXX)

TITLE=neo_wolf_ssl

PLATFORM=

#------------------------------------------------------------------------#
# directory definition
#------------------------------------------------------------------------#
OUT_DIR = examples/reflib/gnu-armhf
#example : ../lib/gnu
REF_DIR = 
DST_DIR = $(HOME)/project
#example : /usr/local

DST_DIR_LIB = $(DST_DIR)/lib
DST_DIR_INC = $(DST_DIR)/include
#/$(TITLE)

#------------------------------------------------------------------------#
# result definition
#------------------------------------------------------------------------#
OUT_STATIC_LIB = $(OUT_DIR)/lib$(TITLE).a
OUT_SHARED_LIB = $(OUT_DIR)/lib$(TITLE).so
OUT_EXE = $(OUT_DIR)/$(TITLE)


#------------------------------------------------------------------------#
# flag definition
#------------------------------------------------------------------------#
INC = -Iinclude -I.
#example : -IAAA -IBBB

CDEFINE=-D_USE_UTF8_ -DNEOUSEMBCS -DNEO_STATIC -DLSA_EXPORTS_NOUSE -DWOLFSSL_USER_SETTINGS_ -DCYASSL_USER_SETTINGS -DHAVE_ECC -DBUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 -DDEBUG_WOLFSSL -DHAVE_COMP_KEY -DNO_RSA -DNO_MD4 -DNO_OLD_TLS -DNO_DH -DNO_DSA -DNO_MD5 -DNO_PWDBASED -DNO_RABBIT -DNO_SHA
#example -DBBBB -DCCCCCC

CFLAGS=-Wall -O2 -fPIC -Wl,-Bsymbolic -std=gnu++11
#example -Wall -O2 -fPIC -Wl,-Bsymbolic -std=gnu++11

LDFLAGS = -shared -fPIC  -L../lib/gnu -ldl
#example -shared -fPIC  -L../lib/gnu -ldl

CFLAG_ALL = $(INC) $(CDEFINE) $(CFLAGS)

#------------------------------------------------------------------------#
# object directory definition
#------------------------------------------------------------------------#

OBJDIR_SRC_CPP = obj/gnu_src_cpp

OBJDIR_SRC_C = obj/gnu_src_c

OBJDIR_WOLFCRYPT_SRC_C = obj/gnu_wolfcrypt_src_c

#example
#OBJDIR_OBJ0 = obj/gnu_obj0
#OBJDIR_OBJ1 = obj/gnu_obj1

DEF_RELEASE_INC= ../include


#------------------------------------------------------------------------#
# object set definition
#------------------------------------------------------------------------#

OBJ_SET_SRC_CPP =  $(OBJDIR_SRC_CPP)/debug_util.o  $(OBJDIR_SRC_CPP)/user_bypass.o 

OBJ_SET_SRC_C =  $(OBJDIR_SRC_C)/internal.o  $(OBJDIR_SRC_C)/wolfio.o  $(OBJDIR_SRC_C)/keys.o  $(OBJDIR_SRC_C)/ssl.o  $(OBJDIR_SRC_C)/tls.o 

OBJ_SET_WOLFCRYPT_SRC_C =  $(OBJDIR_WOLFCRYPT_SRC_C)/aes.o  $(OBJDIR_WOLFCRYPT_SRC_C)/arc4.o  $(OBJDIR_WOLFCRYPT_SRC_C)/asn.o  $(OBJDIR_WOLFCRYPT_SRC_C)/coding.o  $(OBJDIR_WOLFCRYPT_SRC_C)/des3.o  $(OBJDIR_WOLFCRYPT_SRC_C)/ecc_empty.o  $(OBJDIR_WOLFCRYPT_SRC_C)/error.o  $(OBJDIR_WOLFCRYPT_SRC_C)/hash.o  $(OBJDIR_WOLFCRYPT_SRC_C)/hmac.o  $(OBJDIR_WOLFCRYPT_SRC_C)/integer.o  $(OBJDIR_WOLFCRYPT_SRC_C)/logging.o  $(OBJDIR_WOLFCRYPT_SRC_C)/memory.o  $(OBJDIR_WOLFCRYPT_SRC_C)/rabbit.o  $(OBJDIR_WOLFCRYPT_SRC_C)/random.o  $(OBJDIR_WOLFCRYPT_SRC_C)/ripemd.o  $(OBJDIR_WOLFCRYPT_SRC_C)/sha256.o  $(OBJDIR_WOLFCRYPT_SRC_C)/signature.o  $(OBJDIR_WOLFCRYPT_SRC_C)/wc_encrypt.o  $(OBJDIR_WOLFCRYPT_SRC_C)/wc_port.o  $(OBJDIR_WOLFCRYPT_SRC_C)/wolfmath.o 

#example OBJ_SET_OBJ0 =  $(OBJDIR)/CSerialRS232.o  $(OBJDIR)/EtcModule.o  $(OBJDIR)/MemoryNode.o  $(OBJDIR)/NeoCoLib.o 



	
#------------------------------------------------------------------------#
# all object definition
#------------------------------------------------------------------------#		
OBJ_SET_ALL =  $(OBJ_SET_SRC_CPP) $(OBJ_SET_SRC_C) $(OBJ_SET_WOLFCRYPT_SRC_C)   
#example OBJ_SET_ALL =  $(OBJ_SET_OBJ0) $(OBJ_SET_OBJ1) $(OBJ_SET_OBJ2)


#------------------------------------------------------------------------#
# command option definition
#------------------------------------------------------------------------#		

all: static share
install:  lib_install share_install

clean: clean_release 

before_release: 
	test -d bin/Release || mkdir -p bin/Release
	test -d $(OUT_DIR) || mkdir -p $(OUT_DIR)
	test -d $(OBJDIR_SRC_CPP) || mkdir -p $(OBJDIR_SRC_CPP)
	test -d $(OBJDIR_SRC_C) || mkdir -p $(OBJDIR_SRC_C)
	test -d $(OBJDIR_WOLFCRYPT_SRC_C) || mkdir -p $(OBJDIR_WOLFCRYPT_SRC_C)
	

	


after_release: 
	echo 'none'
	#mkdir -p ../include
	#cp -pr ../include/*.h $(DST_DIR)/include
	
before_install: 
	test -d $(DST_DIR_LIB) || mkdir -p $(DST_DIR_LIB)
	test -d $(DST_DIR_INC) || mkdir -p $(DST_DIR_INC)
	

	

static: before_release out_release after_release
share: before_release out_shared_release after_release
exe: before_release out_exe_release after_release


lib_install:before_install 
	test -d $(OUT_STATIC_LIB) || cp -p $(OUT_STATIC_LIB)  $(DST_DIR_LIB)

	
share_install:before_install 
	test -d $(OUT_SHARED_LIB) ||cp -p $(OUT_SHARED_LIB)  $(DST_DIR_LIB)
	#ldconfig
	#ln -s $(OUT_SHARED_RELEASE) $(OUT_SHARED_RELEASE).0.0.1

		

out_release: $(OBJ_SET_ALL)
	$(AR) rcs $(OUT_STATIC_LIB) $(OBJ_SET_ALL) $(LIB)
	
	
out_shared_release: $(OBJ_SET_ALL)
	echo $(OUT_SHARED_RELEASE)
	echo $(LDFLAGS)
	$(CXX)  --shared $(LDFLAGS) -o $(OUT_SHARED_LIB) $(OBJ_SET_ALL) $(LIB)
	#cp -p $(OUT_SHARED_RELEASE)  $(DST_DIR_LIB)

out_exe_release: $(OBJ_SET_ALL)
	echo $(OUT_SHARED_RELEASE)
	echo $(LDFLAGS)
	$(CXX)  $(LDFLAGS) -o $(OUT_EXE) $(OBJ_SET_ALL) $(LIB)

	
$(OBJDIR_SRC_CPP)/%.o: src/%.cpp
	$(CXX) $(CFLAG_ALL)  -c -o $@ $<	
	
$(OBJDIR_SRC_C)/%.o: src/%.c
	$(CC) $(CFLAG_ALL)  -c -o $@ $<	
	
$(OBJDIR_WOLFCRYPT_SRC_C)/%.o: wolfcrypt/src/%.c
	$(CC) $(CFLAG_ALL)  -c -o $@ $<	
	
	
	

clean_release: 
	rm -f $(OBJ_SET_ALL)
	rm -f $(OBJDIR)


.PHONY: before_debug after_debug clean_debug before_release after_release clean_release

