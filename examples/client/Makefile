
###############################################
# neo_wolf_ssl
###############################################


#------------------------------------------------------------------------#
# main definition
#------------------------------------------------------------------------#
CC = gcc
CXX = g++
AR = ar
LD = $(CXX)

TITLE=neo_wolf_ssl



#------------------------------------------------------------------------#
# directory definition
#------------------------------------------------------------------------#
OUT_DIR = ../../bin
#example : ../lib/gnu

DST_DIR = /usr/local
#example : /usr/local

DST_DIR_LIB = $(DST_DIR)/lib
DST_DIR_INC = $(DST_DIR)/include/$(TITLE)

#------------------------------------------------------------------------#
# result definition
#------------------------------------------------------------------------#
OUT_STATIC_LIB = $(OUT_DIR)/lib$(TITLE).a
OUT_SHARED_LIB = $(OUT_DIR)/lib$(TITLE).so
OUT_EXE = $(OUT_DIR)/$(TITLE)


#------------------------------------------------------------------------#
# flag definition
#------------------------------------------------------------------------#
INC = -I../../ -I$(HOME)/project/include/g3_api_lib -I$(HOME)/project/include/neo_wolf_ssl -Ineo_c_lib -I.
#example : -IAAA -IBBB

CDEFINE=-D_USE_UTF8_ -DNEOUSEMBCS -DNEODEBUG -DNEO_STATIC -DLSA_EXPORTS_NOUSE  -DCYASSL_USER_SETTINGS -DDEBUG_WOLFSSL -DHAVE_ECC -DBUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 -DHAVE_COMP_KEY -DNO_OLD_TLS -DNO_DH -D__USEI2C__0 -D__USE_FT4222__
#example -DBBBB -DCCCCCC

CFLAGS=-Wall -O2 -fPIC -Wl,-Bsymbolic -std=gnu++11 -g -ggdb
#example -Wall -O2 -fPIC -Wl,-Bsymbolic -std=gnu++11

LDFLAGS = -fPIC  -L$(HOME)/project/lib  -ldl -lneo_c_lib -lneo_wolf_ssl -lg3_api_lib -lwiringPi -lft4222 -g -ggdb
#example -shared -fPIC  -L../lib/gnu -ldl

CFLAG_ALL = $(INC) $(CDEFINE) $(CFLAGS)

#------------------------------------------------------------------------#
# object directory definition
#------------------------------------------------------------------------#

OBJDIR___C = obj/gnu___c

OBJDIR___CPP = obj/gnu___cpp

#example
#OBJDIR_OBJ0 = obj/gnu_obj0
#OBJDIR_OBJ1 = obj/gnu_obj1

DEF_RELEASE_INC= ../include


#------------------------------------------------------------------------#
# object set definition
#------------------------------------------------------------------------#

OBJ_SET___C =  $(OBJDIR___C)/client.o 

OBJ_SET___CPP =  $(OBJDIR___CPP)/io_sample_cdc.o  $(OBJDIR___CPP)/io_sample_i2c.o  $(OBJDIR___CPP)/io_sample_ft4222.o  $(OBJDIR___CPP)/user_ecc_handling.o  $(OBJDIR___CPP)/util.o 

#example OBJ_SET_OBJ0 =  $(OBJDIR)/CSerialRS232.o  $(OBJDIR)/EtcModule.o  $(OBJDIR)/MemoryNode.o  $(OBJDIR)/NeoCoLib.o 



	
#------------------------------------------------------------------------#
# all object definition
#------------------------------------------------------------------------#		
OBJ_SET_ALL =  $(OBJ_SET___C) $(OBJ_SET___CPP)   
#example OBJ_SET_ALL =  $(OBJ_SET_OBJ0) $(OBJ_SET_OBJ1) $(OBJ_SET_OBJ2)


#------------------------------------------------------------------------#
# command option definition
#------------------------------------------------------------------------#		

all: exe
install:  lib_install share_install

clean: clean_release 

before_release: 
	test -d bin/Release || mkdir -p bin/Release
	test -d $(OUT_DIR) || mkdir -p $(OUT_DIR)
	test -d $(OBJDIR___C) || mkdir -p $(OBJDIR___C)
	test -d $(OBJDIR___CPP) || mkdir -p $(OBJDIR___CPP)
	

	


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

	
$(OBJDIR___C)/%.o: ./%.c
	$(CC) $(CFLAG_ALL)  -c -o $@ $<	
	
$(OBJDIR___CPP)/%.o: ./%.cpp
	$(CXX) $(CFLAG_ALL)  -c -o $@ $<	
	
	
	

clean_release: 
	rm -f $(OBJ_SET_ALL)
	rm -f $(OBJDIR)


.PHONY: before_debug after_debug clean_debug before_release after_release clean_release

