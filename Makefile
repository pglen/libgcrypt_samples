# These point to already built sub parts. Edit it if you move
# the files to a different directory.
# This is so one can use the parts without installation.

INC2=../../../libgpg-error-1.27/src 
INC3=../../src 
LIB2=../../src/.libs/ 
LIB3=../../../libgpg-error-1.27/src/.libs
LIB4= -l gcrypt -l gpg-error 
CC=gcc
OPT2=-I $(INC2) -I $(INC3) -L $(LIB2) -L $(LIB3) $(LIB4)

# This is to create templates for test expectations. We substitue memory 
# locations with zeros, so diff is happy

FILTER=sed s/0x[0-9A-F]*/0x00000000/g
ENCTEST=asencrypt.exe -i sample.txt -o sample.enc testkey.pub  
ENCTEST2=asdecrypt.exe -i sample.enc -o sample.dec -p 1111 testkey.key

.c.o: 
	$(CC) $(OPT2) -c $<  
    
OBJS =  base64.o gcry.o getpass.o zmalloc.o gsexp.o

all:  encrypt.exe keygen.exe encdec.exe asencrypt.exe asdecrypt.exe dump.exe
         
tests:  build_tests
	@echo Tests pass if diffs are silent.
	@test_base64a.exe > test.tmp
	@diff test_base64a.org test.tmp
	@test_base64.exe > test.tmp
	@diff test_base64.org test.tmp
	@test_zmalloc.exe | $(FILTER) > test.tmp
	@diff test_zmalloc.org test.tmp
	@$(ENCTEST); $(ENCTEST2)
	@diff sample.txt sample.dec
	@-rm test.tmp

build_tests: test_base64.exe test_base64a.exe  test_zmalloc.exe asencrypt.exe asdecrypt.exe

prep_tests:
	@test_base64.exe > test_base64.org
	@test_base64a.exe > test_base64a.org
	@test_zmalloc.exe | $(FILTER) > test_zmalloc.org
	$(ENCTEST) > enctest.org
              
encrypt.exe:  encrypt.c  zmalloc.c 
	$(CC) encrypt.c  $(OPT2) zmalloc.c -o encrypt

keygen.exe: $(OBJS) keygen.c
	$(CC) keygen.c $(OBJS) $(OPT2) -o keygen

encdec.exe: $(OBJS) encdec.c
	$(CC) encdec.c $(OBJS) $(OPT2) -o encdec

asencrypt.exe: $(OBJS) asencrypt.c
	$(CC) asencrypt.c $(OBJS) $(OPT2) -o asencrypt

asdecrypt.exe: $(OBJS) asdecrypt.c
	$(CC) asdecrypt.c $(OBJS) $(OPT2) -o asdecrypt

test_base64.exe:  test_base64.c  base64.c zmalloc.c 
	gcc test_base64.c  base64.c zmalloc.c -o test_base64 

test_base64a.exe:  test_base64a.c  base64.c zmalloc.c 
	gcc test_base64a.c  base64.c zmalloc.c -o test_base64a 

test_zmalloc.exe:  test_zmalloc.c  zmalloc.c 
	gcc test_zmalloc.c  zmalloc.c -o test_zmalloc

dump.exe:  $(OBJS) dump.c
	$(CC) dump.c  $(OBJS) $(OPT2) -o dump.exe

clean:
	@-rm aa.*      >aa  2>&1 
	@-rm bb.*      >aa  2>&1 
	@-rm cc.*      >aa  2>&1 
	@-rm *.exe     >aa  2>&1 
	@-rm *.o       >aa  2>&1 
	@-rm aa












