
/* =====[ test_asym.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <signal.h>

#include "gcrypt.h"
#include "gcry.h"
#include "zmalloc.h"
#include "getpass.h"
#include "gsexp.h"

static int dump = 0;
static int verbose = 0;
static int test = 0;
static int ppub = 0;
static int nocrypt = 0;

static char    infile[MAX_PATH] = {'\0'};
static char    outfile[MAX_PATH] = {'\0'};
static char    keyfile[MAX_PATH] = {'\0'};
static char    thispass[MAX_PATH] = {'\0'};

char usestr[] = "test_asym [options] keyfile";

opts opts_data[] = {
                    'i',  "infile",  NULL, infile,  0, 0, NULL, 
                    "-i <filename>  --infile <filename>     - input file name",
                    
                    'o',  "outfile",  NULL, outfile,  0, 0, NULL, 
                    "-o <filename>  --outfile <filename>    - output file name",
                   
                    'p',   "pass",   NULL,  thispass, 0, 0,    NULL, 
                    "-p             --pass                  - pass in for key (testing only)",
                    
                    'k',  "keyfile",  NULL, keyfile,  0, 0, NULL, 
                    "-k <filename>  --keyfile <filename>    - key file name",

                    'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
                    "-v             --verbose               - Verbosity on",
                    
                    'd',   "dump",  NULL, NULL,  0, 0, &dump, 
                    "-d             --dump                  - Dump buffers",
                    
                    't',   "test",  NULL,  NULL, 0, 0, &test, 
                    "-t             --test                  - test on",
                    
                    'n',   "nocrypt",  NULL,  NULL, 0, 0, &nocrypt, 
                    "-n             --nocrypt               - do not decypt private key",
                   
                    'x',   "printpub",  NULL,  NULL, 0, 0, &ppub, 
                    "-x             --printpub              - print public key",
                    
                     0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
                    };


static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

int main(int argc, char** argv)
{
    signal(SIGSEGV, myfunc);

    char *err_str;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    if (err_str)
        {
        printf(err_str);
        usage(usestr, opts_data); exit(2);
        }

    if (argc - nn != 2 && strlen(keyfile) == 0) {
        printf("Missing argument for ascrypt.");
        usage(usestr, opts_data); exit(2);
    }

    //printf("thispass '%s'\n", thispass);
    
    //zverbose(TRUE);
    //gcry_set_allocation_handler(zalloc, NULL, NULL, zrealloc, zfree);
    
    gcrypt_init();
    gcry_error_t err;
    
    char* fname = argv[1 + nn];

    FILE* lockf = fopen(fname, "rb");
    if (!lockf) {
        xerr2("fopen() on '%s' failed.", fname);
    }
    
    /* Read and decrypt the key pair from disk. */
    unsigned int flen = getfsize(lockf);
    zline2(__LINE__, __FILE__);
    char* fbuf = zalloc(flen + 1);
    if (!fbuf) {
        xerr("malloc: could not allocate rsa buffer");
    }
    if (fread(fbuf, flen, 1, lockf) != 1) {
        xerr("fread() on composit key failed");
    }
    fclose(lockf);
    
    //fbuf[flen] = '\0';
    zcheck(fbuf, __LINE__);
    
    if(dump)
      dump_mem(fbuf, flen);
    
    zline2(__LINE__, __FILE__);
    int  rsa_len = flen;
    char *rsa_buf = decode_priv_key(fbuf, &rsa_len, &err_str);
    zfree(fbuf);
    
    if (!rsa_buf) {
        //printf("%s\n", err_str);
        xerr2("Decode key failed. %s", err_str);
    }
    //if(dump)
    //    dump_mem(rsa_buf, rsa_len);
    
    zline2(__LINE__, __FILE__);
    /* Grab a key pair password and create an AES context with it. */
    if(thispass[0] == '\0' && !nocrypt)
        {
        getpassx  passx;
        passx.prompt  = "Enter keypair pass:";
        passx.pass = thispass;    
        passx.maxlen = MAXPASSLEN;
        passx.minlen = 3;
        passx.weak   = TRUE;
        passx.nodouble = TRUE;
        passx.strength = 4;
        int ret = getpass2(&passx);
        if(ret < 0)
            xerr("Error on password entry.");
        }
    
    //printf("thispass '%s'\n", thispass);
    
    gcry_cipher_hd_t aes_hd;
    get_aes_ctx(&aes_hd, thispass, strlen(thispass));

    zline2(__LINE__, __FILE__);
    if(!nocrypt)
    {
        // Decrypt buffer
        err = gcry_cipher_decrypt(aes_hd, (unsigned char*) rsa_buf,
                                  rsa_len, NULL, 0);
        if (err) {
            xerr("gcrypt: failed to decrypt key pair");
        }
    }
    if(dump)
        dump_mem(rsa_buf, rsa_len);
    
    zline2(__LINE__, __FILE__);
    /* Load the key pair components into sexps. */
    gcry_sexp_t rsa_keypair;
    err = gcry_sexp_new(&rsa_keypair, rsa_buf, rsa_len, 0);
    if(err)
        {
        //printerr(err, NULL);
        xerr2("gcrypt: failed to load key. (pass?)");
        }
        
    zline2(__LINE__, __FILE__);
    gcry_sexp_t pubk = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
    if(pubk == NULL)
        xerr2("gcrypt: no public key present");
    //print_sexp(pubk);
    gcry_sexp_t privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);
    if(privk == NULL)
        xerr2("gcrypt: no private key present");
    //print_sexp(privk);
    
    zline2(__LINE__, __FILE__);
    printf("Key length pub: %d priv: %d\n", 
                    gcry_pk_get_nbits(pubk), gcry_pk_get_nbits(privk));

    int cycle =  gcry_pk_get_nbits(privk)/8;
    
    const unsigned char* ss = (const unsigned char*)
    "Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    //"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    "Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world.";

    printf("Original message -> %d bytes \n'%s'\n", strlen(ss), (char*) ss);
    
    zline2(__LINE__, __FILE__);
    gcry_sexp_t ciph;
    int ret = pk_encrypt_buffer(ss, strlen(ss), pubk, &ciph);
    //print_sexp(ciph);
    decode_sexp(ciph, "a");
    
    zline2(__LINE__, __FILE__);
    /* Decrypt the message. */
    gcry_sexp_t plain;
    zline2(__LINE__, __FILE__);
    err = gcry_pk_decrypt(&plain, ciph, privk);
    if (err) {
        xerr("gcrypt: decryption failed");
    }

    zline2(__LINE__, __FILE__);
    /* Pretty-print the results. */
    gcry_mpi_t out_msg = gcry_sexp_nth_mpi(plain, 0, GCRYMPI_FMT_USG);
    
    zline2(__LINE__, __FILE__);
    int written = 0;
    unsigned char *buffm;                                     
    err = gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffm, &written, out_msg);
                         
    if (err) {
        xerr("failed to stringify mpi");
    }
    printf("Decrypted message -> (%d bytes)\n'%s'\n", strlen(buffm), (char*) buffm);

    if(strcmp(buffm, ss) == 0)
        {
        printf("Buffers compare OK\n");
        }
    else
        {
        printf("Buffers DO NOT compare.\n");
        }
        
    /* Release contexts. */
    gcry_mpi_release(out_msg);
    gcry_sexp_release(rsa_keypair);
    gcry_sexp_release(pubk);
    gcry_sexp_release(privk);
    gcry_sexp_release(ciph);
    gcry_sexp_release(plain);
    gcry_cipher_close(aes_hd);
    zline2(__LINE__, __FILE__);
    zfree(rsa_buf);
    zline2(__LINE__, __FILE__);
    gcry_free(buffm);
  
    zleak();
    return 0;
}










