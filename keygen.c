
/* =====[ keygen.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "gcrypt.h"
#include "gcry.h"
#include "getpass.h"
#include "gsexp.h"
#include "base64.h"
#include "zmalloc.h"

int  num_bits_set(unsigned int ks); 

//static  int keysize = 1024;
static  unsigned int keysize = 2048;
//static  int keysize = 4096;

static int weak = FALSE;
static int force = FALSE;
static int dump = 0;
static int verbose = 0;
static int test = 0;
static int nocrypt = 0;

char usestr[] = "keygen [options] keyfile\n"
                "Where keyfile is the basename for .key .pub .mod files.";
static char    thispass[MAX_PATH] = {'\0'};

/*  char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help; */
    
opts opts_data[] = {
                    //'i',  "infile",  NULL, infile,  0, 0, NULL, 
                    //"-i <filename>  --infile <filename>     - input file name",
                    
                    //'o',  "outfile",  NULL, outfile,  0, 0, NULL, 
                    //"-o <filename>  --outfile <filename>    - output file name",

                    //'k',  "keyfile",  NULL, keyfile,  0, 0, NULL, 
                    //"-k <filename>  --keyfile <filename>    - key file name",

                    'k',   "keylen",   &keysize,  NULL,  1024, 32768,    NULL, 
                    "-k             --keylen                - key length in bits",
                    
                    'p',   "pass",   NULL,  thispass, 0, 0,    NULL, 
                    "-p             --pass                  - pass in for key (testing only)",
                    
                    'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
                    "-v             --verbose               - Verbosity on",
                    
                    'd',   "dump",  NULL, NULL,  0, 0, &dump, 
                    "-d             --dump                  - Dump buffers",
                    
                    't',   "test",  NULL,  NULL, 0, 0, &test, 
                    "-t             --test                  - test on",
                    
                    'f',   "force",  NULL,  NULL, 0, 0, &force, 
                    "-f             --force                 - force clobbering files",
                    
                    'w',   "weak",  NULL,  NULL, 0, 0, &weak, 
                    "-w             --weak                  - allow weak pass",
                    
                    'n',   "nocrypt",  NULL,  NULL, 0, 0, &nocrypt, 
                    "-n             --nocrypt               - do not encrypt key (testing only)",
                   
                                         0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
                    };


void my_progress_handler (void *cb_data, const char *what,
                            int printchar, int current, int total)
{
    printf(".");
    //printf("%c", printchar);
}

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

// -----------------------------------------------------------------------

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
    
    if (argc - nn != 2) {
        //fprintf(stderr, "Usage: keygen.exe outfile\n");
        //xerr("Invalid arguments.");
        usage(usestr, opts_data); exit(2);
    }
    if(thispass[0] != '\0')
        {
        if(nocrypt)
            xerr("\nConflicting options, cannot provide key with the 'nocrypt' flag.\n");
        }
    //if(keysize % 2 )
    //    {
    //    xerr2("Keysize must be even %d", keysize);
    //    }
        
    if(num_bits_set(keysize) != 1)
        {
        xerr2("Keysize must be a power of two. ( ... 1024, 2048, 4096 ...)");
        } 
        
    gcrypt_init();

    char* fname = zstrcat(argv[nn+1], ".key");
    //printf("fname %s\n", fname);
    char* fname2 = zstrcat(argv[nn+1], ".pub");
    //printf("fname2 %s\n", fname2);
    
    char* fname3 = zstrcat(argv[nn+1], ".mod");
    //printf("fname3 %s\n", fname3);
    
    if(access(fname, F_OK) >= 0 && !force)
        {
        xerr("File already exists, use different name or delete the file or use -f (--force) option.");
        }
        
    /* Generate a new RSA key pair. */
    printf("\nRSA key generation (of %d bits) can take a few minutes. Your computer "
           "needs to gather random entropy.\n\n", keysize);
    printf("Please wait ");

    gcry_set_progress_handler(my_progress_handler, NULL);

    gcry_error_t err = 0;
    gcry_sexp_t rsa_parms;
    gcry_sexp_t rsa_keypair;
    
    char *key_str = zalloc(64); 
    snprintf(key_str, 64, "(genkey (rsa (nbits 4:%d)))", keysize);
    err = gcry_sexp_build(&rsa_parms, NULL, key_str);
    zfree(key_str);
    if (err) {
        printerr(err, "create rsa params");
        xerr("gcrypt: failed to create rsa params");
    }
    
    err = gcry_pk_genkey(&rsa_keypair, rsa_parms);
    if (err) {
        printerr(err, "create keypair");
        xerr("gcrypt: failed to create rsa key pair");
    }
    memset(key_str, sizeof(key_str), '\0'); 

    if(dump)
        {    
        //gcry_sexp_dump(rsa_keypair);
        //int ss = gcry_sexp_sprint(rsa_keypair, GCRYSEXP_FMT_ADVANCED, NULL, 0);
        //char *ppp = (char*)malloc(ss+1);
        //gcry_sexp_sprint(rsa_keypair, GCRYSEXP_FMT_ADVANCED, ppp, ss);
        //printf("%s\n", ppp);
        }
        
    printf("\n\nRSA key generation complete.\n\n");
    
    /* Grab a key pair password and create an encryption context with it. */
        
    int ret = 0;
    if(thispass[0] == '\0' && !nocrypt)
        {
        printf("Please enter a password to lock your key pair.\n");
        printf("This password must be retained for later use. Do not loose this password.\n\n");
        if(weak)
            printf("Warning! Weak option specified, recommended for testing only.\n");
        getpassx  passx;
        passx.prompt  = "Enter  keypair  pass:";
        passx.prompt2 = "Confirm keypair pass:";
        passx.pass = thispass;    
        passx.maxlen = sizeof(thispass);
        passx.minlen = 4;
        passx.strength = 6;
        passx.weak = weak;
        passx.nodouble = FALSE;
        
        ret = getpass2(&passx);
        }
    if(ret < 0)
        {
        xerr("Error on entering pass, no keys are written.\n");
        }
    //printf("pass '%s'\n", thispass);
    
    if(write_pubkey(&rsa_keypair, fname2) < 0)
        xerr("Could not write pubic key");
    
    // Ignore error (if any)    
    write_mod_exp(&rsa_keypair, fname3);
    
    gcry_cipher_hd_t aes_hd;
    get_aes_ctx(&aes_hd, thispass, strlen(thispass));
    
    /* Encrypt the RSA key pair. */
    size_t rsa_len = get_keypair_size(keysize);
    zline2(__LINE__, __FILE__);
    void* rsa_buf = zalloc(rsa_len);
    if (!rsa_buf) {
        xerr("malloc: could not allocate rsa buffer");
    }
    
    char *ttt = datestr();
    char *rrr = randstr(32);
 
    gcry_sexp_t glib_keys;
    err = gcry_sexp_build(&glib_keys, NULL, 
                "(gcrypt-key (date %s) (key-id %s) ) %S",  ttt, rrr, rsa_keypair);
    //print_sexp(glib_keys);
    zfree(ttt);   zfree(rrr);
    
    //rsa_len = gcry_sexp_sprint(rsa_keypair, GCRYSEXP_FMT_CANON, rsa_buf, rsa_len);
    rsa_len = gcry_sexp_sprint(glib_keys, GCRYSEXP_FMT_CANON, rsa_buf, rsa_len);
    if(rsa_len == 0)
        {
        xerr("Cannot sprint keypair");
        }
    //if(dump)
    //    dump_mem(rsa_buf, rsa_len);
        
    if(!nocrypt)
        {
        err = gcry_cipher_encrypt(aes_hd, (unsigned char*) rsa_buf, 
                                  rsa_len, NULL, 0);
        if (err) {
            xerr("gcrypt: could not encrypt with AES");
            }
        }
        
    FILE* lockf = fopen(fname, "wb");
    if (!lockf) {
        xerr("fopen() failed");                                                              
    }
    ///* Write the encrypted base64 key pair to disk. */
    int limlen = rsa_len;
    char *mem6 = base_and_lim(rsa_buf, rsa_len, &limlen);
   
    //if(dump)
    //    dump_mem(mem6, limlen);
        
    fprintf(lockf, "%s\n", comp_start);
    fprintf(lockf, "%*s\n", limlen, mem6);
    fprintf(lockf, "%s\n", comp_end);
    
    fclose(lockf);
    zfree(mem6);
    
    /* Release contexts. */
    gcry_sexp_release(rsa_keypair);
    gcry_sexp_release(rsa_parms);
    gcry_cipher_close(aes_hd);
    zfree(rsa_buf);
    
    printf("Key successfully saved.\n");
    
    zfree(fname);
    zfree(fname2);
    zfree(fname3);
    zleak();
    
    return 0;
}

// See if keysize has more than one bit set (if it is a power of two)

int  num_bits_set(unsigned int ks) 
{
    int bits = 0; 
    //printf("bits of %d (0x%x)\n", ks, ks);
    while(TRUE)
        {
        if(ks & 1)
            bits++;
        ks >>= 1;
        if (ks == 0)
            break;
        }  
    //printf("ks bits %d\n", bits);  
    return bits;
}    










