
/* =====[ encdec.c ]=========================================================

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
#include "gsexp.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"

//static  int keysize = 2048;

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

int main(int argc, char** argv)
{
    signal(SIGSEGV, myfunc);

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <rsa-keypair.key>\n", argv[0]);
        xerr("Invalid arguments.");
    }

    printf("Showing mutated cypher text.\n");
    
    gcrypt_init();
    gcry_error_t err;
    char* fname = argv[1];

    FILE* lockf = fopen(fname, "rb");
    if (!lockf) {
        xerr2("fopen() on '%s' failed.", fname);
    }
    
    //int pkv = gcry_pk_map_name("rsa");
    //printf("Public key algo: %d Name: '%s'\n", pkv, gcry_pk_algo_name(pkv) );
    
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
    fbuf[flen] = '\0';
    zcheck(fbuf, __LINE__);
    
    char *err_str;
    int  rsa_len = flen;
    char *rsa_buf = decode_comp_key(fbuf, &rsa_len, &err_str);
    
    if (!rsa_buf) {
        xerr2("decode key failed. %s", err_str);
    }
    
    /* Grab a key pair password and create an AES context with it. */
    char passwd[MAXPASSLEN]; int weak = TRUE;
    
    getpassx  passx;
    passx.prompt  = "Enter  keypair  pass:";
    passx.pass = passwd;    
    passx.maxlen = MAXPASSLEN;
    passx.minlen = 3;
    passx.weak   = TRUE;
    passx.nodouble = TRUE;
    int ret = getpass2(&passx);
    if(ret < 0)
        xerr("Error on password entry.");
    
    gcry_cipher_hd_t aes_hd;
    get_aes_ctx(&aes_hd, passwd, strlen(passwd));

    err = gcry_cipher_decrypt(aes_hd, (unsigned char*) rsa_buf,
                              rsa_len, NULL, 0);
    if (err) {
        xerr("gcrypt: failed to decrypt key pair");
    }

    /* Load the key pair components into sexps. */
    gcry_sexp_t rsa_keypair;
    err = gcry_sexp_new(&rsa_keypair, rsa_buf, rsa_len, 0);
    if(err)
        {
        xerr("gcrypt: failed to rate key pair S-expr (pass?)");
        }
        
    gcry_sexp_t pubk = gcry_sexp_find_token(rsa_keypair,  "public-key", 0);
    gcry_sexp_t privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);

    if(privk == NULL)
        {
        xerr("No private key here.");
        }
    //printf("keylen %d\n", gcry_pk_get_nbits(privk));
    
    /* Create a message. */
    gcry_mpi_t msg;
    gcry_sexp_t data;
    const unsigned char* ss = (const unsigned char*)
    //"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    //"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    "Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world.";

    printf("Original message -> %d bytes \n'%s'\n", strlen(ss), (char*) ss);
    
    err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, ss,
                        strlen((const char*) ss), NULL);

    if (err) {
        xerr("failed to create a mpi from the message");
    }

    err = gcry_sexp_build(&data, NULL,
                           "(data (flags raw) (value %m))", msg);
    if (err) {
        xerr("failed to create a sexp from the message");
    }

    /* Encrypt the message. */
    gcry_sexp_t ciph;
    err = gcry_pk_encrypt(&ciph, data, pubk);
    if (err) {
        xerr("gcrypt: encryption failed");
    }

    gcry_mpi_t msg2;
    gcry_sexp_t data2;
    char *sss = strdup(ss);
    sss[1] = 'f';
    err = gcry_mpi_scan(&msg2, GCRYMPI_FMT_USG, sss,
                        strlen((const char*) sss), NULL);

    err = gcry_sexp_build(&data2, NULL,
                           "(data (flags raw) (value %m))", msg2);
    if (err) {
        xerr("failed to create a sexp from the message");
    }
    gcry_sexp_t ciph2;
    err = gcry_pk_encrypt(&ciph2, data2, pubk);
    if (err) {
        xerr("gcrypt: encryption failed");
    }

    printf("\n" "Cypher:\n");
    gcry_sexp_t ddd = gcry_sexp_find_token(ciph, "a", 1);
    print_sexp(ddd);
    
    unsigned int plen = 0;
    const char *ptr = gcry_sexp_nth_data(ddd, 1, &plen);
    
    printf("\n" "Cypher2:\n");
    gcry_sexp_t ddd2 = gcry_sexp_find_token(ciph2, "a", 1);
    print_sexp(ddd2);
    
    unsigned int plen2 = 0;
    const char *ptr2 = gcry_sexp_nth_data(ddd2, 1, &plen2);
    //dump_mem(ptr2, plen2);
    
    /* Decrypt the message. */
    gcry_sexp_t plain;
    err = gcry_pk_decrypt(&plain, ciph, privk);
    if (err) {
        xerr("gcrypt: decryption failed");
    }
    gcry_mpi_t out_msg = gcry_sexp_nth_mpi(plain, 0, GCRYMPI_FMT_USG);
    
    unsigned char *buffm;                           
    int written;          
    err = gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffm, &written, out_msg);
    if (err) {
        xerr("failed to stringify mpi");
    }
    printf("Decrypted message -> (%d bytes)\n'%s'\n", strlen(buffm), (char*) buffm);

    /* Release contexts. */
    gcry_mpi_release(msg);
    gcry_mpi_release(out_msg);
    gcry_sexp_release(rsa_keypair);
    gcry_sexp_release(pubk);
    gcry_sexp_release(privk);
    gcry_sexp_release(data);
    gcry_sexp_release(ciph);
    gcry_sexp_release(plain);
    gcry_cipher_close(aes_hd);
    zfree(rsa_buf);
    //fclose(lockf);

    return 0;
}







