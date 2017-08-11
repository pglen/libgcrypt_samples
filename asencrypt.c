
/* =====[ ascrypt.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.22.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <signal.h>
#include <stdio.h>

#include "gcrypt.h"
#include "gcry.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"
#include "gsexp.h"

char *decode_pub_key(char *rsa_buf, int *prsa_len, char **err_str);

static int dump = 0;
static int verbose = 0;
static int test = 0;
static int ppub = 0;

static char    infile[MAX_PATH] = {'\0'};
static char    outfile[MAX_PATH] = {'\0'};
static char    keyfile[MAX_PATH] = {'\0'};

/*  char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help; */
    
opts opts_data[] = {
                    'i',  "infile",  NULL, infile,  0, 0, NULL, 
                    "-i <filename>  --infile <filename>     - input file name",
                    
                    'o',  "outfile",  NULL, outfile,  0, 0, NULL, 
                    "-o <filename>  --outfile <filename>    - output file name",

                    'k',  "keyfile",  NULL, keyfile,  0, 0, NULL, 
                    "-k <filename>  --keyfile <filename>    - key file name",

                    'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
                    "-v             --verbose               - Verbosity on",
                    
                    'd',   "dump",  NULL, NULL,  0, 0, &dump, 
                    "-d             --dump                  - Dump buffers",
                    
                    't',   "test",  NULL,  NULL, 0, 0, &test, 
                    "-t             --test                  - test on",
                    
                    'b',   "ppub",  NULL,  NULL, 0, 0, &ppub, 
                    "-p             --ppub              - print public key",
                    
                     0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
                    };

char *test_str = //"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    "Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    "Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world.";
    
char tmp_str[MAX_PATH];

char usestr[] = "ascrypt [options] keyfile";

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

//////////////////////////////////////////////////////////////////////////

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

    if(verbose)
        {
        //printf("nn=%d  test=%d verbose=%d\n", nn, test, verbose);
        printf("infile='%s' outfile='%s' keyfile='%s'\n", infile, outfile, keyfile);
        }
    
    if (argc - nn != 2 && strlen(keyfile) == 0) {
        printf("Missing argument for ascrypt.");
        usage(usestr, opts_data); exit(2);
    }

    if(argc - nn >= 2)
        {
        strncpy(keyfile, argv[nn + 1], sizeof(keyfile));
        } 
    
    //zverbose(1);
    gcrypt_init();
    gcry_error_t err;
    //char* fname = argv[nn + 1];
    
    FILE* lockf = fopen(keyfile, "rb");
    if (!lockf) {
        xerr2("fopen() failed on file '%s'", keyfile);
    }

    /* Grab the public key and key size */
    unsigned int rsa_len = getfsize(lockf);
    if(verbose)
        printf("Key file size %d\n", rsa_len);
        
    zline(__LINE__);
    char* rsa_buf = zalloc(rsa_len + 1);
    if (!rsa_buf) {
        xerr("malloc: could not allocate rsa buffer");
    }
    if (fread(rsa_buf, rsa_len, 1, lockf) != 1) {
        xerr("fread() on public key failed");
    }
    
    fclose(lockf);

    //rsa_buf[rsa_len] = '\0';
    int outlen = rsa_len;
    char *dec_err_str;
    char *mem = decode_pub_key(rsa_buf, &outlen, &dec_err_str);
    if(mem == NULL)
        {
        //printf("%s\n", dec_err_str);
        //xerr("Cannot decode public key");
        xerr2("Cannot decode public key: %s", dec_err_str);
        }
        
    if(ppub)
        dump_mem(mem, outlen); 
        
    gcry_sexp_t pubkey;
    err = gcry_sexp_new(&pubkey, mem, outlen, 1);
    zfree(mem);
    if (err) {
        printerr(err, "encrypt");
        xerr("gcrypt: failed to read public key.");
        }
        
    if(ppub)
        print_sexp(pubkey);
    
    int keylen = gcry_pk_get_nbits(pubkey) / 8;
    //printf("keylen %d\n", keylen);
    
    /* Read in a buffer */
    char* data_buf;
    unsigned int  data_len;
    if(strlen(infile))
        {
        FILE* dataf = fopen(infile, "rb");
        if (!dataf) {
            xerr2("Cannot open data file: '%s'", infile);
            }
        data_len = getfsize(dataf);
        //printf("data file size %d\n", rsa_len);
        zline(__LINE__);
        data_buf = zalloc(data_len + 1);
        if (!data_buf) {
            xerr("malloc: could not allocate data buffer");
            }
        if (fread(data_buf, data_len, 1, dataf) != 1) {
            xerr("fread() on data file failed");
            }
        }
    else
        {        
        data_len = strlen(test_str);
        zline(__LINE__);
        data_buf = zalloc(data_len + 1);
        memcpy(data_buf, test_str, data_len);
        }
    //if(dump)
    //    {
    //    dump_mem(data_buf, data_len);
    //    }
    
    int  outlen2 = 0, outlim = data_len * 2 + keylen * 2;
    zline(__LINE__);
    char *outptr = zalloc(outlim);
    if(!outptr)
        {
        xerr("Cannot allocate memory");
        }
    
    /* Create a message. Parse keylen chunks, padd last chunk with zeros */
    for(int loop = 0; loop < data_len; loop += keylen)
        {
        int curr_len = keylen;
        if(data_len - loop < keylen)
            {
            curr_len = data_len - loop;
            //if(loop + keylen > outlim)
            //    {
            //    xerr("Output limit overwite prevented");
            //    }
            //memset(data_buf + data_len,  keylen - (data_len % keylen), '\0');
            //printf("magic len %d\n", keylen - (data_len % keylen));
            }
              
        //printf("data %p len = %d ", data_buf + loop, curr_len);
        
        gcry_mpi_t msg;
        err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, data_buf + loop,
                            curr_len, NULL);
    
        if (err) {
            xerr("failed to create a mpi from the message");
        }
        
        gcry_sexp_t enc_data;
        err = gcry_sexp_build(&enc_data, NULL,
                               "(data (flags raw) (value %m))", msg);
                               
        if (err) {
            printerr(err, "bulding sexp");
            xerr("failed to create a sexp from the message");
        }
        
        /* Encrypt the message. */
        gcry_sexp_t ciph;
        err = gcry_pk_encrypt(&ciph, enc_data, pubkey);
        if (err) {
            printerr(err, "encryption");
            xerr("gcrypt: encryption failed");
        }
        
        //if(dump)
        //  print_sexp(ciph);
        
        gcry_sexp_t ddd = gcry_sexp_find_token(ciph, "a", 1);
        //print_sexp(ddd);
        
        if(ddd == NULL)
        if (err) {
            xerr("Internal: find token failed");
        }
        
        unsigned int plen = 0;
        const char *dptr = gcry_sexp_nth_data(ddd, 1, &plen);
        
        //printf("outlen %d\n", plen);
        if(dump)
            {
            //printf("Output:\n");
            dump_mem(dptr, plen);
            }
        // Add to our cummulative buffer
        
        if(outlen2 + plen > outlim)
            {
            xerr("Could not write all mem to buffer");
            }
        *( (short *)(outptr + outlen2)) = (short) plen & 0xffff;
        outlen2 += sizeof(short); 
        memcpy(outptr + outlen2, dptr, plen); 
        outlen2 += plen;
            
        /* Release contexts. */
        gcry_mpi_release(msg);
        gcry_sexp_release(enc_data);
        gcry_sexp_release(ciph);
        }      
    int outx, plen;
    char *mem3 = base_and_lim(outptr, outlen2, &outx);
    
    FILE* outf = stdout;
    if(strlen(outfile))
        {
        outf = fopen(outfile, "wb");
        if(!outf)
            {
            xerr("Cannnot open outfile");
            }
        }
    int fullen =  strlen(cyph_start) + strlen(cyph_start) + outx + 10;
    char *mem4 = malloc(fullen);
    if(!mem4) 
        xerr("Cannot allocate memory");
    
    int add = snprintf(mem4, fullen, "%s\n", cyph_start);
    add += snprintf(mem4 + add, fullen - add, "%.*s\n", outx, mem3);
    add += snprintf(mem4 + add, fullen - add, "%s\n", cyph_end);
    
    //dump_mem(mem4, add);
    int retf = fwrite(mem4, add, 1, outf); 
    if(retf != 1)
        {
        xerr("Cannot write to file");
        }
    
    //fprintf(outf, "%s\n", cyph_start);
    //fprintf(outf, "%*s\n", outx, mem3);
    //fprintf(outf, "%s\n", cyph_end);
    
    if(outf != stdout)
        {
        fclose(outf);
        }
        
    zfree(mem3);
    zfree(data_buf);
    
    /* Release contexts. */
    gcry_sexp_release(pubkey);
    
    zline(__LINE__);
    zfree(rsa_buf);
    zfree(outptr);
    
    zleak();
    return 0;
}


#if 0

    int outlen = base64_calc_encodelen(strlen(s));
    zline(__LINE__);
    char *mem = zalloc(outlen);
    base64_encode(s, strlen(s), mem, &outlen);
    zcheck(mem, __LINE__);
    printf("base64\n%s\n", mem);
    
    int declen = base64_calc_decodelen(outlen);
    char *dmem = zalloc(declen);
    base64_decode(mem, outlen, dmem, &declen);
    printf("dec base64\n%s\n", dmem);
    //dump_mem(dmem, strlen(dmem));
    zcheck(dmem, __LINE__);
    zfree(mem);
    #endif

/* EOF */

















