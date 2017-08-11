
/* =====[ gcry.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  jul.17.2017     Peter Glen      Added dump mem

   ======================================================================= */

#include <stdlib.h>
#include <ctype.h>

#include "gcrypt.h"
#include "gcry.h"
#include "gsexp.h"
#include "zmalloc.h"
#include "getpass.h"
#include "base64.h"

// -----------------------------------------------------------------------
// Unified strings for key files, definitons

const char *pub_start  = "-----BEGIN GCRYPT RSA PUBLIC KEY-----";
const char *pub_end    = "-----END GCRYPT RSA PUBLIC KEY-----";

const char *comp_start = "-----BEGIN GCRYPT RSA COMPOSITE KEY-----";
const char *comp_end   = "-----END GCRYPT RSA COMPOSITE KEY-----";

const char *cyph_start = "-----BEGIN GCRYPT RSA CYPHER-----";
const char *cyph_end   = "-----END GCRYPT RSA CYPHER-----";

const char *mod_start  = "-----BEGIN RSA PUBLIC MODULUS-----";
const char *mod_end    = "-----END RSA PUBLIC MODULUS-----";
    
const char *exp_start  = "-----BEGIN RSA PUBLIC EXPONENT-----";
const char *exp_end    = "-----END RSA PUBLIC EXPONENT-----";
    
void xerr(const char* msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(2);                                
}

void xerr2(const char* msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    
    vfprintf(stderr, msg, ap);
    exit(2);                                
}

//////////////////////////////////////////////////////////////////////////

void printerr(int err, char *str)

{
    if(str)
        fprintf (stderr, "%s\n", str);
        
    fprintf (stderr, "Failure: %s/%s\n",
                    gcry_strsource (err),
                        gcry_strerror (err));
                        
    //fprintf (stdout, "Failure: %s/%s\n",
    //                gcry_strsource (err),
    //                    gcry_strerror (err));
}       

//////////////////////////////////////////////////////////////////////////

void gcrypt_init()

{
    /* Version check should be the very first call because it
       makes sure that important subsystems are intialized. */
    if (!gcry_check_version (GCRYPT_VERSION))
    {
        xerr("gcrypt: library version mismatch");
    }

    gcry_error_t err = 0;

    /* We don't want to see any warnings, e.g. because we have not yet
       parsed program options which might be used to suppress such
       warnings. */
    err = gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

    /* ... If required, other initialization goes here.  Note that the
       process might still be running with increased privileges and that
       the secure memory has not been intialized.  */

    /* Allocate a pool of 16k secure memory.  This make the secure memory
       available and also drops privileges where needed.  */
    err |= gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

    /* It is now okay to let Libgcrypt complain when there was/is
       a problem with the secure memory. */
    err |= gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    /* ... If required, other initialization goes here.  */

    /* Tell Libgcrypt that initialization has completed. */
    err |= gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (err) {
        xerr("gcrypt: failed initialization");
    }
}

size_t get_keypair_size(int nbits)
{
    size_t aes_blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128);

    // format overhead * {pub,priv}key (2 * bits)
    size_t keypair_nbits = 4 * (2 * nbits);

    size_t rem = keypair_nbits % aes_blklen;
    return (keypair_nbits + rem) / 8;
}

void get_aes_ctx(gcry_cipher_hd_t* aes_hd, const char *passwd, int pass_len)
{
    const size_t keylen = 16;
    char passwd_hash[keylen];
    
    int err = gcry_cipher_open(aes_hd, GCRY_CIPHER_AES128, 
                               GCRY_CIPHER_MODE_CFB, 0);
    if (err) {
        xerr("gcrypt: failed to create aes handle");
    }

    gcry_md_hash_buffer(GCRY_MD_MD5, (void*) &passwd_hash, 
                        (const void*) passwd, pass_len);

    err = gcry_cipher_setkey(*aes_hd, (const void*) &passwd_hash, keylen);
    if (err) {
        xerr("gcrypt: could not set cipher key");
    }

    err = gcry_cipher_setiv(*aes_hd, (const void*) &passwd_hash, keylen);
    if (err) {
        xerr("gcrypt: could not set cipher initialization vector");
    }
}

//////////////////////////////////////////////////////////////////////////
// Return file size

unsigned int getfsize(FILE *fp)

{
    size_t org_pos = ftell(fp);
    fseek(fp, 0, SEEK_END);
    size_t file_len = ftell(fp);
    fseek(fp, org_pos, SEEK_SET);
    
    return  file_len;
}

// Helper for command line

static char tmp_error[MAX_PATH];

static int parse_one(const char *str, opts popts_data[], int idx)

{
    int ret = 0;
    
    if(popts_data[idx].strval != NULL)
        {
        if(str == NULL)
            {   
            return -1;
            }
        strncpy(popts_data[idx].strval, str, MAX_PATH);
        ret = 1;
        }
    else if(popts_data[idx].val != NULL)
        {
        int val = atoi(str);
        if(popts_data[idx].minval > val ||
                popts_data[idx].maxval < val) 
            {
            return -1;
            }
        *popts_data[idx].val =  val;
        ret = 1;
        } 
    else if(popts_data[idx].flag != NULL)
        {
        *popts_data[idx].flag = TRUE;
        }
    return ret;
}    

/*
 * Read command line switches, set globals.
 *
 * In:      Arguments, procession options, place for error str
 * Out:     Args parsed
 * Return:  Last index processed
 # Pointer to an error message or NULL
 *
 */

int     parse_commad_line(char **argv, opts *popts_data, char **err_str)

{
    int     got, nn, processed = 0, err = 0;
    char    *ret_val = NULL;
    int     inval_arg = 0;

    *err_str = NULL;
    
    for (nn = 1; argv[nn] != NULL; nn++)
        {
        got = 0;
        // Long option?
        if(strlen(argv[nn]) > 2 && (argv[nn][0] == '-' && argv[nn][1] == '-'))
            {
            char *cmdstr = &argv[nn][2];
            //printf("Long option: '%s'\n", cmdstr);
            int idx = 0;
            if(strcmp(cmdstr, "help") == 0)
                {
                *err_str = "Help requested, long form.";
                return nn;
                }
            while(TRUE)
                {
                if(popts_data[idx].long_opt == NULL && popts_data[idx].opt == 0)
                    {
                    if(got == 0)
                        {
                        err++;
                        inval_arg = nn;
                        }
                    else
                        processed++;                        
                    break;
                    } 
                if(strcmp(popts_data[idx].long_opt, cmdstr) == 0)
                    {
                    //printf("Found long option %s arg %s\n", cmdstr, argv[nn]);
                    int ret = parse_one(argv[nn+1], popts_data, idx);
                    if(ret < 0)
                        { 
                        snprintf(tmp_error, sizeof(tmp_error), 
                            "Invalid value on option '--%s'\n", cmdstr);
                        *err_str = tmp_error;
                        return nn;
                        }
                    processed += ret;
                    got++;
                    }
                idx++;
                }
            }
        else if(argv[nn][0] == '-' ||  argv[nn][0] == '/')   /* option recognized */
            {
            int idx = 0;
            //char cmd = tolower(argv[nn][1]); // made it case sensitive
            char cmd = argv[nn][1];
            if(cmd == '?' || cmd == 'h')
                {
                *err_str = "Help requested.";
                return nn;
                }
            while(TRUE)
                {
                if(popts_data[idx].long_opt == NULL && popts_data[idx].opt == 0)                    {
                    if(got == 0)
                        {
                        inval_arg = nn;
                        err++;
                        }
                    else
                        processed++;                        
                    break;
                    }   
                if(popts_data[idx].opt == cmd)
                    {
                    //printf("Got command %c\n", cmd);
                    got++;
                    int ret = 0; 
                    if(strlen(argv[nn]) > 2)
                        {
                        // Option in line
                        parse_one(&argv[nn][2], popts_data, idx);
                        }
                    else
                        {
                        // Next command is option  value
                        ret = parse_one(argv[nn+1], popts_data, idx);
                        if(ret < 0)
                            { 
                            snprintf(tmp_error, sizeof(tmp_error), 
                                "Invalid value on option '-%c'\n", cmd);
                            *err_str = tmp_error;
                            return nn;
                            }
                        }
                    processed += ret;
                    }
                 idx++;
                }
            }                 
        }
    if (err)
        {
        snprintf(tmp_error, sizeof(tmp_error), 
                   "Invalid option on command line '%s'\n", argv[inval_arg]);    
        *err_str = tmp_error;
        }
    return(processed);
}

void    usage(const char *progname, opts *opts_data)

{
    int  idx = 0, ret_val = 0;
    
    //printf("opts_data %s", opts_data);
    
    printf("\
\n\
Usage: %s\n\
Options can be:     \n\
", progname);

   while(TRUE)
        {
        if(opts_data[idx].opt == 0)
            break;
            
        printf("               %s\n", opts_data[idx].help);
        idx++;
        }
    printf("\n");
    printf(    "               -?             --help                  - displays this help\n");
    printf(    "               -h             --help                  - displays this help\n");
    printf(    "One option per item, last option prevails.\n");
}

//////////////////////////////////////////////////////////////////////////

typedef struct _armor_params
{
    char    *rsa_buf;
    int     *prsa_len;
    char    **err_str; 
    int     *cleanlen;
    const   char *starts; 
    const   char *ends;
}
armor_params;

static char *decode_armor(armor_params *params)

{
    char *sbegin = strstr(params->rsa_buf, params->starts);
    if(sbegin == NULL)
        {
        *params->err_str = "No start marker";
        return(NULL);
        }
    char *send   = strstr(params->rsa_buf, params->ends);
    if(send == NULL)
        {
        *params->err_str = "No end marker";
        return(NULL);
        }
    sbegin += strlen(params->starts);
    int slen = send - sbegin;
    *params->cleanlen = slen;
    return sbegin;
} 

//////////////////////////////////////////////////////////////////////////
// Unscramble --Begin --End marks, then base64 unexpand and decode.
// free pointer with zalloc / zfree.

char *decode_pub_key(char *rsa_buf, int *prsa_len, char **err_str)

{
    armor_params params;
    int slen;
    *err_str = NULL;
    params.rsa_buf = rsa_buf;    params.prsa_len = prsa_len;
    params.err_str = err_str;    params.cleanlen = &slen;
    params.starts =  pub_start;   params.ends    = pub_end;

    char *sbegin = decode_armor(&params);
    if(!sbegin)
        return NULL;          
              
    int cleanlen = slen;
    zline2(__LINE__, __FILE__);
    char *memc = zalloc(cleanlen);
    base64_clean(sbegin, slen, memc, &cleanlen);

    int outlen = base64_calc_decodelen(cleanlen);
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(cleanlen);
    base64_decode(memc, cleanlen, mem, &outlen);
    zcheck(mem, __LINE__);
    zfree(memc);
    *prsa_len = outlen;
    return mem;    
}

//////////////////////////////////////////////////////////////////////////
// Unscramble --Begin --End marks, then base64 unexpand and decode.
// free pointer with zalloc / zfree.

char *decode_rsa_cyph(char *rsa_buf, int *prsa_len, char **err_str)

{
    armor_params params;
    int slen;
    *err_str = NULL;
    params.rsa_buf = rsa_buf;    params.prsa_len = prsa_len;
    params.err_str = err_str;    params.cleanlen = &slen;
    params.starts =  cyph_start; params.ends     = cyph_end;

    char *sbegin = decode_armor(&params);
    if(!sbegin)
        return NULL;          
              
    int cleanlen = slen;
    zline2(__LINE__, __FILE__);
    char *memc = zalloc(cleanlen);
    base64_clean(sbegin, slen, memc, &cleanlen);
    zcheck(memc, __LINE__);
    
    int outlen = base64_calc_decodelen(cleanlen);
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(cleanlen);
    base64_decode(memc, cleanlen, mem, &outlen);
    zcheck(mem, __LINE__);
    
    zfree(memc);
    *prsa_len = outlen;
    return mem;    
}
            
//////////////////////////////////////////////////////////////////////////
// Unscramble --Begin --End marks, then base64 unexpand and decode.
// free pointer with zalloc / zfree.

char *decode_comp_key(char *rsa_buf, int *prsa_len, char **err_str)

{
    armor_params params;
    int slen;
    *err_str = NULL;
    params.rsa_buf = rsa_buf;    params.prsa_len = prsa_len;
    params.err_str = err_str;    params.cleanlen = &slen;
    params.starts = comp_start;  params.ends = comp_end;

    char *sbegin = decode_armor(&params);
    if(!sbegin)
        return(NULL);
                            
    int cleanlen = slen;
    zline2(__LINE__, __FILE__);
    
    char *memc = zalloc(cleanlen);
    base64_clean(sbegin, slen, memc, &cleanlen);

    int outlen = base64_calc_decodelen(cleanlen);
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(cleanlen);
    base64_decode(memc, cleanlen, mem, &outlen);
    zcheck(mem, __LINE__);
    zfree(memc);
    *prsa_len = outlen;
    return mem;    
}

void    print_cypher_details(const char *str)

{
    int cy = gcry_cipher_map_name(str);
    printf("Cypher:       %d\n", cy);
    printf("Cypher name:  '%s'\n", gcry_cipher_algo_name(cy));
    printf("Blocklen:     %d\n", gcry_cipher_get_algo_blklen(cy));
    printf("Keylen:       %d\n", gcry_cipher_get_algo_keylen(cy));
    printf("\n");
}    

//////////////////////////////////////////////////////////////////////////

int pk_encrypt_buffer(const char *buf, int len, gcry_sexp_t pubk, gcry_sexp_t *ciph)

{ 
    int ret = 0;
            
    /* Create a message. */
    gcry_mpi_t msg; 
    gcry_error_t err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, buf, len, NULL);

    if (err) {
        printerr(err, "create mpi");
        //xerr("failed to create a mpi from the buffer");
    }

    gcry_sexp_t data; 
    err = gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", msg);
    if (err) {
        printerr(err, "build");
        //xerr("failed to create a sexp from the message");
    }

    /* Encrypt the message. */
    err = gcry_pk_encrypt(ciph, data, pubk);
    if (err) {
            print_sexp(*ciph);
            printerr(err, "encryption");
        //xerr("gcrypt: encryption failed");
    }
    
    gcry_sexp_release(data);
    gcry_mpi_release(msg);
    ret = err;
    return ret;
}

//////////////////////////////////////////////////////////////////////////

int write_pubkey(gcry_sexp_t *rsa_keypair, const char *fname2)

{
    int ret = TRUE;
    gcry_sexp_t pubk = gcry_sexp_find_token(*rsa_keypair, "public-key", 0);
    int klen;
    
    char *kptr = sprint_sexp(pubk, &klen, GCRYSEXP_FMT_CANON);
    if(!kptr)  {
       //xerr2("sprint failed. %s %d", __FILE__, __LINE__);                                                              
        printf("Could not sprint S exp for %s\n", fname2);
        return -1;
    }
    int outx;
    char *mem5 = base_and_lim(kptr, klen, &outx);
    mem5[outx] = '\0';
    
    FILE* fp3 = fopen(fname2, "wb");
    if (!fp3) {
        {
        //xerr("fopen() failed");                                                              
        printf("Could not write publick key %s\n", fname2);
        return -1;
        }
    }
    fprintf(fp3, "%s\n", pub_start);
    fprintf(fp3, "%.*s\n", outx, mem5);
    fprintf(fp3, "%s\n", pub_end);
    
    fclose(fp3); 
    zfree(mem5);
    zfree(kptr);
    
    return ret;
}    
    
int write_mod_exp(gcry_sexp_t *rsa_keypair, const char *fname2)

{
    int ret = TRUE;
    
    gcry_sexp_t nnn = gcry_sexp_find_token(*rsa_keypair, "n", 0);
    if(nnn == NULL)
        {
        printf("Could not find public modulus. (no .mod file written)\n");
        return -1;
        }
    //print_sexp(nnn);
    
    unsigned int pklen = 0;
    const char *pkptr = gcry_sexp_nth_data(nnn, 1, &pklen);
    //dump_mem(ptr, pklen);
    
    gcry_sexp_t eee = gcry_sexp_find_token(*rsa_keypair, "e", 0);
    if(eee == NULL)
        {
        printf("Could not find public expenent. (no .mod file written)\n");
        return -1;
        }
    //print_sexp(eee);
    unsigned int elen = 0;
    const char *eptr = gcry_sexp_nth_data(eee, 1, &elen);
         
    FILE* fp2 = fopen(fname2, "wb");
    if (!fp2) {
        printf("Could not write .mod file to %s\n", fname2);
        return -1;
        //xerr("fopen() failed");                                                              
    }
    int outx;
    zline2(__LINE__, __FILE__);
    char *mem3 = base_and_lim(pkptr, pklen, &outx);
    mem3[outx] = '\0';
    fprintf(fp2, "%s\n", mod_start);
    fprintf(fp2, "%.*s\n", outx, mem3);
    fprintf(fp2, "%s\n", mod_end);
    zline2(__LINE__, __FILE__);
    char *mem4 = base_and_lim(eptr, elen, &outx);
    mem4[outx] = '\0';
    fprintf(fp2, "%s\n", exp_start);
    fprintf(fp2, "%.*s\n", outx, mem4);
    fprintf(fp2, "%s\n", exp_end);
  
    fclose(fp2);
    zfree(mem3);
    zfree(mem4);
        
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Return an allocated base64 line limited string.
// Must use zfree to free pointer

char *base_and_lim(const char *mem, int len, int *olen)
{
    int outlen = base64_calc_encodelen(len);
    zline2(__LINE__, __FILE__);
    char *mem2 = zalloc(outlen);
    int ret = base64_encode(mem, len, mem2, &outlen);
    if(ret < 0)
        return NULL;
    zcheck(mem2, __LINE__);             
    zline2(__LINE__, __FILE__);
    
    int linelen = 64, limlen = outlen + 4 + outlen / linelen ;
    char *mem3 = zalloc(limlen);        
    int ret2 = base64_limline(mem2, outlen, mem3, &limlen, linelen);
    zfree(mem2);
    if(ret2 < 0)
        return NULL;
    *olen = limlen;
    
    return mem3;
}

#if 0
      int  tm_sec;          /* Seconds: 0-60 (to accommodate leap seconds) */
      int  tm_min;          /* Minutes: 0-59 */
      int  tm_hour;         /* Hours since midnight: 0-23 */
      int  tm_mday;         /* Day of the month: 1-31 */
      int  tm_mon;          /* Months *since* January: 0-11 */
      int  tm_year;         /* Years since 1900 */
      int  tm_wday;         /* Days since Sunday (0-6) */
      int  tm_yday;         /* Days since Jan. 1: 0-365 */
      int  tm_isdst;        /* +1=Daylight Savings Time, 0=No DST, -1=unknown */
    #endif

//////////////////////////////////////////////////////////////////////////
// get current date, return pointer.
// must free with zfree

char *datestr()

{
    int allocsize = 64;
    zline2(__LINE__, __FILE__);
    char *ttt = zalloc(allocsize);
    time_t tme = time(NULL);
    struct tm *tmm = localtime(&tme);
    int len = snprintf(ttt, allocsize, "%4d/%02d/%02d %02d:%02d:%02d", 
               tmm->tm_year + 1900, tmm->tm_mon + 1, tmm->tm_mday,
                tmm->tm_hour, tmm->tm_min, tmm->tm_sec );
    zcheck(ttt, __LINE__);
    return ttt;  
}

// Must free with zfree
    
char *randstr(int len)

{
    zline2(__LINE__, __FILE__);
    char *rrr = zalloc(len);
    gcry_randomize(rrr, len, GCRY_STRONG_RANDOM);
    //rrr[sizeof(rrr)-1] = '\0';
    int len2 = len;
    char *ret = tobase64(rrr, &len2);
    zcheck(rrr, __LINE__);
    zfree(rrr);
    return ret;
}    

// Must free with zfree

char *tobase64(char *mem, int *len)

{
    int outlen = base64_calc_encodelen(*len);
    zline2(__LINE__, __FILE__);
    char *mem2 = zalloc(outlen);
    int ret = base64_encode(mem, *len, mem2, &outlen);
    if(ret < 0)
        return NULL;
    zcheck(mem2, __LINE__);             
    *len = outlen;
    return(mem2);    
}

//////////////////////////////////////////////////////////////////////////
// 

char *zstrcat(const char *str1, const char* str2)
{
    //printf("cat %s + %s\n", str1, str2);
    int len1 = strlen(str1), len2 = strlen(str2);
    zline2(__LINE__, __FILE__);
    char *ret = zalloc(len1 + len2 + 4);
    strcpy(ret, str1);
    strcat(ret, str2);
    zcheck(ret, __LINE__);
    //printf("cat out %s\n", ret);
    return ret;
}
        
/* EOF */






