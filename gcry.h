
/* =====[ gcry.h ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.17.2017     Peter Glen      Added dump mem
      0.00  jul.22.2017     Peter Glen      Sexp helpers

   ======================================================================= */

// Unified strings for files

const char *pub_start;
const char *pub_end;
const char *comp_start;
const char *comp_end;
const char *cyph_start;
const char *cyph_end;
const char *mod_start;
const char *mod_end;  
const char *exp_start;
const char *exp_end; 

typedef struct _opts
{
    char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help;
} opts;

int     parse_commad_line(char **argv, opts *popts_data, char **err_str);
void    usage(const char *progname, opts *opts_data);

// /* Crash routines. */
void xerr(const char* msg);
void xerr2(const char* msg, ...);
void printerr(int err, char *str);

// /* Initialize libgcrypt. */
void gcrypt_init();

unsigned int getfsize(FILE *fp);

// /* Estimate the size of the encrypted key pair. */
size_t get_keypair_size(int nbits);

// /* Create an AES context out of a user's password. */
void    get_aes_ctx(gcry_cipher_hd_t* aes_hd, const char *passwd, int pass_len);
void    print_cypher_details(const char *str);

char    *decode_comp_key(char *rsa_buf, int *prsa_len, char **err_str);
char    *decode_rsa_cyph(char *rsa_buf, int *prsa_len, char **err_str);
char    *decode_pub_key(char *rsa_buf, int *prsa_len, char **err_str);

int     write_pubkey(gcry_sexp_t *rsa_keypair, const char *xfname2);
int     write_mod_exp(gcry_sexp_t *rsa_keypair, const char *xfname2);

int     pk_encrypt_buffer(const char *buf, int len, gcry_sexp_t pubk, gcry_sexp_t *ciph);

char    *base_and_lim(const char *mem, int len, int *olen);
char    *randstr(int len);
char    *tobase64(char *mem, int *len);
char    *datestr();
char    *zstrcat(const char *str1, const char* str2);

// EOF


