
/* =====[ keygen.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug03.2017     Peter Glen      Initial version.

   ======================================================================= */

// Sexp helpers
char    *sprint_sexp(gcry_sexp_t sexp, int *len, int format);
void    print_sexp(gcry_sexp_t rsa_keypair);
int     decode_sexp(gcry_sexp_t list, const char *findstr);

// General memory helpers
void    dump_mem(const char *ptr, int len);



