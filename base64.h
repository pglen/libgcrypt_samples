
/* =====[ keygen.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  aug.03.2017     Peter Glen      Added baselim

   ======================================================================= */

int     base64_calc_encodelen(int len);
int     base64_calc_decodelen(int len);

int     base64_encode(const unsigned char *data,
                    int input_length, char *encoded_data, int *output_length) ;

int     base64_decode(const char *data,
                             int input_length, unsigned char *decoded_data,
                             int *output_length) ;

int     base64_limline(const char *inp, int inlen, char *outp, int *olen, int linelen);
int     base64_clean(const char *inp, int inlen, char *outp, int *olen);

/* EOF */
