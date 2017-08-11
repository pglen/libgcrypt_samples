
/* =====[ keygen.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  aug03.2017     Peter Glen      Initial version.

   ======================================================================= */
 
#include <stdio.h>

#include "gcrypt.h"
#include "gcry.h"
#include "gsexp.h"
#include "zmalloc.h"

//////////////////////////////////////////////////////////////////////////
// Print sexp to memory
// Free the resulting pointer

char *sprint_sexp(gcry_sexp_t sexp, int *len, int format)

{
    int slen = gcry_sexp_sprint(sexp, format, NULL, 0);
    *len = 0;
    zline2(__LINE__, __FILE__);
    char *ppp = (char*)zalloc(slen+1);
    if(ppp == NULL)
        return NULL;
    
    gcry_sexp_sprint(sexp, format, ppp, slen);
    *len = slen;
    // Zero terminate
    ppp[slen-1] = '\0';
    return(ppp);
}    

//////////////////////////////////////////////////////////////////////////
// Print sexp to stdout

void print_sexp(gcry_sexp_t rsa_keypair)

{
    int len;
    char *ppp = sprint_sexp(rsa_keypair, &len, GCRYSEXP_FMT_ADVANCED);
    if(ppp == NULL)
        return;
    printf("%s\n", ppp);
    zfree(ppp);
}    

void dump_mem(const char *ptr, int len)

{
    int loop, cut = 16, base = 0;
    
    if (ptr == NULL) 
        {
        printf("NULL\n");
        return;
        }
        
    printf("Begin: %p (len=%d)\n", ptr, len);
    while(1==1)
        {
        printf(" ");
        for(loop = 0; loop < 16; loop++)
            {
            if(base + loop < len)
                {
                printf("%.02x", ptr[base + loop] & 0xff);
                if(loop < 15)
                    printf("-");
                }
            else
                printf("   ");
            }
        printf("   ");
        for(loop = 0; loop < 16; loop++)
            {
            if(base + loop < len)
                {
                unsigned char chh = ptr[base + loop] & 0xff;
                if(chh < 128 && chh >= 32 )
                    printf("%c", chh);
                else
                    printf(".");
                }
            else
                printf(" ");
            }
        printf("\n");
        base += 16;
        if(base >= len)
            break;
        }
    printf("End\n");
}    

static int decode_one(gcry_sexp_t list, const char *findstr)

{
    int len = 0, onelen = gcry_sexp_length(list);
    
    for(int loop = 0; loop < onelen; loop++)
        {
        const char *data = gcry_sexp_nth_data(list, loop, &len);
        if (data == NULL)
            decode_sexp(gcry_sexp_cdr(list), findstr);
        else
            {
            if(strncmp(findstr, data, len) == 0)
                {
                const char *data2 = gcry_sexp_nth_data(list, loop + 1, &len);
                if (data == NULL)
                    return 0;
                //printf("data%d '%.*s'\n", len, len, data);
                //dump_mem(data, len);
                }
            }
        }
}    

int decode_sexp(gcry_sexp_t list, const char *findstr)

{
    int ret = 0;
    
    for (int loop = 0; loop < gcry_sexp_length(list); loop++)
        {
        gcry_sexp_t element = gcry_sexp_nth(list, loop);
        //printf("element start\n");
        //print_sexp(element);
        //printf("\nelement end\n");
        decode_one(element, findstr);
        }
    return ret;
}

/* EOF */


