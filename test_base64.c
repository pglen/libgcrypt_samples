
/* =====[ test_base64.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  aug.04.2017     Peter Glen      Terminator added

   ======================================================================= */

#include <stdio.h>
#include <string.h>

#include "zmalloc.h"
#include "base64.h"

int main(int argc, char** argv)
{
    //printf("Testing base64.\n");
    //char str[] = "Here is a nul string.\0Null.";
    //printf(" '%s' '%*s'\n", str, sizeof(str), str);
    //return(0);
    
    const unsigned char* sss = (const unsigned char*)
    "Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    "Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
    "Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world.";
    
    //zverbose(1);
     
    int slen =  strlen(sss);
    printf("org: len=%d\n'%s'\n", slen, sss);
    int outlen = base64_calc_encodelen(slen);
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(outlen + 1);
    //printf("base64 encode pre outlen=%d\n", outlen);                                           
    base64_encode(sss, slen, mem, &outlen);
    mem[outlen] = '\0';
    printf("base64 encode outlen=%d\n'%s'\n", outlen, mem);                                           
    zcheck(mem, __LINE__);             
     
    int linelen = 64;
    int limlen = outlen + 4 + outlen / linelen ;
    zline2(__LINE__, __FILE__);
    char *mem3 = zalloc(limlen);        
    //memset(mem3, limlen, 'a');        
    //printf("base64 limline pre limlen=%d\n", limlen);
    base64_limline(mem, outlen, mem3, &limlen, linelen);
    mem3[limlen] = '\0';
    printf("base64 limline limlen=%d\n'%s'\n", limlen, mem3);                                           
    
    int ulimlen = limlen;
    char *mem4 = zalloc(ulimlen);
    int ret = base64_clean(mem3, limlen, mem4, &ulimlen);
    mem4[ulimlen] = '\0';
    zcheck(mem4, __LINE__);
    printf("base64 unexpand ulimlen=%d\n'%s'\n", ulimlen, mem4);                                           
    
    int declen = base64_calc_decodelen(ulimlen);
    zline2(__LINE__, __FILE__);
    char *dmem = zalloc(declen + 1);
    base64_decode(mem4, ulimlen, dmem, &declen);
    dmem[declen] = '\0';
    printf("dec base64 len=%d\n'%s'\n", declen, dmem);
    //dump_mem(dmem, strlen(dmem));
    zline2(__LINE__, __FILE__);
    zcheck(dmem, __LINE__);
    
    if(strcmp(dmem, sss) != 0)
        {
        printf("\nData strings do not match!!!!\n");
        }
    
    zline2(__LINE__, __FILE__);
    zfree(mem);
    zfree(dmem);
    zfree(mem3);
    zfree(mem4);
    
    zleak();  
}









