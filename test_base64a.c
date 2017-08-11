
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

const unsigned char* str = (const unsigned char*)
//"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
//"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
//"Hello world. Hello world. Hello world. Hello world. Hello world. Hello world. Hello world."
"Hello 1 world";


int main(int argc, char** argv)
{
    //printf("Testing base64.\n");
    // Test /0 printf
    //char str2[] = "Here is a nul string.\0This is after nul.";
    //printf(" '%s'\n'%.*s'\n", str2, sizeof(str2), str2);
    //return(0);
    
    int slen =  strlen(str);
    printf("org: len=%d\n'%s'\n\n", slen, str);
    int outlen = base64_calc_encodelen(slen);
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(outlen + 1);
    printf("base64 encode pre outlen=%d\n", outlen);                                           
    base64_encode(str, slen, mem, &outlen);
    //mem[outlen] = '\0';
    printf("base64 encode outlen=%d\n'%s'\n", outlen, mem);                                           
    zcheck(mem, __LINE__);             
    
    int dlen = outlen;
    char *dmem = zalloc(dlen + 2);
    printf("base64 decode pre dlen=%d\n", dlen);                                           
    base64_decode(mem, outlen, dmem, &dlen);
    //dmem[dlen] = '\0';
    printf("base64 decode dlen=%d\n'%s'\n", dlen, dmem);                                           
    zcheck(dmem, __LINE__);             
    //dump_mem(dmem, outlen);
    
    if(dlen != slen)
        {
        printf("\nError! Decode length does not match\n");
        }
    if (strcmp(str, dmem) != 0)
        {
        printf("\nError! Decode does not match\n");
        }
    zfree(mem); zfree(dmem);
    
    zleak();  
}









