
/* =====[ test_base64.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <stdio.h>
#include <string.h>

#include "zmalloc.h"
#include "base64.h"

int main(int argc, char** argv)

{
    printf("\nTesting zmalloc, silent OK\n");
     
    zline2(__LINE__, __FILE__);
    char *mem0 = zalloc(1000);
    zcheck(mem0, __LINE__);             
    zline(__LINE__);
    char *mem0a = zrealloc(mem0, 1200);
    zcheck(mem0a, __LINE__);             
    zline(__LINE__);
    zfree(mem0a);
    
    #if 0
    zverbose(1);
    printf("\nTesting zmalloc, verbose OK\n");
    int outlen = 100;
    zline2(__LINE__, __FILE__);
    char *mem = zalloc(outlen);
    zcheck(mem, __LINE__);             
    zline(__LINE__);
    zfree(mem);
    zverbose(0);
    #endif
    
     printf("\nTesting zmalloc, damage past end\n");
    zline2(__LINE__, __FILE__);
    int outlen2 = 200;
    zline2(__LINE__, __FILE__);
    char *mem2 = zalloc(outlen2);
    mem2[outlen2] = 'z';
    zline2(__LINE__, __FILE__);
    //zcheck(mem2, __LINE__);
    zfree(mem2);
    
    printf("\nTesting zmalloc, damage before beginning\n");
    zline(__LINE__);
    int outlen4 = 200;
    zline2(__LINE__, __FILE__);
    char *mem4 = zalloc(outlen4);
    mem4[-1] = 'x';
    zline2(__LINE__, __FILE__);
    //zcheck(mem4, __LINE__);
    zfree(mem4);

    printf("\nTesing attempt to free memory not allocated\n");
    char *ptr2 = "test";
    zfree(ptr2);
 
    printf("\nTesting zmalloc, not freed\n");
    zline(__LINE__);
    int outlen3 = 300;
    zline2(__LINE__, __FILE__);
    char *mem3 = zalloc(outlen3);
    zline2(__LINE__, __FILE__);
    
    zleak();  
    zfree(mem3);

    printf("\nTesting zmalloc, multiple alloc, some freed\n");
    char *memarr[10];
    int iter = sizeof(memarr) / sizeof(int);
    zline2(__LINE__, __FILE__);
    for(int loop = 0; loop < iter; loop++)
        memarr[loop] = zalloc(20);
    for(int loop = 0; loop < iter - 1; loop++)
        zfree(memarr[loop]);
    zleak();
    // Free it so further reports will not show it:
    zfree(memarr[iter-1]);  
              
    printf("\nTesting zmalloc, damage on length indicator\n");
    zline(__LINE__);
    int outlen5 = 200;
    zline2(__LINE__, __FILE__);
    char *mem5 = zalloc(outlen5);
    mem4[-5] = 'x';
    zline2(__LINE__, __FILE__);
    //zcheck(mem5, __LINE__);
    zfree(mem5);
    
    printf("\nTest corrupted memory\n");
    extern void *zarr[];
    zline2(__LINE__, __FILE__);
    char *memc0 = zalloc(1000);
    zarr[0] = (void*)100;
    zcheck(memc0, __LINE__);             
    zline(__LINE__);
    zfree(memc0);
    zarr[0] = (void*)0;
    
    printf("\nFinal report: (should be blank)\n");
    zleak();  
}









