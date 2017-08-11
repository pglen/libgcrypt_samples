
/* =====[ zmalloc.c ]=========================================================

   Description:     Encryption examples. Feasability study for diba 
                    [Digital Bank]. Testing libgcrypt library.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.
      0.00  jul.24.2017     Peter Glen      More
      0.00  jul.28.2017     Peter Glen      Test, SF release

   ======================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zmalloc.h"

#define POOLSIZE 1024

// Cheater malloc. Decorate as follows:
// xxxx 'a' 'b' 'c' 'd' mmmmmmm 'e' 'f' 'g' 'h'
// xxxx is 4 bytes of length, mmmmmm is the requested memory

// Expose this for testing memory corruption
void *zarr[POOLSIZE] = {NULL};

static const char *zfnamearr[POOLSIZE] = {NULL};
static int  zlinearr[POOLSIZE] = {-1};
static int  zlenarr[POOLSIZE] = {-1};

static int  zlast = 0;
static int  zlastline = 0;
static const char *zlastfile = NULL;
static int  check_on = (1==1);
static int  verbose_on = (1==0);
static int  temp_sum = 0;

static void die()
{
    printf("zmalloc: Cannot allocate memory, error exit\n");
    exit(2);
}

static int calc_sum(const char *ptr, int len)

{
    int ret = 0;
    for(int loop = 0; loop < len; loop++)
        ret += (unsigned char)ptr[loop];
    return ret;   
}


static int calc_all_sums()

{
    int ret = 0;
    
    ret += calc_sum((const char*)zarr, sizeof(zarr));
    ret += calc_sum((const char*)zfnamearr, sizeof(zfnamearr));
    ret += calc_sum((const char*)zlinearr, sizeof(zlinearr));
    ret += calc_sum((const char*)zlenarr, sizeof(zlenarr));

    //printf("Sum %d\n", ret);
    return ret;   
}

void zline2(int line, const char *fname)
{
   zlastline = line;
   zlastfile = fname;
}

void zline(int line)
{
   zlastline = line;
}

void zverbose(int flag)                       
{
    verbose_on = flag;
}

void zcheck(void *mem, int line)

{
    if(!check_on)
        return;
    
    char *mem2 = (char *)mem;
    int  *mem3 = (int  *)mem;
    char *mem4 = (char *)mem;
    
    mem2 -= 4;
    mem3 = (int *)(mem2 - sizeof(int));
    mem4 += *mem3; 
    
    //printf("%p %d '%c %c %c %c' '%c %c %c %c' \n", mem, *mem3, mem2[0], mem2[1],  mem2[2],  mem2[3],
    //                    mem4[0], mem4[1], mem4[2], mem4[3] );
    
    // See where it was allocated
    const char *afname = NULL; int aline = 0;
    for(int loop = 0; loop < zlast; loop++)
        {
        if(zarr[loop] == mem)
            {
            aline = zlinearr[loop];
            afname = zfnamearr[loop];
            }
        }
                        
    if(mem2[0] != 'a' ||  mem2[1] != 'b' ||
             mem2[2] != 'c' ||  mem2[3] != 'd')
         {
         printf("zmalloc: Memory check failed. (at beginning) Line: %d Allocated at %d (%s)\n", 
                                line, aline, afname);
         }
    if(mem4[0] != 'e' ||  mem4[1] != 'f' ||
             mem4[2] != 'g' ||  mem4[3] != 'h')
         {
         printf("zmalloc: Memory check failed. (at end) Line: %d Allocated at %d (%s)\n", 
                                line, aline, afname);
         }
}

// Use as usual realloc

void *zrealloc(void *ptr, unsigned int msize)

{
    if(ptr == NULL)
        {
        return zalloc(msize);
        }
    if(msize == 0)
        {
        zfree(ptr);
        return NULL;
        }
    
    char *mem = (char*)ptr;
    int *mem3 = (int *)(mem - (sizeof(int) + 4));
    int  xsize = *mem3; 
        
    void *memnew = zalloc(msize);
    if(msize < xsize) xsize = msize;  // Scrinking
    memcpy(memnew, ptr, xsize);
    //if(verbose_on)
        printf("zmalloc: realloc at line %d from (0x%p) %d bytes to (0x%p) %d bytes\n",
                                     zlastline, ptr, xsize, memnew, msize);
    zfree(ptr);
    return memnew;
}

// Use as usual malloc

void *zalloc(unsigned int msize)

{
    char *mem2 = NULL; int  *mem3 = NULL;
    void *mem = malloc (msize + 8 + sizeof(int));
    
    if (mem == NULL)
        return NULL;
        //die();
        
    if(zlinearr[0] == -1)
        {
        memset(zarr, 0, sizeof(zarr)); 
        memset(zlenarr, 0, sizeof(zlenarr)); 
        memset(zlinearr, 0, sizeof(zlinearr)); 
        memset(zfnamearr, 0, sizeof(zfnamearr)); 
        }
    memset(mem, 0, msize);
    
    // Decorate
    mem2 = (char*)mem;   mem3 = (int*)mem;
    *(mem3) = msize;
    *(mem2 + 4) = 'a';
    *(mem2 + 5) = 'b';
    *(mem2 + 6) = 'c';
    *(mem2 + 7) = 'd';
    
    *(mem2 + 4 + msize + sizeof(int) + 0) = 'e';
    *(mem2 + 4 + msize + sizeof(int) + 1) = 'f';
    *(mem2 + 4 + msize + sizeof(int) + 2) = 'g';
    *(mem2 + 4 + msize + sizeof(int) + 3) = 'h';
    
    //printf("%c %c %c %c \n", mem2[4], mem2[5],
    //            *(mem2 + msize + sizeof(int)), *(mem2 + msize + sizeof(int)+1) );
   
    void *ret = (void *) (mem2 + 4 + sizeof(int)); 
    zcheck(ret, zlastline );
    
    if(verbose_on)
        printf("zmalloc: Alloc at line %d (0x%p) %d bytes\n", zlastline, ret, msize);
    if(zlast < POOLSIZE)
        {
        zarr[zlast] = ret;
        zlinearr[zlast] =  zlastline;
        zlenarr[zlast]  =  msize;
        zfnamearr[zlast] =  zlastfile;
        zlast++;
        }
    else 
        {              
        // Find deleted slot
        int loop;
        for(loop = 0; loop < zlast; loop++)
            {
            //printf("Finding slot\n");
            if(zarr[loop] == (void*)0)
                {   
                zarr[loop] = ret;
                zlinearr[loop] =  zlastline;
                zlenarr[loop]  =  msize;
                zfnamearr[loop] =  zlastfile;
                break;
                }
            }
        if(loop == zlast)
            printf("zmalloc: Increase zlast memory pool\n");
        }
        
    temp_sum = calc_all_sums();
    
    return ret;
}

void zfree(void *mem)

{
    zfree2(mem, zlastline);
}

void zfree2(void *mem, int line)

{
    int *mem3 = (int *)(mem - (sizeof(int) + 4));
    int  msize = *mem3; 
    
    if(verbose_on)
        printf("zmalloc: Free at line %d (0x%p) %d bytes\n", line, mem, msize);
    
    // See if our memory was tempered with
    if(temp_sum != calc_all_sums())
        printf("zmalloc: possible dangling pointer write.\n");
                    
    // See where it was allocated
    const char *afname = NULL; int aline = -1, xlen = 0;
    for(int loop = 0; loop < zlast; loop++)
        {
        if(zarr[loop] == mem)
            {
            aline = zlinearr[loop];
            afname = zfnamearr[loop];
            xlen =  zlenarr[loop];
            }
        }
    
    // This actually prevents a program from blowing up with illegal 
    // MEMORY access (buserror)
    if(aline == -1)
        {
        printf("zmalloc: Trying to free unallocated memory at line %d (0x%p)\n",
                zlastline, mem);
        return;
        } 
       
    // Check if length is damaged
    if(xlen != msize)
        {
        if(verbose_on)
            printf("zmalloc: Damaged lenght indicator at line %d (0x%p) %d bytes.\n",
                            zlastline, mem, msize);
                            
        printf("zmalloc: Damaged length, item allocated at line %d (%s) %d bytes.\n",
                                aline, afname, xlen);
        //return;
        // Attempt to free smaller memory
        if(xlen < msize) 
            {
            *mem3 = xlen; msize = xlen;
            }
        else 
            {
            // Do not do anything else, serious corrupton suspected
            return;
            }
        }
    zcheck(mem, line);
        
    // Erase it from history
    for(int loop = 0; loop < zlast; loop++)
        {
        if(zarr[loop] == mem)
            {
            zarr[loop] = NULL;
            zfnamearr[loop] =  NULL;
            zlinearr[loop] = 0;
            zlenarr[loop] = 0;
            }
        }
    
    // Reset memory before freeing, may apply cryptographic function
    memset(mem, '\0', msize);
    
    char *mem2 = (char *)mem; 
    mem2 -= 4 + sizeof(int);
    
    temp_sum = calc_all_sums();
    
    free( (void *)mem2 );
}

//////////////////////////////////////////////////////////////////////////
// Report leaks. Return how many.

int     zleak()

{
    int ret = 0;
    for(int loop = 0; loop < zlast; loop++)
        if(zarr[loop] != NULL)
            {
            printf("zmalloc: Memory leak on %s at line %d (0x%p)\n", 
                            zfnamearr[loop], zlinearr[loop], zarr[loop]); 
            ret++;
            }
    return ret; 
}

// EOF


