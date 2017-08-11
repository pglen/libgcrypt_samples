
/* =====[ dump.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <unistd.h>

#include "gcrypt.h"
#include "gcry.h"
#include "gsexp.h"
#include "getpass.h"
#include "zmalloc.h"

//int keysize = 4096;
int keysize = 1024;

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: dump.exe filename\n");
        xerr("Invalid arguments.");
    }
    
    char* fname = argv[1];
    
    FILE* lockf = fopen(fname, "rb");
    if (!lockf) {
        xerr("fopen() failed");
    }

    /* Grab the file */
    
    unsigned int mem_len = getfsize(lockf);
    //printf("File size %d\n", mem_len);
    
    zline(__LINE__);
    void* mem_buf = zalloc(mem_len);
    if (!mem_buf) {
        xerr("malloc: could not allocate rsa buffer");
    }

    if (fread(mem_buf, mem_len, 1, lockf) != 1) {
        xerr("fread() failed");
    }
    dump_mem(mem_buf, mem_len);  
    //printf("%s\n", mem_buf);
    zfree(mem_buf);
    zleak();
}



