
/* =====[ encrypt.c ]=========================================================

   Description:     Encryption examples. Feasability study for diba 
                    [Digital Bank]. Testing libgcrypt library.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <stdio.h>
#include <gcrypt.h>
#include <assert.h>

#include "zmalloc.h"

char key[] = "This is the key we are using";

void printerr(int err, char *str)

{
    fprintf (stderr, "%s\n", str);

    fprintf (stderr, "Failure: &#37;s/%s\n",
                    gcry_strsource (err),
                        gcry_strerror (err));
    fprintf (stdout, "Failure: %s/%s\n",
                    gcry_strsource (err),
                        gcry_strerror (err));
    
}       

void printhex(void *mem, int len)
{
    int aa;
    char *ptr = (char *)mem;
    for(aa = 0; aa < len; aa++)
        {
        printf("%02x ", ptr[aa] & 0xff);
        if (aa % 32 == 31)
            printf("\n");
        }
} 

//////////////////////////////////////////////////////////////////////////
    
int main()

{
    gcry_cipher_hd_t handle;
    gcry_error_t err = 0;
    
    char *plain_text, *out, *deout ;
    
    gcry_check_version (NULL);
    gcry_control( GCRYCTL_DISABLE_SECMEM_WARN );
    gcry_control( GCRYCTL_INIT_SECMEM, 16384, 0 );
    
    //err = gcry_cipher_open (&handle, GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, 0);
    
    int cyp = GCRY_CIPHER_TWOFISH; 
    //int cyp = GCRY_CIPHER_IDEA;
    int mode = GCRY_CIPHER_MODE_ECB;
 
    err = gcry_cipher_open (&handle, cyp, mode, 0);
    if (err)
        printerr(err, "open");
    
    int keysize  =  gcry_cipher_get_algo_keylen(cyp);
    int blklen = gcry_cipher_get_algo_blklen(cyp);
    printf("Keysize: %d Blocklength: %d\n", keysize, blklen);

    //size_t size_of_plain = sizeof(char) * 6;
    size_t size_of_crypt = sizeof(char) * 2 * blklen;
    
    out =  zalloc (size_of_crypt);
    deout = zalloc (size_of_crypt);
    
    plain_text = zalloc (blklen);
    strncpy(plain_text , "Secret Text", blklen);
    plain_text[blklen - 1] = 0;
    
    err = gcry_cipher_setkey (handle, key, keysize);
    if (err)
        printerr(err, "setkey");
    
    //gcry_cipher_final(handle);
    err =  gcry_cipher_encrypt (handle,
          (unsigned char *)out, size_of_crypt, (const unsigned char *)plain_text, blklen);
    if (err)
        printerr(err, "encrypt");
       
    err = gcry_cipher_setkey (handle, key,  keysize);
    if (err)
        printerr(err, "setkey");
    
    //gcry_cipher_final(handle);
    err =  gcry_cipher_decrypt (handle,
          (unsigned char *)deout, size_of_crypt, (const unsigned char *)out, blklen);
    if (err)
         {
         printerr(err, "decrypt");
         }
         
    printf("Plain text: (len=%d) '%s'", strlen(plain_text), plain_text);
    printf("\nCypher:\n");
    printhex(out, size_of_crypt);
    printf("\nCypher end.\n");
    printf("Decr text: '%s'\n", deout);
      
  zfree(plain_text);
  zfree(out);
  zfree(deout);
  gcry_cipher_close(handle);
  return 0;
}	


