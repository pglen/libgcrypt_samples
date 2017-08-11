
/* =====[ keygen.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <stdio.h>
#include <string.h>
#include <conio.h>

#include "getpass.h"
#include "zmalloc.h"

#define TRUE  (1==1)
#define FALSE (1!=1)

#define CRTL_C     '\3'
#define CRTL_D     '\4'
#define BACKSPACE  '\b'


// Strenghts:
//     Every item kind adds two points. (upper, lower, number, punct)

static int getstrength(const char *pass)
{
    int ret = 0;
    if(strpbrk((char*)pass, "1234567890"))
        {
        //printf("number token\n");
        ret += 2;
        }
    if(strpbrk((char*)pass, "abcdefghijklmnopqrstuvwxyz"))
        {
        //printf("lowercase token\n");
        ret += 2;
        }
    if(strpbrk((char*)pass, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
        {
        //printf("uppercase token\n");
        ret += 2;
        }
    // Incomplete, re visit on finaliation
    if(strpbrk((char*)pass, "*&!@#$%^&*()_+"))
        {
        //printf("punctuation token\n");
        ret += 2;
        }
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Get pass from console. Return -1 for abort.

int     getpass(const char *prompt, char *passptr, int maxlen)

{
    int ret = 0;
    unsigned int idx = 0;
    passptr[idx] = 0;
    
    printf("%s ", prompt);
    fflush(stdout);
    
    while(TRUE) {
        unsigned char cc = _getch(); 
        
        //printf(" '%c' %d ", cc, cc & 0xff);
        if(cc == 224 || cc == 0)
            {
            _getch();  // Throw away
            continue;
            }    
    
        if (cc == '\n')
            break;
        if (cc == '\r')
            break;
        if (cc == EOF)
            break;
        if (cc == CRTL_C)
            { ret = -1; break; }
        if (cc == CRTL_D)
            { ret = -1; break; }
            
        if (cc == BACKSPACE)
            {
            //printf("backspace\n");
            if(idx > 0)
                {
                idx--;
                passptr[idx] = '\0';
                putchar('\b'); putchar(' '); 
                putchar('\b');    
                }
            }
        else
            {
            passptr[idx] = cc;
            passptr[idx + 1] = '\0';
            putchar('*');    
            idx ++;
            }
        
        if (idx >= maxlen)
            break;
        }          
    //printf("got pass '%s'\n", passptr);  
    printf("\n");    
    return ret;
}

//////////////////////////////////////////////////////////////////////////
// Get pass

int getpass2(getpassx *passx)

{   
    int ret = TRUE;
    int try = 0;

    if(passx->maxlen == 0)
        return -1;
        
    char  *ppp = zalloc(passx->maxlen + 1);
    
    while((TRUE))
        {
        ret = getpass(passx->prompt, ppp, passx->maxlen);
        if (ret < 0)
            {
            ret = -1;
            break;
            }    
        if(try++ >= ALLOW_TRIES)
            {
            printf("Too many tries, giving up\n");
            ret = -1;
            break;
            }
        
        if(!passx->weak)
            {
            if(strlen(ppp) < passx->minlen)
                printf("Must be %d characters or more, try again.\n", passx->minlen);
            else if(getstrength(ppp) < passx->strength)
                printf("Pass must have upper and lower case letters and numbers, try again.\n");
            else
                break;
            }
        else
            {
            if(strlen(ppp) <= 0)
                printf("Cannot use empty pass, try again.\n");
            else
                break;
            }
        }
    if(ret < 0)
        {
        zfree(ppp);
        return ret;   
        }
           
    if(passx->nodouble == FALSE)
        {
        char  *ppp2 = zalloc(passx->maxlen + 1);
        int try2 = 0;
        while((TRUE))
            {
            ret = getpass(passx->prompt2, ppp2, passx->maxlen);
            if(ret < 0)
                break;
                
            if(strcmp(ppp, ppp2) == 0)
                break;
            
            if(try2++ >= ALLOW_TRIES)
                {
                printf("Too many tries, giving up\n");
                ret = -1;
                break;
                }
            printf("Passes do not match, try again.\n");
            }
         zfree(ppp2);
         }
    //printf("ppp '%s' maxlen %d", ppp, passx->maxlen);     
    if(ret >= 0)
        {
        strncpy(passx->pass, ppp, passx->maxlen);
        }
    zfree(ppp); 
    
    return ret;
}









