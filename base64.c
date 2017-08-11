
/* =====[ base64.c ]=========================================================

   Description:     Encryption excamples. Feasability study for diba 
                    [Digital Bank].

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  jul.14.2017     Peter Glen      Initial version.

   ======================================================================= */

#include <stdio.h>
#include <stdint.h>
#include <limits.h>

//////////////////////////////////////////////////////////////////////////
// Clumsy attempt to detect 32 bit build

//#define SIZEOF(x) ((char*)(&(x) + 1) - (char*)&(x))

#ifndef UINTPTR_MAX
#error Not defined UINTPTR_MAX
#endif

#ifndef UINT_MAX
#error  Not defined UINT_MAX
#endif

#if UINT_MAX != 0xffffffff
 #error "Unexpected integer size, expecting a 32 bit machine."
#endif

#if UINTPTR_MAX <= UINT_MAX
    // Compile 32 bit
    #ifndef uint32_t
        typedef unsigned int uint32_t ;
    #endif
#else
    #error Integer is not 32 bit, editing needed __SIZEOF_INT__
#endif

static void build_decoding_table() ;
static char decoding_table[256] = {0};
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
                                
static int mod_table[] = {0, 2, 1};

// Encode 

int  base64_calc_encodelen(int len)
{
    return  ((4 * (len + 2)) / 3) + 3;
}

int base64_encode(const unsigned char *data,
                    int input_length, char *encoded_data, int *output_length) 
{
    int ret = 0;
    
    if (*output_length < 4 * ((input_length + 2) / 3) + 1)
        return -1;

    if (encoded_data == NULL) return -1;
    int domlen = (input_length / 3) * 3;
    //printf("input_length=%d domlen=%d outlen=%d\n", 
    //                    input_length, domlen, (domlen / 3) * 4);
    int ii, jj;
    for (ii = 0, jj = 0; ii < domlen;) {

        uint32_t octet_a = ii < input_length ? (unsigned char)data[ii++] : 0;
        uint32_t octet_b = ii < input_length ? (unsigned char)data[ii++] : 0;
        uint32_t octet_c = ii < input_length ? (unsigned char)data[ii++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[jj++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[jj++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[jj++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[jj++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    // Output final sequence
    if((input_length) % 3 == 2)
        {
        //printf("add two %c %c ", data[ii], data[ii + 1]);
        uint32_t octet_a = ii < input_length ? (unsigned char)data[ii++] : 0;
        uint32_t octet_b = ii < input_length ? (unsigned char)data[ii++] : 0;
        
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08);

        encoded_data[jj++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[jj++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[jj++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[jj++] = '=';
        }
    if((input_length % 3) == 1)
        {
        //printf("add one %c ", data[ii]);
        uint32_t octet_a = ii < input_length ? (unsigned char)data[ii++] : 0;
        
        uint32_t triple = (octet_a << 0x10);

        encoded_data[jj++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[jj++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[jj++] = '=';
        encoded_data[jj++] = '=';
        }
        
    if(jj < *output_length)
        encoded_data[jj] =  '\0';
    *output_length = jj;    
    return ret;
}

int base64_calc_decodelen(int len)
{
    return (len / 4) * 3 + 1;
}

// Decode

int     base64_decode(const char *data,
                             int input_length, unsigned char *decoded_data,
                             int *output_length) 
{
    int ret = 0;
    
    if (decoding_table[0] == 0) build_decoding_table();

    if (decoded_data == 0L) return -1;

    if (input_length % 4 != 0) 
        {
        printf("Length not divided by four");
        return -1;
        }
    int expected_length = (input_length * 3) / 4;                       
    if (*output_length < expected_length)
        {
        printf("Short buffer passed.");
        return -1;
        }
    if (data[input_length - 1] == '=') expected_length--;
    if (data[input_length - 2] == '=') expected_length--;
       
    int domlen = (input_length / 4) * 4;
    //printf("input_length=%d domlen=%d outlen=%d\n", 
    //                    input_length, domlen, (domlen / 4) * 3);

    int ii, jj;
    for (ii = 0, jj = 0; ii < domlen; /*none*/) 
        {
        uint32_t sextet_a = data[ii] == '=' ? 0 & ii++ : decoding_table[data[ii++]];
        uint32_t sextet_b = data[ii] == '=' ? 0 & ii++ : decoding_table[data[ii++]];
        uint32_t sextet_c = data[ii] == '=' ? 0 & ii++ : decoding_table[data[ii++]];
        uint32_t sextet_d = data[ii] == '=' ? 0 & ii++ : decoding_table[data[ii++]];

        uint32_t triple =     (sextet_a << 3 * 6)
                            + (sextet_b << 2 * 6)
                            + (sextet_c << 1 * 6)
                            + (sextet_d << 0 * 6);

        if (jj < expected_length) decoded_data[jj++] = (triple >> 2 * 8) & 0xFF;
        if (jj < expected_length) decoded_data[jj++] = (triple >> 1 * 8) & 0xFF;
        if (jj < expected_length) decoded_data[jj++] = (triple >> 0 * 8) & 0xFF;
    }
    
    if(jj < *output_length)
        decoded_data[jj] =  '\0';
    *output_length = jj; 
    return ret;
}
                   
//////////////////////////////////////////////////////////////////////////
// Limit the line length of base64 strings


int base64_limline(const char *inp, int inlen, char *outp, int *olen, int linelen)

{
    int ret = 0, loop = 0, cnt = 0, prog = 0;
    
    for(loop = 0; loop <  inlen; loop ++)
        {
        outp[prog] = inp[loop];  prog ++;
        if(prog >= *olen) { ret = -1; break; }
        
        if((prog % (linelen + 1)) == linelen)         
            {
            outp[prog] = '\n';  prog++;
            if(prog >= *olen) { ret = -1; break; }
            }
        }
    // Zero terminate
    if(prog < *olen)
        { 
        outp[prog] = '\0'; 
    
        // Do not do this, as it cheats on binary data ... 
        // however it is a safety catch in case you put printf to it
        // prog ++; 
        }
    else
        { ret = -1;   }
    *olen = prog;
    return ret;
}

int base64_clean(const char *inp, int inlen, char *outp, int *olen)
{
    int ret = 0, loop = 0, cnt = 0, prog = 0;
    
    for(loop = 0; loop <  inlen; loop ++)
        {
        unsigned char cch = inp[loop];
        if( (cch == '+') || (cch == '/') || (cch == '=') || 
             ((cch >= 'a') && (cch <= 'z')) ||
               ((cch >= 'A') && (cch <= 'Z')) ||
                  ((cch >= '0') && (cch <= '9'))
           )
            {
            outp[prog] =  cch;  prog ++;
            if(prog >= *olen)
                {
                ret = -1; break;
                }
            }
        }
        
    if(prog < *olen)
        { 
        //outp[prog] = '\0'; //prog ++; 
        }
    else
        { ret = -1;   }
    *olen = prog;
    return ret;   
}

//////////////////////////////////////////////////////////////////////////
// Helpers

static void build_decoding_table() 
{
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = (unsigned char)i;
   
}














