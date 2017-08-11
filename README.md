README

  These are encryption / decryption samples for the gcrypt library. 
  
  They can be used as a standalone project for 
  
            key generation / encryption / decryption.

FILES

    keygen          --      Key generator.
    asencrypt       --      Asymmetric encryption with public key.
    asdecrypt       --      Asymmetric decryption with private key.
    
    
 Encryption:
    
    asencrypt.exe -i infile.txt -o outfile.enc testkey.pub  
        
 Decryption: 
            
    asdecrypt.exe -i infile.enc -o outfile.dec -p password_for_key testkey.key
            
 See Makefile for typical usage. The programs will print basic usage 
information on request.

BUILD

 All the files are built on Windows using MSYS and MinGW. The files should
build on linux and variants with little modification.
 
PREP

 Build the glibcrypt library first. This project will look for the built
libs and includes in the .lib subdir under the original build directories.
This allows installation-less build. (for test and experimentation)

NOTABLES

  I made a small malloc subsystem. It can be used to detect leaks very easily.
Use zalloc() like you would use malloc(). If you make an alloc mistake, this 
malloc gently prints a string like:

    zmalloc: Memory leak on gcry.c at line 711 (0x010A1178)    
    
  Also created a base64 encode / decode subsystem. See headers and source 
for more info.

FILE FORMAT

 The output format of the encrypted file is base64 line aligned to 64 char
length. The header and trailer line contains the RSA string delimiter.
"-----BEGIN GCRYPT RSA CYPHER-----" etc ...
Under the hood the file is in chunks, determined by the key size.
The chunk starts with a two byte length and data follows. The next 
chunk start is calculated from the length of the current chunk. Like this:

    LEN LEN DATA ..... DATA  LEN LEN DATA ....
    |------------------------|
    
 This is the simplest (I think) way to adapt tho the variable length output
of the asymmetric encryption.    


TESTING

 'make tests' will build the needed files and execute a diff on generated 
outputs. It is comparing them with expected output of the original files. 
Test passes if the diffs are silent.

FEEDBACK

This code was developed for a larger project. However, taming the library is
a common task, so I shared it ...

peterglen99@gmail.com

            
