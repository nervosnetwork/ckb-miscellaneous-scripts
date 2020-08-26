
## Purpose of the Folder
The purpose of this folder is to split ckb-c-stdlib into declaration and definition, only leaving declaration in this folder.

## Problem
The ckb-c-stdlib uses header(.h) only strategy, which header files contain both declaration and definition.
When compiling 3-rd party libraries, if we set include path to ckb-c-stdlib, the multiple definitions error occur. 

## Solution
On compiling stage of 3rd party libraries, it 
only sets include path to this folder, make compiler happy. On compiling the last .c file (e.g. rsa_sighash_all.c), it
sets include path to ckb-c-stdlib, which contains the implementation of the missing functions (like, memmv, memcpy).
