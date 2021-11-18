#!/bin/bash
if [ $# -eq 0 ]
  then
    echo "Runtime encryption PoC by Tretorn"
    echo "Learn how to program the assembly file on hello.asm comments!"
    echo "Usage ./cryptload.sh <file.asm>"
    exit 1
fi
rm -f *.o
rm -f *.out

nasm -felf64 -o $1.o $1
echo \#include \"main.h\" > shellcode.c
shellcode=$(objdump -d $1.o|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'|sed 's/$/;/'|sed 's/^/uint8_t shellcode[] = /')
size=$(echo $shellcode |sed 's/[^\\]//g' | awk '{ print length }')
echo $shellcode >> shellcode.c
echo $size|sed 's/^/int shellcode_size = /'|sed 's/$/;/' >> shellcode.c
gcc main.c hash_table.c -o cuak.out shellcode.c
./cuak.out

