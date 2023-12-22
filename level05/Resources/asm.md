# level05
```
objdump -M intel -d level05
objdump -s -j .data level05
```

## main
```
08048444 <main>:
8048444:       55                      push   ebp
8048445:       89 e5                   mov    ebp,esp
8048447:       57                      push   edi
8048448:       53                      push   ebx
8048449:       83 e4 f0                and    esp,0xfffffff0
804844c:       81 ec 90 00 00 00       sub    esp,0x90
8048452:       c7 84 24 8c 00 00 00    mov    DWORD PTR [esp+0x8c],0x0
8048459:       00 00 00 00
804845d:       a1 f0 97 04 08          mov    eax,ds:0x80497f0
8048462:       89 44 24 08             mov    DWORD PTR [esp+0x8],eax
8048466:       c7 44 24 04 64 00 00    mov    DWORD PTR [esp+0x4],0x64
804846d:       00
804846e:       8d 44 24 28             lea    eax,[esp+0x28]
8048472:       89 04 24                mov    DWORD PTR [esp],eax
8048475:       e8 d6 fe ff ff          call   8048350 <fgets@plt>
804847a:       c7 84 24 8c 00 00 00    mov    DWORD PTR [esp+0x8c],0x0
8048481:       00 00 00 00
8048485:       eb 4c                   jmp    80484d3 <main+0x8f>
8048487:       8d 44 24 28             lea    eax,[esp+0x28]
804848b:       03 84 24 8c 00 00 00    add    eax,DWORD PTR [esp+0x8c]
8048492:       0f b6 00                movzx  eax,BYTE PTR [eax]
8048495:       3c 40                   cmp    al,0x40
8048497:       7e 32                   jle    80484cb <main+0x87>
8048499:       8d 44 24 28             lea    eax,[esp+0x28]
804849d:       03 84 24 8c 00 00 00    add    eax,DWORD PTR [esp+0x8c]
80484a4:       0f b6 00                movzx  eax,BYTE PTR [eax]
80484a7:       3c 5a                   cmp    al,0x5a
80484a9:       7f 20                   jg     80484cb <main+0x87>
80484ab:       8d 44 24 28             lea    eax,[esp+0x28]
80484af:       03 84 24 8c 00 00 00    add    eax,DWORD PTR [esp+0x8c]
80484b6:       0f b6 00                movzx  eax,BYTE PTR [eax]
80484b9:       89 c2                   mov    edx,eax
80484bb:       83 f2 20                xor    edx,0x20
80484be:       8d 44 24 28             lea    eax,[esp+0x28]
80484c2:       03 84 24 8c 00 00 00    add    eax,DWORD PTR [esp+0x8c]
80484c9:       88 10                   mov    BYTE PTR [eax],dl
80484cb:       83 84 24 8c 00 00 00    add    DWORD PTR [esp+0x8c],0x1
80484d2:       01
80484d3:       8b 9c 24 8c 00 00 00    mov    ebx,DWORD PTR [esp+0x8c]
80484da:       8d 44 24 28             lea    eax,[esp+0x28]
80484de:       c7 44 24 1c ff ff ff    mov    DWORD PTR [esp+0x1c],0xffffffff
80484e5:       ff
80484e6:       89 c2                   mov    edx,eax
80484e8:       b8 00 00 00 00          mov    eax,0x0
80484ed:       8b 4c 24 1c             mov    ecx,DWORD PTR [esp+0x1c]
80484f1:       89 d7                   mov    edi,edx
80484f3:       f2 ae                   repnz scas al,BYTE PTR es:[edi]
80484f5:       89 c8                   mov    eax,ecx
80484f7:       f7 d0                   not    eax
80484f9:       83 e8 01                sub    eax,0x1
80484fc:       39 c3                   cmp    ebx,eax
80484fe:       72 87                   jb     8048487 <main+0x43>
8048500:       8d 44 24 28             lea    eax,[esp+0x28]
8048504:       89 04 24                mov    DWORD PTR [esp],eax
8048507:       e8 34 fe ff ff          call   8048340 <printf@plt>
804850c:       c7 04 24 00 00 00 00    mov    DWORD PTR [esp],0x0
8048513:       e8 58 fe ff ff          call   8048370 <exit@plt>
8048518:       90                      nop
```

- `8048444 - 804844c` Prep stack and stack alignment, allocates 144 bytes for the stack. 
- `8048452 - 80484a9` Write 0 to a variable called **count** at `[esp+0x8c]`. Load a buffer from `[esp+0x28]` aka **inputbuf**, call `fgets(inputbuf, 100, stdin)`. Write 0 to **count** again and then jump to `80484d3` (I dont know why its so abrupt, loop maybe?), load address **inputbuf** to a tmp variable and increment the address by **count**. Derefrence the inputbuf and compare it with `64` and `90`. If its less or equals than `64` or more than `90` (not capital alphabet), jump to `80484cb`. 
- `80484ab - 8048513` Load address of **inputbuf** and increment by **count**. Derefrence the index at **inputbuf** and `xor 32` the element. `inputbuf[count] = xorred_res` and increment **count**. while `strlen(inputbuf)` is more than **count**, jump back to `8048487.` When the loop exits, `printf(inputbuf)` and `exit(0)`

