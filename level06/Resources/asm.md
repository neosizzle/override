# level06
```
objdump -M intel -d level06
objdump -s -j .data level06
```

## main
```
8048879:       55                      push   ebp
804887a:       89 e5                   mov    ebp,esp
804887c:       83 e4 f0                and    esp,0xfffffff0
804887f:       83 ec 50                sub    esp,0x50
8048882:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
8048885:       89 44 24 1c             mov    DWORD PTR [esp+0x1c],eax
8048889:       65 a1 14 00 00 00       mov    eax,gs:0x14
804888f:       89 44 24 4c             mov    DWORD PTR [esp+0x4c],eax
8048893:       31 c0                   xor    eax,eax
8048895:       50                      push   eax
8048896:       31 c0                   xor    eax,eax
8048898:       74 03                   je     804889d <main+0x24>
804889a:       83 c4 04                add    esp,0x4
804889d:       58                      pop    eax
804889e:       c7 04 24 d4 8a 04 08    mov    DWORD PTR [esp],0x8048ad4
80488a5:       e8 e6 fc ff ff          call   8048590 <puts@plt>
80488aa:       c7 04 24 f8 8a 04 08    mov    DWORD PTR [esp],0x8048af8
80488b1:       e8 da fc ff ff          call   8048590 <puts@plt>
80488b6:       c7 04 24 d4 8a 04 08    mov    DWORD PTR [esp],0x8048ad4
80488bd:       e8 ce fc ff ff          call   8048590 <puts@plt>
80488c2:       b8 08 8b 04 08          mov    eax,0x8048b08
80488c7:       89 04 24                mov    DWORD PTR [esp],eax
80488ca:       e8 41 fc ff ff          call   8048510 <printf@plt>
80488cf:       a1 60 a0 04 08          mov    eax,ds:0x804a060
80488d4:       89 44 24 08             mov    DWORD PTR [esp+0x8],eax
80488d8:       c7 44 24 04 20 00 00    mov    DWORD PTR [esp+0x4],0x20
80488df:       00
80488e0:       8d 44 24 2c             lea    eax,[esp+0x2c]
80488e4:       89 04 24                mov    DWORD PTR [esp],eax
80488e7:       e8 64 fc ff ff          call   8048550 <fgets@plt>
80488ec:       c7 04 24 d4 8a 04 08    mov    DWORD PTR [esp],0x8048ad4
80488f3:       e8 98 fc ff ff          call   8048590 <puts@plt>
80488f8:       c7 04 24 1c 8b 04 08    mov    DWORD PTR [esp],0x8048b1c
80488ff:       e8 8c fc ff ff          call   8048590 <puts@plt>
8048904:       c7 04 24 d4 8a 04 08    mov    DWORD PTR [esp],0x8048ad4
804890b:       e8 80 fc ff ff          call   8048590 <puts@plt>
8048910:       b8 40 8b 04 08          mov    eax,0x8048b40
8048915:       89 04 24                mov    DWORD PTR [esp],eax
8048918:       e8 f3 fb ff ff          call   8048510 <printf@plt>
804891d:       b8 60 8a 04 08          mov    eax,0x8048a60
8048922:       8d 54 24 28             lea    edx,[esp+0x28]
8048926:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
804892a:       89 04 24                mov    DWORD PTR [esp],eax
804892d:       e8 ae fc ff ff          call   80485e0 <__isoc99_scanf@plt>
8048932:       8b 44 24 28             mov    eax,DWORD PTR [esp+0x28]
8048936:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
804893a:       8d 44 24 2c             lea    eax,[esp+0x2c]
804893e:       89 04 24                mov    DWORD PTR [esp],eax
8048941:       e8 02 fe ff ff          call   8048748 <auth>
8048946:       85 c0                   test   eax,eax
8048948:       75 1f                   jne    8048969 <main+0xf0>
804894a:       c7 04 24 52 8b 04 08    mov    DWORD PTR [esp],0x8048b52
8048951:       e8 3a fc ff ff          call   8048590 <puts@plt>
8048956:       c7 04 24 61 8b 04 08    mov    DWORD PTR [esp],0x8048b61
804895d:       e8 3e fc ff ff          call   80485a0 <system@plt>
8048962:       b8 00 00 00 00          mov    eax,0x0
8048967:       eb 05                   jmp    804896e <main+0xf5>
8048969:       b8 01 00 00 00          mov    eax,0x1
804896e:       8b 54 24 4c             mov    edx,DWORD PTR [esp+0x4c]
8048972:       65 33 15 14 00 00 00    xor    edx,DWORD PTR gs:0x14
8048979:       74 05                   je     8048980 <main+0x107>
804897b:       e8 00 fc ff ff          call   8048580 <__stack_chk_fail@plt>
8048980:       c9                      leave
8048981:       c3                      ret
8048982:       90                      nop
```
- `8048879 - 804887f` Set up stack frame, stack alignment and allocates 80 bytes for the stack
- `8048882 - 8048898` Load argv into `[esp+0x1c]` aka **argv** and 20 into `[esp+0x4c]` aka **canary**. and save `canary ^ canary` in memory, aka **canary_xor**. `canary ^ canary` again, and if its true, jump to `804889d`
- `804889a - 80488ca` Idk why they want to shrink the stack by 4 and pop the result to eax, I assume its for stack canary. Call these in order : 
```
puts("***********************************");
puts("*    level06    *");
puts("***********************************");
printf("-> Enter Login:");

```
- `80488cf - 8048918` Load a buffer to `[esp+0x2c]` aka **logininput** and call `fgets(logininput, 32, stdin)` and calls these in order: 
```
puts("***********************************");
puts("*    NEW ACOUNT DETECTED    *");
puts("***********************************");
printf("-> Enter Serial:");
```
- `804891d - 804897b` Load an unsigned int in `[esp+0x28]` aka **serial_input**. Call `scanf("%u", &serialinput);`. After that, call `auth(logininput, serialinput)`. If the return value is not equal zero, check the stack overflow and return. If it is, `system("/bin/sh")`

## auth 
 
 ```
8048748:       55                      push   ebp
8048749:       89 e5                   mov    ebp,esp
804874b:       83 ec 28                sub    esp,0x28
804874e:       c7 44 24 04 63 8a 04    mov    DWORD PTR [esp+0x4],0x8048a63
8048755:       08
8048756:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
8048759:       89 04 24                mov    DWORD PTR [esp],eax
804875c:       e8 bf fd ff ff          call   8048520 <strcspn@plt>
8048761:       03 45 08                add    eax,DWORD PTR [ebp+0x8]
8048764:       c6 00 00                mov    BYTE PTR [eax],0x0
8048767:       c7 44 24 04 20 00 00    mov    DWORD PTR [esp+0x4],0x20
804876e:       00
804876f:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
8048772:       89 04 24                mov    DWORD PTR [esp],eax
8048775:       e8 56 fe ff ff          call   80485d0 <strnlen@plt>
804877a:       89 45 f4                mov    DWORD PTR [ebp-0xc],eax
804877d:       50                      push   eax
804877e:       31 c0                   xor    eax,eax
8048780:       74 03                   je     8048785 <auth+0x3d>
8048782:       83 c4 04                add    esp,0x4
8048785:       58                      pop    eax
8048786:       83 7d f4 05             cmp    DWORD PTR [ebp-0xc],0x5
804878a:       7f 0a                   jg     8048796 <auth+0x4e>
804878c:       b8 01 00 00 00          mov    eax,0x1
8048791:       e9 e1 00 00 00          jmp    8048877 <auth+0x12f>
8048796:       c7 44 24 0c 00 00 00    mov    DWORD PTR [esp+0xc],0x0
804879d:       00
804879e:       c7 44 24 08 01 00 00    mov    DWORD PTR [esp+0x8],0x1
80487a5:       00
80487a6:       c7 44 24 04 00 00 00    mov    DWORD PTR [esp+0x4],0x0
80487ad:       00
80487ae:       c7 04 24 00 00 00 00    mov    DWORD PTR [esp],0x0
80487b5:       e8 36 fe ff ff          call   80485f0 <ptrace@plt>
80487ba:       83 f8 ff                cmp    eax,0xffffffff
80487bd:       75 2e                   jne    80487ed <auth+0xa5>
80487bf:       c7 04 24 68 8a 04 08    mov    DWORD PTR [esp],0x8048a68
80487c6:       e8 c5 fd ff ff          call   8048590 <puts@plt>
80487cb:       c7 04 24 8c 8a 04 08    mov    DWORD PTR [esp],0x8048a8c
80487d2:       e8 b9 fd ff ff          call   8048590 <puts@plt>
80487d7:       c7 04 24 b0 8a 04 08    mov    DWORD PTR [esp],0x8048ab0
80487de:       e8 ad fd ff ff          call   8048590 <puts@plt>
80487e3:       b8 01 00 00 00          mov    eax,0x1
80487e8:       e9 8a 00 00 00          jmp    8048877 <auth+0x12f>
80487ed:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
80487f0:       83 c0 03                add    eax,0x3
80487f3:       0f b6 00                movzx  eax,BYTE PTR [eax]
80487f6:       0f be c0                movsx  eax,al
80487f9:       35 37 13 00 00          xor    eax,0x1337
80487fe:       05 ed ed 5e 00          add    eax,0x5eeded
8048803:       89 45 f0                mov    DWORD PTR [ebp-0x10],eax
8048806:       c7 45 ec 00 00 00 00    mov    DWORD PTR [ebp-0x14],0x0
804880d:       eb 4c                   jmp    804885b <auth+0x113>
804880f:       8b 45 ec                mov    eax,DWORD PTR [ebp-0x14]
8048812:       03 45 08                add    eax,DWORD PTR [ebp+0x8]
8048815:       0f b6 00                movzx  eax,BYTE PTR [eax]
8048818:       3c 1f                   cmp    al,0x1f
804881a:       7f 07                   jg     8048823 <auth+0xdb>
804881c:       b8 01 00 00 00          mov    eax,0x1
8048821:       eb 54                   jmp    8048877 <auth+0x12f>
8048823:       8b 45 ec                mov    eax,DWORD PTR [ebp-0x14]
8048826:       03 45 08                add    eax,DWORD PTR [ebp+0x8]
8048829:       0f b6 00                movzx  eax,BYTE PTR [eax]
804882c:       0f be c0                movsx  eax,al
804882f:       89 c1                   mov    ecx,eax
8048831:       33 4d f0                xor    ecx,DWORD PTR [ebp-0x10]
8048834:       ba 2b 3b 23 88          mov    edx,0x88233b2b
8048839:       89 c8                   mov    eax,ecx
804883b:       f7 e2                   mul    edx
804883d:       89 c8                   mov    eax,ecx
804883f:       29 d0                   sub    eax,edx
8048841:       d1 e8                   shr    eax,1
8048843:       01 d0                   add    eax,edx
8048845:       c1 e8 0a                shr    eax,0xa
8048848:       69 c0 39 05 00 00       imul   eax,eax,0x539
804884e:       89 ca                   mov    edx,ecx
8048850:       29 c2                   sub    edx,eax
8048852:       89 d0                   mov    eax,edx
8048854:       01 45 f0                add    DWORD PTR [ebp-0x10],eax
8048857:       83 45 ec 01             add    DWORD PTR [ebp-0x14],0x1
804885b:       8b 45 ec                mov    eax,DWORD PTR [ebp-0x14]
804885e:       3b 45 f4                cmp    eax,DWORD PTR [ebp-0xc]
8048861:       7c ac                   jl     804880f <auth+0xc7>
8048863:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
8048866:       3b 45 f0                cmp    eax,DWORD PTR [ebp-0x10]
8048869:       74 07                   je     8048872 <auth+0x12a>
804886b:       b8 01 00 00 00          mov    eax,0x1
8048870:       eb 05                   jmp    8048877 <auth+0x12f>
8048872:       b8 00 00 00 00          mov    eax,0x0
8048877:       c9                      leave
8048878:       c3                      ret
8048748:       55                      push   ebp
8048749:       89 e5                   mov    ebp,esp
804874b:       83 ec 28                sub    esp,0x28
804874e:       c7 44 24 04 63 8a 04    mov    DWORD PTR [esp+0x4],0x8048a63
8048755:       08
8048756:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
8048759:       89 04 24                mov    DWORD PTR [esp],eax
804875c:       e8 bf fd ff ff          call   8048520 <strcspn@plt>
8048761:       03 45 08                add    eax,DWORD PTR [ebp+0x8]
8048764:       c6 00 00                mov    BYTE PTR [eax],0x0
8048767:       c7 44 24 04 20 00 00    mov    DWORD PTR [esp+0x4],0x20
804876e:       00
804876f:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
8048772:       89 04 24                mov    DWORD PTR [esp],eax
8048775:       e8 56 fe ff ff          call   80485d0 <strnlen@plt>
804877a:       89 45 f4                mov    DWORD PTR [ebp-0xc],eax
804877d:       50                      push   eax
804877e:       31 c0                   xor    eax,eax
8048780:       74 03                   je     8048785 <auth+0x3d>
8048782:       83 c4 04                add    esp,0x4
8048785:       58                      pop    eax
8048786:       83 7d f4 05             cmp    DWORD PTR [ebp-0xc],0x5
804878a:       7f 0a                   jg     8048796 <auth+0x4e>
804878c:       b8 01 00 00 00          mov    eax,0x1
8048791:       e9 e1 00 00 00          jmp    8048877 <auth+0x12f>
8048796:       c7 44 24 0c 00 00 00    mov    DWORD PTR [esp+0xc],0x0
804879d:       00
804879e:       c7 44 24 08 01 00 00    mov    DWORD PTR [esp+0x8],0x1
80487a5:       00
80487a6:       c7 44 24 04 00 00 00    mov    DWORD PTR [esp+0x4],0x0
80487ad:       00
80487ae:       c7 04 24 00 00 00 00    mov    DWORD PTR [esp],0x0
80487b5:       e8 36 fe ff ff          call   80485f0 <ptrace@plt>
80487ba:       83 f8 ff                cmp    eax,0xffffffff
80487bd:       75 2e                   jne    80487ed <auth+0xa5>
80487bf:       c7 04 24 68 8a 04 08    mov    DWORD PTR [esp],0x8048a68
80487c6:       e8 c5 fd ff ff          call   8048590 <puts@plt>
80487cb:       c7 04 24 8c 8a 04 08    mov    DWORD PTR [esp],0x8048a8c
80487d2:       e8 b9 fd ff ff          call   8048590 <puts@plt>
80487d7:       c7 04 24 b0 8a 04 08    mov    DWORD PTR [esp],0x8048ab0
80487de:       e8 ad fd ff ff          call   8048590 <puts@plt>
80487e3:       b8 01 00 00 00          mov    eax,0x1
80487e8:       e9 8a 00 00 00          jmp    8048877 <auth+0x12f>
80487ed:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
80487f0:       83 c0 03                add    eax,0x3
80487f3:       0f b6 00                movzx  eax,BYTE PTR [eax]
80487f6:       0f be c0                movsx  eax,al
80487f9:       35 37 13 00 00          xor    eax,0x1337
80487fe:       05 ed ed 5e 00          add    eax,0x5eeded
8048803:       89 45 f0                mov    DWORD PTR [ebp-0x10],eax
8048806:       c7 45 ec 00 00 00 00    mov    DWORD PTR [ebp-0x14],0x0
804880d:       eb 4c                   jmp    804885b <auth+0x113>
804880f:       8b 45 ec                mov    eax,DWORD PTR [ebp-0x14]
8048812:       03 45 08                add    eax,DWORD PTR [ebp+0x8]
8048815:       0f b6 00                movzx  eax,BYTE PTR [eax]
8048818:       3c 1f                   cmp    al,0x1f
804881a:       7f 07                   jg     8048823 <auth+0xdb>
804881c:       b8 01 00 00 00          mov    eax,0x1
8048821:       eb 54                   jmp    8048877 <auth+0x12f>
8048823:       8b 45 ec                mov    eax,DWORD PTR [ebp-0x14]
8048826:       03 45 08                add    eax,DWORD PTR [ebp+0x8]
8048829:       0f b6 00                movzx  eax,BYTE PTR [eax]
804882c:       0f be c0                movsx  eax,al
804882f:       89 c1                   mov    ecx,eax
8048831:       33 4d f0                xor    ecx,DWORD PTR [ebp-0x10]
8048834:       ba 2b 3b 23 88          mov    edx,0x88233b2b
8048839:       89 c8                   mov    eax,ecx
804883b:       f7 e2                   mul    edx
804883d:       89 c8                   mov    eax,ecx
804883f:       29 d0                   sub    eax,edx
8048841:       d1 e8                   shr    eax,1
8048843:       01 d0                   add    eax,edx
8048845:       c1 e8 0a                shr    eax,0xa
8048848:       69 c0 39 05 00 00       imul   eax,eax,0x539
804884e:       89 ca                   mov    edx,ecx
8048850:       29 c2                   sub    edx,eax
8048852:       89 d0                   mov    eax,edx
8048854:       01 45 f0                add    DWORD PTR [ebp-0x10],eax
8048857:       83 45 ec 01             add    DWORD PTR [ebp-0x14],0x1
804885b:       8b 45 ec                mov    eax,DWORD PTR [ebp-0x14]
804885e:       3b 45 f4                cmp    eax,DWORD PTR [ebp-0xc]
8048861:       7c ac                   jl     804880f <auth+0xc7>
8048863:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
8048866:       3b 45 f0                cmp    eax,DWORD PTR [ebp-0x10]
8048869:       74 07                   je     8048872 <auth+0x12a>
804886b:       b8 01 00 00 00          mov    eax,0x1
8048870:       eb 05                   jmp    8048877 <auth+0x12f>
8048872:       b8 00 00 00 00          mov    eax,0x0
8048877:       c9                      leave
8048878:       c3                      ret
```
- `8048748 - 804875c` Set up stack and allocate 40 bytes for stack, load **logininput** to `[epb+0x8]` and call `strcspn(logininput, "\n")`
- `8048761 - 804877a` Replace the character "\n" with a nullbyte for **logininput**. Call `strnlen(logininput, 32)`, save the result in a variable at `[ebp-0xc]` aka **loginlen**
- `804877d - 80487b5` Do some weird canary shit until `8048785`, where it checks if **loginlen** is greater than 5. If it is, jump to `8048796`. If not, junp to `8048877` which returns. Calls `ptrace(0, 0, 1, 0)`, can be translated to `ptrace(PTRACE_TRACEME, 0, 1, 0)` which means allow parent to trace me.
- `80487bd - 80487e8` If the return value of the ptrace is -1, run the following in order:
```
    puts("\033[32m.---------------------------.");
    puts("\033[31m| !! TAMPERING DETECTED !!  |");
    puts("\033[32m'---------------------------'");
    return 1;
```
- `80487ed - 8048818` Store **logininput[3]** in a temp variable and XOR it with `0x1337 (4919)` and add `0x5eeded (6221293)`. The result is stored in `[ebp-0x10]` aka **enc_logininput** and 0 is stored in `[ebp-0x14]` aka **count**. Jump to `804885b` (loop check). Derefrence **logininput[count]** and compares it with 31. If is less or equal than, return 1.
- `8048823 - 8048861` **logininput[count]** is loaded into `ecx` and it is XOR'd against **enc_logininput** to `eax`. `0x88233b2b` which is loaded into `edx`, and we are multiplying `0x88233b2b * **logininput[count]**` and shifting the result by 1 to the right. It add back **logininput[count]** and shifts right by 10. It then multiplies 1337 and stores the value in `eax`. After that, **enc_logininput -= logininput[count]** and move **enc_logininput** to `eax`. **enc_logininput + logininput[count]** and increments **count**, compares count with login length.
- `8048863 - 8048877` Compare **serialinput** with the **enc_logininput** If its equal, return 0, else return 1

