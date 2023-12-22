# level03
```
objdump -M intel -d level03
objdump -s -j .data level03
```

## main
```
804885a:       55                      push   ebp
804885b:       89 e5                   mov    ebp,esp
804885d:       83 e4 f0                and    esp,0xfffffff0
8048860:       83 ec 20                sub    esp,0x20
8048863:       50                      push   eax
8048864:       31 c0                   xor    eax,eax
8048866:       74 03                   je     804886b <main+0x11>
8048868:       83 c4 04                add    esp,0x4
804886b:       58                      pop    eax
804886c:       c7 04 24 00 00 00 00    mov    DWORD PTR [esp],0x0
8048873:       e8 38 fc ff ff          call   80484b0 <time@plt>
8048878:       89 04 24                mov    DWORD PTR [esp],eax
804887b:       e8 80 fc ff ff          call   8048500 <srand@plt>
8048880:       c7 04 24 48 8a 04 08    mov    DWORD PTR [esp],0x8048a48
8048887:       e8 44 fc ff ff          call   80484d0 <puts@plt>
804888c:       c7 04 24 6c 8a 04 08    mov    DWORD PTR [esp],0x8048a6c
8048893:       e8 38 fc ff ff          call   80484d0 <puts@plt>
8048898:       c7 04 24 48 8a 04 08    mov    DWORD PTR [esp],0x8048a48
804889f:       e8 2c fc ff ff          call   80484d0 <puts@plt>
80488a4:       b8 7b 8a 04 08          mov    eax,0x8048a7b
80488a9:       89 04 24                mov    DWORD PTR [esp],eax
80488ac:       e8 cf fb ff ff          call   8048480 <printf@plt>
80488b1:       b8 85 8a 04 08          mov    eax,0x8048a85
80488b6:       8d 54 24 1c             lea    edx,[esp+0x1c]
80488ba:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
80488be:       89 04 24                mov    DWORD PTR [esp],eax
80488c1:       e8 6a fc ff ff          call   8048530 <__isoc99_scanf@plt>
80488c6:       8b 44 24 1c             mov    eax,DWORD PTR [esp+0x1c]
80488ca:       c7 44 24 04 0d d0 37    mov    DWORD PTR [esp+0x4],0x1337d00d
80488d1:       13
80488d2:       89 04 24                mov    DWORD PTR [esp],eax
80488d5:       e8 6d fe ff ff          call   8048747 <test>
80488da:       b8 00 00 00 00          mov    eax,0x0
80488df:       c9                      leave
80488e0:       c3                      ret
```

- `804885a - 8048860` Stack setup, alignment and allocating 32 bytes for the stack
- `8048863 - 804886b` I dont know why they would do this but looks like it is just clearing out eax and making sure the stack is ok?
- `804886c - 8048873` Call `srand(time(0))`
- `8048880 - 804889f` For each line below, call `puts()` on it
```
***********************************
*               level03         **
***********************************
```
- `80488a4 - 80488ac` Call `printf("Password:")`
- `80488ac - 80488c1` Loads `[esp + 0x1c]` aka **pwinput** to `eax`. Calls `scanf("%d", &pwinput)`
- `80488c6 - 80488e0` Calls `test(pwinput, 0x1337d00d)` and returns 0

## test
```
8048747:       55                      push   ebp
8048748:       89 e5                   mov    ebp,esp
804874a:       83 ec 28                sub    esp,0x28
804874d:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
8048750:       8b 55 0c                mov    edx,DWORD PTR [ebp+0xc]
8048753:       89 d1                   mov    ecx,edx
8048755:       29 c1                   sub    ecx,eax
8048757:       89 c8                   mov    eax,ecx
8048759:       89 45 f4                mov    DWORD PTR [ebp-0xc],eax
804875c:       83 7d f4 15             cmp    DWORD PTR [ebp-0xc],0x15
8048760:       0f 87 e4 00 00 00       ja     804884a <test+0x103>
8048766:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
8048769:       c1 e0 02                shl    eax,0x2
804876c:       05 f0 89 04 08          add    eax,0x80489f0
8048771:       8b 00                   mov    eax,DWORD PTR [eax]
8048773:       ff e0                   jmp    eax
8048775:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
8048778:       89 04 24                mov    DWORD PTR [esp],eax
804877b:       e8 e0 fe ff ff          call   8048660 <decrypt>
8048780:       e9 d3 00 00 00          jmp    8048858 <test+0x111>
8048785:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
8048788:       89 04 24                mov    DWORD PTR [esp],eax
804878b:       e8 d0 fe ff ff          call   8048660 <decrypt>
8048790:       e9 c3 00 00 00          jmp    8048858 <test+0x111>
8048795:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
8048798:       89 04 24                mov    DWORD PTR [esp],eax
804879b:       e8 c0 fe ff ff          call   8048660 <decrypt>
80487a0:       e9 b3 00 00 00          jmp    8048858 <test+0x111>
80487a5:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
80487a8:       89 04 24                mov    DWORD PTR [esp],eax
80487ab:       e8 b0 fe ff ff          call   8048660 <decrypt>
80487b0:       e9 a3 00 00 00          jmp    8048858 <test+0x111>
80487b5:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
80487b8:       89 04 24                mov    DWORD PTR [esp],eax
80487bb:       e8 a0 fe ff ff          call   8048660 <decrypt>
80487c0:       e9 93 00 00 00          jmp    8048858 <test+0x111>
80487c5:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
80487c8:       89 04 24                mov    DWORD PTR [esp],eax
80487cb:       e8 90 fe ff ff          call   8048660 <decrypt>
80487d0:       e9 83 00 00 00          jmp    8048858 <test+0x111>
80487d5:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
80487d8:       89 04 24                mov    DWORD PTR [esp],eax
80487db:       e8 80 fe ff ff          call   8048660 <decrypt>
80487e0:       eb 76                   jmp    8048858 <test+0x111>
80487e2:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
80487e5:       89 04 24                mov    DWORD PTR [esp],eax
80487e8:       e8 73 fe ff ff          call   8048660 <decrypt>
80487ed:       eb 69                   jmp    8048858 <test+0x111>
80487ef:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
80487f2:       89 04 24                mov    DWORD PTR [esp],eax
80487f5:       e8 66 fe ff ff          call   8048660 <decrypt>
80487fa:       eb 5c                   jmp    8048858 <test+0x111>
80487fc:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
80487ff:       89 04 24                mov    DWORD PTR [esp],eax
8048802:       e8 59 fe ff ff          call   8048660 <decrypt>
8048807:       eb 4f                   jmp    8048858 <test+0x111>
8048809:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
804880c:       89 04 24                mov    DWORD PTR [esp],eax
804880f:       e8 4c fe ff ff          call   8048660 <decrypt>
8048814:       eb 42                   jmp    8048858 <test+0x111>
8048816:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
8048819:       89 04 24                mov    DWORD PTR [esp],eax
804881c:       e8 3f fe ff ff          call   8048660 <decrypt>
8048821:       eb 35                   jmp    8048858 <test+0x111>
8048823:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
8048826:       89 04 24                mov    DWORD PTR [esp],eax
8048829:       e8 32 fe ff ff          call   8048660 <decrypt>
804882e:       eb 28                   jmp    8048858 <test+0x111>
8048830:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
8048833:       89 04 24                mov    DWORD PTR [esp],eax
8048836:       e8 25 fe ff ff          call   8048660 <decrypt>
804883b:       eb 1b                   jmp    8048858 <test+0x111>
804883d:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
8048840:       89 04 24                mov    DWORD PTR [esp],eax
8048843:       e8 18 fe ff ff          call   8048660 <decrypt>
8048848:       eb 0e                   jmp    8048858 <test+0x111>
804884a:       e8 d1 fc ff ff          call   8048520 <rand@plt>
804884f:       89 04 24                mov    DWORD PTR [esp],eax
8048852:       e8 09 fe ff ff          call   8048660 <decrypt>
8048857:       90                      nop
8048858:       c9                      leave
8048859:       c3                      ret
```

- `8048747 - 8048750` Set up stack frame and load **pwinput** at `[ebp+0x8]` to `eax` and **init_addr**`[ebp+0xc]` which is now equal to `0x1337d00d` to `edx`
- `8048753 - 8048759` **init_addr** -= **pwinput**
- `804875c - 8048760` comapre **init_addr** with `21`. If its more than, jump to `804884a`.
- `8048766 - 8048780` load **init_addr** in some temp variable and shift left by 2, which means multiply by 4 and add `0x80489f0` to that value. The temp variable is the derefrenced and jumped to.
- `804877b - 8048858` Continiously call `decrypt(init_addr)` and return

## decrypt
```
8048660:       55                      push   ebp
8048661:       89 e5                   mov    ebp,esp
8048663:       57                      push   edi
8048664:       56                      push   esi
8048665:       83 ec 40                sub    esp,0x40
8048668:       65 a1 14 00 00 00       mov    eax,gs:0x14
804866e:       89 45 f4                mov    DWORD PTR [ebp-0xc],eax
8048671:       31 c0                   xor    eax,eax
8048673:       c7 45 e3 51 7d 7c 75    mov    DWORD PTR [ebp-0x1d],0x757c7d51
804867a:       c7 45 e7 60 73 66 67    mov    DWORD PTR [ebp-0x19],0x67667360
8048681:       c7 45 eb 7e 73 66 7b    mov    DWORD PTR [ebp-0x15],0x7b66737e
8048688:       c7 45 ef 7d 7c 61 33    mov    DWORD PTR [ebp-0x11],0x33617c7d
804868f:       c6 45 f3 00             mov    BYTE PTR [ebp-0xd],0x0
8048693:       50                      push   eax
8048694:       31 c0                   xor    eax,eax
8048696:       74 03                   je     804869b <decrypt+0x3b>
8048698:       83 c4 04                add    esp,0x4
804869b:       58                      pop    eax
804869c:       8d 45 e3                lea    eax,[ebp-0x1d]
804869f:       c7 45 d4 ff ff ff ff    mov    DWORD PTR [ebp-0x2c],0xffffffff
80486a6:       89 c2                   mov    edx,eax
80486a8:       b8 00 00 00 00          mov    eax,0x0
80486ad:       8b 4d d4                mov    ecx,DWORD PTR [ebp-0x2c]
80486b0:       89 d7                   mov    edi,edx
80486b2:       f2 ae                   repnz scas al,BYTE PTR es:[edi]
80486b4:       89 c8                   mov    eax,ecx
80486b6:       f7 d0                   not    eax
80486b8:       83 e8 01                sub    eax,0x1
80486bb:       89 45 dc                mov    DWORD PTR [ebp-0x24],eax
80486be:       c7 45 d8 00 00 00 00    mov    DWORD PTR [ebp-0x28],0x0
80486c5:       eb 1e                   jmp    80486e5 <decrypt+0x85>
80486c7:       8d 45 e3                lea    eax,[ebp-0x1d]
80486ca:       03 45 d8                add    eax,DWORD PTR [ebp-0x28]
80486cd:       0f b6 00                movzx  eax,BYTE PTR [eax]
80486d0:       89 c2                   mov    edx,eax
80486d2:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
80486d5:       31 d0                   xor    eax,edx
80486d7:       89 c2                   mov    edx,eax
80486d9:       8d 45 e3                lea    eax,[ebp-0x1d]
80486dc:       03 45 d8                add    eax,DWORD PTR [ebp-0x28]
80486df:       88 10                   mov    BYTE PTR [eax],dl
80486e1:       83 45 d8 01             add    DWORD PTR [ebp-0x28],0x1
80486e5:       8b 45 d8                mov    eax,DWORD PTR [ebp-0x28]
80486e8:       3b 45 dc                cmp    eax,DWORD PTR [ebp-0x24]
80486eb:       72 da                   jb     80486c7 <decrypt+0x67>
80486ed:       8d 45 e3                lea    eax,[ebp-0x1d]
80486f0:       89 c2                   mov    edx,eax
80486f2:       b8 c3 89 04 08          mov    eax,0x80489c3
80486f7:       b9 11 00 00 00          mov    ecx,0x11
80486fc:       89 d6                   mov    esi,edx
80486fe:       89 c7                   mov    edi,eax
8048700:       f3 a6                   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
8048702:       0f 97 c2                seta   dl
8048705:       0f 92 c0                setb   al
8048708:       89 d1                   mov    ecx,edx
804870a:       28 c1                   sub    cl,al
804870c:       89 c8                   mov    eax,ecx
804870e:       0f be c0                movsx  eax,al
8048711:       85 c0                   test   eax,eax
8048713:       75 0e                   jne    8048723 <decrypt+0xc3>
8048715:       c7 04 24 d4 89 04 08    mov    DWORD PTR [esp],0x80489d4
804871c:       e8 bf fd ff ff          call   80484e0 <system@plt>
8048721:       eb 0c                   jmp    804872f <decrypt+0xcf>
8048723:       c7 04 24 dc 89 04 08    mov    DWORD PTR [esp],0x80489dc
804872a:       e8 a1 fd ff ff          call   80484d0 <puts@plt>
804872f:       8b 75 f4                mov    esi,DWORD PTR [ebp-0xc]
8048732:       65 33 35 14 00 00 00    xor    esi,DWORD PTR gs:0x14
8048739:       74 05                   je     8048740 <decrypt+0xe0>
804873b:       e8 80 fd ff ff          call   80484c0 <__stack_chk_fail@plt>
8048740:       83 c4 40                add    esp,0x40
8048743:       5e                      pop    esi
8048744:       5f                      pop    edi
8048745:       5d                      pop    ebp
8048746:       c3                      ret
```

- `8048660 - 8048671` Prepare the stack and allocate 64 bytes for the stack. Load `20` into `[ebp-0xc]` aka **canary** and clears `eax`. 
- `8048673 - 804863f` declates **cipher1** in `[ebp-0x1d]` with `0x757c7d51`, **cipher2** in `[ebp-0x19]` with `0x67667360`,**cipher3** in `[ebp-0x15]` with `0x7b66737e`,**cipher4** in `[ebp-0x11]` with `0x33617c7d`, **cipher5** in `[ebp-0xd]` with `0`.
- `8048693 - 804869b` I have no idea why they want to pop `eax` like that, so cant provide any context here yet..... (im guessing stack canary?)
- `804869c - 80486c5` **cipher1** has been loaded into `eax` and `0xffffffff` has been written to `[ebp-0x2c]` aka **clear_mask**.
- `80486a6 - 80486b2` evaluate string length of **cipher1**
- `80486b4 - 80486b8` store the value at eax and flip the polarity, since the result of the strlen was negative (direction flag), and then subtract 1
- `80486bb - 80486c5`Move the length into `[ebp-0x24]` aka **cipherlen** and zero into `[ebp-0x28]` aka **count**, jump to `80486e5`, which seems to be a loop checker
- `80486c7 - 80486e1` Load **cipher1**s address into `eax` and add the value of **count**. Derefrence the resultant address and write that result to `edx`. Load argument 1 (**init_addr**) into `eax` and xor it with `edx`, or our **cipher1addr + count**. -> **xor_res**. **cipher1[count] = xor_res**. `count += 1`
- `80486e5 - 80486eb` if **count** < **cipherlen** jump to `80486c7`
- `8048700 - 8048740` Comapres **cipher1** with the string `Congratulations!` using `strncmp(cipher1, "Congratulations!", 17)`. if its the same, `system("/bin/sh")`, else `puts("Invalid Password")` and return while checking for stack overflow. 

