# level07

## main
```
 8048723:       55                      push   ebp
 8048724:       89 e5                   mov    ebp,esp
 8048726:       57                      push   edi
 8048727:       56                      push   esi
 8048728:       53                      push   ebx
 8048729:       83 e4 f0                and    esp,
 804872c:       81 ec d0 01 00 00       sub    esp,0x1d0
```
This section sets up the stack frame and does stack alignment. Also allocates 464 bytes on the stack.

```
 8048732:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 8048735:       89 44 24 1c             mov    DWORD PTR [esp+0x1c],eax
 8048739:       8b 45 10                mov    eax,DWORD PTR [ebp+0x10]
 804873c:       89 44 24 18             mov    DWORD PTR [esp+0x18],eax
 8048740:       65 a1 14 00 00 00       mov    eax,gs:0x14
 8048746:       89 84 24 cc 01 00 00    mov    DWORD PTR [esp+0x1cc],eax
 804874d:       31 c0                   xor    eax,eax
```
This section takes in argv and writes it to `[esp+0x1c]` aka **argv**, also writes envp in `[esp+0x18]` aka **envp**, writes 20 in `[esp+0x1cc]` aka **num1** and sets up the canary mechanism

```
 804874f:       c7 84 24 b4 01 00 00    mov    DWORD PTR [esp+0x1b4],0x0
 8048756:       00 00 00 00
 804875a:       c7 84 24 b8 01 00 00    mov    DWORD PTR [esp+0x1b8],0x0
 8048761:       00 00 00 00
 8048765:       c7 84 24 bc 01 00 00    mov    DWORD PTR [esp+0x1bc],0x0
 804876c:       00 00 00 00
 8048770:       c7 84 24 c0 01 00 00    mov    DWORD PTR [esp+0x1c0],0x0
 8048777:       00 00 00 00
 804877b:       c7 84 24 c4 01 00 00    mov    DWORD PTR [esp+0x1c4],0x0
 8048782:       00 00 00 00
 8048786:       c7 84 24 c8 01 00 00    mov    DWORD PTR [esp+0x1c8],0x0
 804878d:       00 00 00 00
 8048791:       8d 5c 24 24             lea    ebx,[esp+0x24]
 8048795:       b8 00 00 00 00          mov    eax,0x0
 804879a:       ba 64 00 00 00          mov    edx,0x64
 804879f:       89 df                   mov    edi,ebx
 80487a1:       89 d1                   mov    ecx,edx
 80487a3:       f3 ab                   rep stos DWORD PTR es:[edi],eax
 80487a5:       eb 43                   jmp    80487ea <main+0xc7>
 ```
Declares 6 variables on the stack, `[esp+0x1b4]` aka **op_ret**, `[esp+0x1b8]` aka **user_cmd**, `[esp+0x1bc]` aka **var3**, `[esp+0x1c0]` aka **var4**, `[esp+0x1c4]` aka **var5**, `[esp+0x1c8]` aka **var7**, all of them have value 0 inside them. **var3 to var7** may be part of the same array.

Load a buffer from `[esp+0x24]` aka **meat** and call `memset(meat, 0, 100)` and jump to `80487ea` (looks like a loop).

```
80487a7:       8b 44 24 1c             mov    eax,DWORD PTR [esp+0x1c]
80487ab:       8b 00                   mov    eax,DWORD PTR [eax]
80487ad:       c7 44 24 14 ff ff ff    mov    DWORD PTR [esp+0x14],0xffffffff
80487b4:       ff
80487b5:       89 c2                   mov    edx,eax
80487b7:       b8 00 00 00 00          mov    eax,0x0
80487bc:       8b 4c 24 14             mov    ecx,DWORD PTR [esp+0x14]
80487c0:       89 d7                   mov    edi,edx
80487c2:       f2 ae                   repnz scas al,BYTE PTR es:[edi]
80487c4:       89 c8                   mov    eax,ecx
80487c6:       f7 d0                   not    eax
80487c8:       8d 50 ff                lea    edx,[eax-0x1]
80487cb:       8b 44 24 1c             mov    eax,DWORD PTR [esp+0x1c]
80487cf:       8b 00                   mov    eax,DWORD PTR [eax]
80487d1:       89 54 24 08             mov    DWORD PTR [esp+0x8],edx
80487d5:       c7 44 24 04 00 00 00    mov    DWORD PTR [esp+0x4],0x0
80487dc:       00
80487dd:       89 04 24                mov    DWORD PTR [esp],eax
80487e0:       e8 0b fd ff ff          call   80484f0 <memset@plt>
80487e5:       83 44 24 1c 04          add    DWORD PTR [esp+0x1c],0x4
80487ea:       8b 44 24 1c             mov    eax,DWORD PTR [esp+0x1c]
80487ee:       8b 00                   mov    eax,DWORD PTR [eax]
80487f0:       85 c0                   test   eax,eax
80487f2:       75 b3                   jne    80487a7 <main+0x84>
80487f4:       eb 43                   jmp    8048839 <main+0x116>
80487f6:       8b 44 24 18             mov    eax,DWORD PTR [esp+0x18]
80487fa:       8b 00                   mov    eax,DWORD PTR [eax]
80487fc:       c7 44 24 14 ff ff ff    mov    DWORD PTR [esp+0x14],0xffffffff
8048803:       ff
8048804:       89 c2                   mov    edx,eax
8048806:       b8 00 00 00 00          mov    eax,0x0
804880b:       8b 4c 24 14             mov    ecx,DWORD PTR [esp+0x14]
804880f:       89 d7                   mov    edi,edx
8048811:       f2 ae                   repnz scas al,BYTE PTR es:[edi]
8048813:       89 c8                   mov    eax,ecx
8048815:       f7 d0                   not    eax
8048817:       8d 50 ff                lea    edx,[eax-0x1]
804881a:       8b 44 24 18             mov    eax,DWORD PTR [esp+0x18]
804881e:       8b 00                   mov    eax,DWORD PTR [eax]
8048820:       89 54 24 08             mov    DWORD PTR [esp+0x8],edx
8048824:       c7 44 24 04 00 00 00    mov    DWORD PTR [esp+0x4],0x0
804882b:       00
804882c:       89 04 24                mov    DWORD PTR [esp],eax
804882f:       e8 bc fc ff ff          call   80484f0 <memset@plt>
8048834:       83 44 24 18 04          add    DWORD PTR [esp+0x18],0x4
8048839:       8b 44 24 18             mov    eax,DWORD PTR [esp+0x18]
804883d:       8b 00                   mov   whi eax,DWORD PTR [eax]
804883f:       85 c0                   test   eax,eax
8048841:       75 b3                   jne    80487f6 <main+0xd3>
```

Load argv from **argv** and calls strlen on it after defref `strlen(*argv)` and call `memset(*argv, 0, <strlen res>)`. Increment the address of **argv** by 4 (next argument) and compare it with 0. If its not equal, loop back to `80487a7`, essentially repeating this until argv is fully cleared.

Do the same thing for envp.

```
8048843:       c7 04 24 38 8b 04 08    mov    DWORD PTR [esp],0x8048b38
804884a:       e8 71 fc ff ff          call   80484c0 <puts@plt>
804884f:       b8 4b 8d 04 08          mov    eax,0x8048d4b
8048854:       89 04 24                mov    DWORD PTR [esp],eax
8048857:       e8 14 fc ff ff          call   8048470 <printf@plt>
804885c:       c7 84 24 b4 01 00 00    mov    DWORD PTR [esp+0x1b4],0x1
8048863:       01 00 00 00
8048867:       a1 40 a0 04 08          mov    eax,ds:0x804a040
804886c:       89 44 24 08             mov    DWORD PTR [esp+0x8],eax
8048870:       c7 44 24 04 14 00 00    mov    DWORD PTR [esp+0x4],0x14
8048877:       00
8048878:       8d 84 24 b8 01 00 00    lea    eax,[esp+0x1b8]
804887f:       89 04 24                mov    DWORD PTR [esp],eax
8048882:       e8 19 fc ff ff          call   80484a0 <fgets@plt>
8048887:       8d 84 24 b8 01 00 00    lea    eax,[esp+0x1b8]
804888e:       c7 44 24 14 ff ff ff    mov    DWORD PTR [esp+0x14],0xffffffff
8048895:       ff
8048896:       89 c2                   mov    edx,eax
8048898:       b8 00 00 00 00          mov    eax,0x0
804889d:       8b 4c 24 14             mov    ecx,DWORD PTR [esp+0x14]
80488a1:       89 d7                   mov    edi,edx
80488a3:       f2 ae                   repnz scas al,BYTE PTR es:[edi]
80488a5:       89 c8                   mov    eax,ecx
80488a7:       f7 d0                   not    eax
80488a9:       83 e8 01                sub    eax,0x1
80488ac:       83 e8 01                sub    eax,0x1
80488af:       c6 84 04 b8 01 00 00    mov    BYTE PTR [esp+eax*1+0x1b8],0x0
80488b6:       00
```

Call these in order :-
```
 puts("----------------------------------------------------\n"\
           "  Welcome to wil's crappy number storage service!   \n"\
           "----------------------------------------------------\n"\
           " Commands:                                          \n"\
           "    store - store a number into the data storage    \n"\
           "    read  - read a number from the data storage     \n"\
           "    quit  - exit the program                        \n"\
           "----------------------------------------------------\n"\
           "   wil has reserved some storage :>                 \n"\
           "----------------------------------------------------\n"\
           "\n");
printf("Input command: ");
fgets(user_cmd, 20, stdin);
op_ret = 1；
```

Once the fgets returns, find the newline character in the string and replace it with a nullbyte using .

```
80488b7:       8d 84 24 b8 01 00 00    lea    eax,[esp+0x1b8]
80488be:       89 c2                   mov    edx,eax
80488c0:       b8 5b 8d 04 08          mov    eax,0x8048d5b
80488c5:       b9 05 00 00 00          mov    ecx,0x5
80488ca:       89 d6                   mov    esi,edx
80488cc:       89 c7                   mov    edi,eax
80488ce:       f3 a6                   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
80488d0:       0f 97 c2                seta   dl
80488d3:       0f 92 c0                setb   al
80488d6:       89 d1                   mov    ecx,edx
80488d8:       28 c1                   sub    cl,al
80488da:       89 c8                   mov    eax,ecx
80488dc:       0f be c0                movsx  eax,al
80488df:       85 c0                   test   eax,eax
80488e1:       75 15                   jne    80488f8 <main+0x1d5>
80488e3:       8d 44 24 24             lea    eax,[esp+0x24]
80488e7:       89 04 24                mov    DWORD PTR [esp],eax
80488ea:       e8 41 fd ff ff          call   8048630 <store_number>
80488ef:       89 84 24 b4 01 00 00    mov    DWORD PTR [esp+0x1b4],eax
80488f6:       eb 6d                   jmp    8048965 <main+0x242>
```
Comapre **user_cmd** with "store" using `strncmp(user_cmd, "store", 5)`. If its not equal, jump to `80488f8`, which should check next command. If it is, call `store_number(meat)` and place the return value at **op_ret**, go back to the loop start by jumping to `8048965`

```
80488f8:       8d 84 24 b8 01 00 00    lea    eax,[esp+0x1b8]
80488ff:       89 c2                   mov    edx,eax
8048901:       b8 61 8d 04 08          mov    eax,0x8048d61
8048906:       b9 04 00 00 00          mov    ecx,0x4
804890b:       89 d6                   mov    esi,edx
804890d:       89 c7                   mov    edi,eax
804890f:       f3 a6                   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
8048911:       0f 97 c2                seta   dl
8048914:       0f 92 c0                setb   al
8048917:       89 d1                   mov    ecx,edx
8048919:       28 c1                   sub    cl,al
804891b:       89 c8                   mov    eax,ecx
804891d:       0f be c0                movsx  eax,al
8048920:       85 c0                   test   eax,eax
8048922:       75 15                   jne    8048939 <main+0x216>
8048924:       8d 44 24 24             lea    eax,[esp+0x24]
8048928:       89 04 24                mov    DWORD PTR [esp],eax
804892b:       e8 a7 fd ff ff          call   80486d7 <read_number>
8048930:       89 84 24 b4 01 00 00    mov    DWORD PTR [esp+0x1b4],eax
8048937:       eb 2c                   jmp    8048965 <main+0x242>
```
Do the same thing to `read`, `strncmp(user_cmd, "read", 4)` and call `read_number(meat)` , saving the output at **op_ret** and jumping to `8048965`

```
8048939:       8d 84 24 b8 01 00 00    lea    eax,[esp+0x1b8]
8048940:       89 c2                   mov    edx,eax
8048942:       b8 66 8d 04 08          mov    eax,0x8048d66
8048947:       b9 04 00 00 00          mov    ecx,0x4
804894c:       89 d6                   mov    esi,edx
804894e:       89 c7                   mov    edi,eax
8048950:       f3 a6                   repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
8048952:       0f 97 c2                seta   dl
8048955:       0f 92 c0                setb   al
8048958:       89 d1                   mov    ecx,edx
804895a:       28 c1                   sub    cl,al
804895c:       89 c8                   mov    eax,ecx
804895e:       0f be c0                movsx  eax,al
8048961:       85 c0                   test   eax,eax
8048963:       74 6a                   je     80489cf <main+0x2ac>
```

Do the same thing to `"quit"`, `strncmp(user_cmd, "quit", 4)` and jump to `80489cf`, which checks for canary and returns.

```
 8048965:       83 bc 24 b4 01 00 00    cmp    DWORD PTR [esp+0x1b4],0x0
 804896c:       00
 804896d:       74 1a                   je     8048989 <main+0x266>
 804896f:       b8 6b 8d 04 08          mov    eax,0x8048d6b
 8048974:       8d 94 24 b8 01 00 00    lea    edx,[esp+0x1b8]
 804897b:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 804897f:       89 04 24                mov    DWORD PTR [esp],eax
 8048982:       e8 e9 fa ff ff          call   8048470 <printf@plt>
 8048987:       eb 18                   jmp    80489a1 <main+0x27e>
 8048989:       b8 88 8d 04 08          mov    eax,0x8048d88
 804898e:       8d 94 24 b8 01 00 00    lea    edx,[esp+0x1b8]
 8048995:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 8048999:       89 04 24                mov    DWORD PTR [esp],eax
 804899c:       e8 cf fa ff ff          call   8048470 <printf@plt>
 80489a1:       8d 84 24 b8 01 00 00    lea    eax,[esp+0x1b8]
 80489a8:       c7 00 00 00 00 00       mov    DWORD PTR [eax],0x0
 80489ae:       c7 40 04 00 00 00 00    mov    DWORD PTR [eax+0x4],0x0
 80489b5:       c7 40 08 00 00 00 00    mov    DWORD PTR [eax+0x8],0x0
 80489bc:       c7 40 0c 00 00 00 00    mov    DWORD PTR [eax+0xc],0x0
 80489c3:       c7 40 10 00 00 00 00    mov    DWORD PTR [eax+0x10],0x0
 80489ca:       e9 80 fe ff ff          jmp    804884f <main+0x12c>
 80489cf:       90                      nop
 80489d0:       b8 00 00 00 00          mov    eax,0x0
 80489d5:       8b b4 24 cc 01 00 00    mov    esi,DWORD PTR [esp+0x1cc]
 80489dc:       65 33 35 14 00 00 00    xor    esi,DWORD PTR gs:0x14
 80489e3:       74 05                   je     80489ea <main+0x2c7>
 80489e5:       e8 c6 fa ff ff          call   80484b0 <__stack_chk_fail@plt>
 80489ea:       8d 65 f4                lea    esp,[ebp-0xc]
 80489ed:       5b                      pop    ebx
 80489ee:       5e                      pop    esi
 80489ef:       5f                      pop    edi
 80489f0:       5d                      pop    ebp
 80489f1:       c3                      ret
```
Check for empty **op_ret** If it is empty or 0, jump to `8048989` which calls 
`printf(" Completed %s command successfully\n", user_cmd)`, clears all vars and goes back to loop. If the loop exits, check canary and return.

If **op_ret** is non zero, call `printf("Failed to do %s command\n", user_cmd)`

## read_number
```
080486d7 <read_number>:
80486d7:       55                      push   ebp
80486d8:       89 e5                   mov    ebp,esp
80486da:       83 ec 28                sub    esp,0x28
80486dd:       c7 45 f4 00 00 00 00    mov    DWORD PTR [ebp-0xc],0x0
80486e4:       b8 dd 8a 04 08          mov    eax,0x8048add
80486e9:       89 04 24                mov    DWORD PTR [esp],eax
80486ec:       e8 7f fd ff ff          call   8048470 <printf@plt>
80486f1:       e8 f1 fe ff ff          call   80485e7 <get_unum>
80486f6:       89 45 f4                mov    DWORD PTR [ebp-0xc],eax
80486f9:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
80486fc:       c1 e0 02                shl    eax,0x2
80486ff:       03 45 08                add    eax,DWORD PTR [ebp+0x8]
8048702:       8b 10                   mov    edx,DWORD PTR [eax]
8048704:       b8 1b 8b 04 08          mov    eax,0x8048b1b
8048709:       89 54 24 08             mov    DWORD PTR [esp+0x8],edx
804870d:       8b 55 f4                mov    edx,DWORD PTR [ebp-0xc]
8048710:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
8048714:       89 04 24                mov    DWORD PTR [esp],eax
8048717:       e8 54 fd ff ff          call   8048470 <printf@plt>
804871c:       b8 00 00 00 00          mov    eax,0x0
8048721:       c9                      leave
8048722:       c3                      ret
```
Sets up stack and allocates 40 bytes on the stack. Clears out `[ebp-0xc]` aka **num_input** and calls `printf("Index: ")` and then calls `get_unum()`, and stores the value in **num_input**. The number is then shifted left by 2 and added by the first argument in `[ebp+0x8]` aka **meat**. **meat** is then derefrenced and put to `edx` and calls `printf("Number at data[%u] is %u, ", num_input, meat)`. Returns 0

## store_number
```
 8048630:       55                      push   ebp
 8048631:       89 e5                   mov    ebp,esp
 8048633:       83 ec 28                sub    esp,0x28
 8048636:       c7 45 f0 00 00 00 00    mov    DWORD PTR [ebp-0x10],0x0
 804863d:       c7 45 f4 00 00 00 00    mov    DWORD PTR [ebp-0xc],0x0
 8048644:       b8 d3 8a 04 08          mov    eax,0x8048ad3
 8048649:       89 04 24                mov    DWORD PTR [esp],eax
 804864c:       e8 1f fe ff ff          call   8048470 <printf@plt>
 8048651:       e8 91 ff ff ff          call   80485e7 <get_unum>
 8048656:       89 45 f0                mov    DWORD PTR [ebp-0x10],eax
 8048659:       b8 dd 8a 04 08          mov    eax,0x8048add
 804865e:       89 04 24                mov    DWORD PTR [esp],eax
 8048661:       e8 0a fe ff ff          call   8048470 <printf@plt>
 8048666:       e8 7c ff ff ff          call   80485e7 <get_unum>
 804866b:       89 45 f4                mov    DWORD PTR [ebp-0xc],eax
 804866e:       8b 4d f4                mov    ecx,DWORD PTR [ebp-0xc]
 8048671:       ba ab aa aa aa          mov    edx,0xaaaaaaab
 8048676:       89 c8                   mov    eax,ecx
 8048678:       f7 e2                   mul    edx
 804867a:       d1 ea                   shr    edx,1
 804867c:       89 d0                   mov    eax,edx
 804867e:       01 c0                   add    eax,eax
 8048680:       01 d0                   add    eax,edx
 8048682:       89 ca                   mov    edx,ecx
 8048684:       29 c2                   sub    edx,eax
 8048686:       85 d2                   test   edx,edx
 8048688:       74 0d                   je     8048697 <store_number+0x67>
 804868a:       8b 45 f0                mov    eax,DWORD PTR [ebp-0x10]
 804868d:       c1 e8 18                shr    eax,0x18
 8048690:       3d b7 00 00 00          cmp    eax,0xb7
 8048695:       75 2b                   jne    80486c2 <store_number+0x92>
 8048697:       c7 04 24 e6 8a 04 08    mov    DWORD PTR [esp],0x8048ae6
 804869e:       e8 1d fe ff ff          call   80484c0 <puts@plt>
 80486a3:       c7 04 24 f8 8a 04 08    mov    DWORD PTR [esp],0x8048af8
 80486aa:       e8 11 fe ff ff          call   80484c0 <puts@plt>
 80486af:       c7 04 24 e6 8a 04 08    mov    DWORD PTR [esp],0x8048ae6
 80486b6:       e8 05 fe ff ff          call   80484c0 <puts@plt>
 80486bb:       b8 01 00 00 00          mov    eax,0x1
 80486c0:       eb 13                   jmp    80486d5 <store_number+0xa5>
 80486c2:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
 80486c5:       c1 e0 02                shl    eax,0x2
 80486c8:       03 45 08                add    eax,DWORD PTR [ebp+0x8]
 80486cb:       8b 55 f0                mov    edx,DWORD PTR [ebp-0x10]
 80486ce:       89 10                   mov    DWORD PTR [eax],edx
 80486d0:       b8 00 00 00 00          mov    eax,0x0
 80486d5:       c9                      leave
 80486d6:       c3                      ret
 ```
 Sets up stack and allocates 40 bytes on the stack. Clears up `[ebp-0x10]` aka **num_input** and `[ebp-0xc]` aka **idx_input**. Call `printf("Number: ")` and then call `get_unum()`, which assigns the return value to **num_input** Do the same for **idx_input**, with the print being `printf("Index: ")`. The pseudocode for `8048671 - 8048686` is like so.
 
 ```
 let idx_input = ...;
 let temp1 = 0xaaaaaaab;
 
idx_input += temp1
temp1 >> 1
let temp2 = temp1
temp2 *= 2
temp2 += temp1
let temp3 = 0xaaaaaaab - temp2
temp3 == 0?
 ```
If the condition is true jump to `8048697` which calls 
```
 puts(" *** ERROR! ***");
puts("   This index is reserved for wil!");
puts(" *** ERROR! ***");
```
and return 1

The pseudocode for `804868a - 8048690` is like so
```
num_input >> 0x18 == 0xb7?
```
If its not true, jump to `80486c2`  which does `meat[idx_input] = num_input;`
and return 0. jump to `8048697` if its not.

## get_unum
```
 80485e7:       55                      push   ebp
 80485e8:       89 e5                   mov    ebp,esp
 80485ea:       83 ec 28                sub    esp,0x28
 80485ed:       c7 45 f4 00 00 00 00    mov    DWORD PTR [ebp-0xc],0x0
 80485f4:       a1 60 a0 04 08          mov    eax,ds:0x804a060
 80485f9:       89 04 24                mov    DWORD PTR [esp],eax
 80485fc:       e8 7f fe ff ff          call   8048480 <fflush@plt>
 8048601:       b8 d0 8a 04 08          mov    eax,0x8048ad0
 8048606:       8d 55 f4                lea    edx,[ebp-0xc]
 8048609:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 804860d:       89 04 24                mov    DWORD PTR [esp],eax
 8048610:       e8 eb fe ff ff          call   8048500 <__isoc99_scanf@plt>
 8048615:       e8 aa ff ff ff          call   80485c4 <clear_stdin>
 804861a:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
 804861d:       c9                      leave
 804861e:       c3                      ret
 ```
 Setup stack and allocate 40 bytes for the stack, declare a variable at `[ebp-0xc]` aka **res**, call `fflush(stdout)` and then ` scanf("%u", &res)`. Call `clear_stdin()` and return **res**
 

## clear_stdin
```
080485c4 <clear_stdin>:
80485c4:       55                      push   ebp
80485c5:       89 e5                   mov    ebp,esp
80485c7:       83 ec 18                sub    esp,0x18
80485ca:       c6 45 f7 00             mov    BYTE PTR [ebp-0x9],0x0
80485ce:       eb 01                   jmp    80485d1 <clear_stdin+0xd>
80485d0:       90                      nop
80485d1:       e8 ba fe ff ff          call   8048490 <getchar@plt>
80485d6:       88 45 f7                mov    BYTE PTR [ebp-0x9],al
80485d9:       80 7d f7 0a             cmp    BYTE PTR [ebp-0x9],0xa
80485dd:       74 06                   je     80485e5 <clear_stdin+0x21>
80485df:       80 7d f7 ff             cmp    BYTE PTR [ebp-0x9],0xff
80485e3:       75 eb                   jne    80485d0 <clear_stdin+0xc>
80485e5:       c9                      leave
80485e6:       c3                      ret
```

 Setup stack and allocate 24 bytes for the stack, declare a variable at `[ebp-0x9]` aka **curr**, jump to `80485d1` (loop start), calls `getchar()` and stores ret value at **curr**. Compare **curr** with '\n' and -1. Return of they are either equal. jump back to `80485d0` if they are not (infinite loop)
