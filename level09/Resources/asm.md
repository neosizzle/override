# level09
```
objdump -M intel -d level09
objdump -s -j .rodata level09
```

## main
```
aa8:	55                   	push   rbp
aa9:	48 89 e5             	mov    rbp,rsp
aac:	48 8d 3d 5d 01 00 00 	lea    rdi,[rip+0x15d]        # c10 <_IO_stdin_used+0x58>
ab3:	e8 78 fc ff ff       	call   730 <puts@plt>
ab8:	e8 03 fe ff ff       	call   8c0 <handle_msg>
abd:	b8 00 00 00 00       	mov    eax,0x0
ac2:	5d                   	pop    rbp
ac3:	c3                   	ret    
```
Load a string and calls
```
    puts("--------------------------------------------\n|   ~Welcome to l33t-m$n ~    v1337        |\n--------------------------------------------");
```
calls `handle_msg()` and returns 0;

## handle_msg
```
8c0:	55                   	push   rbp
8c1:	48 89 e5             	mov    rbp,rsp
8c4:	48 81 ec c0 00 00 00 	sub    rsp,0xc0
8cb:	48 8d 85 40 ff ff ff 	lea    rax,[rbp-0xc0]
8d2:	48 05 8c 00 00 00    	add    rax,0x8c
8d8:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
8df:	48 c7 40 08 00 00 00 	mov    QWORD PTR [rax+0x8],0x0
8e6:	00 
8e7:	48 c7 40 10 00 00 00 	mov    QWORD PTR [rax+0x10],0x0
8ee:	00 
8ef:	48 c7 40 18 00 00 00 	mov    QWORD PTR [rax+0x18],0x0
8f6:	00 
8f7:	48 c7 40 20 00 00 00 	mov    QWORD PTR [rax+0x20],0x0
8fe:	00 
8ff:	c7 45 f4 8c 00 00 00 	mov    DWORD PTR [rbp-0xc],0x8c

```
Sets up stack and allocates 192 bytes on the stack. Loads a variable at `[rbp-0xc0]` aka **var1**, increments the pointer to `[rbp-0x34] (c0 - 8c)`, sets  `[rbp-0x34]`, `[rbp-0x34+0x8]`, `[rbp-0x34+0x10]`, `[rbp-0x34+0x20]` to 0, and writes 140 to `[rbp-0xc]` aka **num**. Since this is a 64 bit program, a word is 8 bytes so we can assume that `[rbp-0x34]` to `[rbp-0xc]` are contigious zeroes `memset([rbp-0x34], 0, 40)`.

Since the assembly only loaded one address from memory and assigns values relatively, we can also say that they are loading a struct like so 
```
struct my_struct {
    char    msg[0x8c];
	char    username[0x28];
	int    msglen;
};
```

```
906:	48 8d 85 40 ff ff ff 	lea    rax,[rbp-0xc0]
90d:	48 89 c7             	mov    rdi,rax
910:	e8 b8 00 00 00       	call   9cd <set_username>
915:	48 8d 85 40 ff ff ff 	lea    rax,[rbp-0xc0]
91c:	48 89 c7             	mov    rdi,rax
91f:	e8 0e 00 00 00       	call   932 <set_msg>
924:	48 8d 3d 95 02 00 00 	lea    rdi,[rip+0x295]        # bc0 <_IO_stdin_used+0x8>
92b:	e8 00 fe ff ff       	call   730 <puts@plt>
930:	c9                   	leave  
931:	c3                   	ret    
```
calls `set_username(&var1)` and `set_msg(&var1)` and call `puts(">: Msg sent!")`

## set_username
```
9cd:	55                   	push   rbp
9ce:	48 89 e5             	mov    rbp,rsp
9d1:	48 81 ec a0 00 00 00 	sub    rsp,0xa0
9d8:	48 89 bd 68 ff ff ff 	mov    QWORD PTR [rbp-0x98],rdi
9df:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
9e6:	48 89 c6             	mov    rsi,rax
9e9:	b8 00 00 00 00       	mov    eax,0x0
9ee:	ba 10 00 00 00       	mov    edx,0x10
9f3:	48 89 f7             	mov    rdi,rsi
9f6:	48 89 d1             	mov    rcx,rdx
9f9:	f3 48 ab             	rep stos QWORD PTR es:[rdi],rax
9fc:	48 8d 3d e1 01 00 00 	lea    rdi,[rip+0x1e1]        # be4 <_IO_stdin_used+0x2c>
a03:	e8 28 fd ff ff       	call   730 <puts@plt>
a08:	48 8d 05 d0 01 00 00 	lea    rax,[rip+0x1d0]        # bdf <_IO_stdin_used+0x27>
a0f:	48 89 c7             	mov    rdi,rax
a12:	b8 00 00 00 00       	mov    eax,0x0
a17:	e8 34 fd ff ff       	call   750 <printf@plt>
```
Allocates 160 bytes on the stack, loads argument1 **&var1** at `[rbp-0x98]` and loads variable `[rbp-0x90]` aka **temp**. call `memset(temp, 0, 16)` and call 
```
puts(">: Enter your username");
printf(">>: ");
```

```
a1c:	48 8b 05 95 15 20 00 	mov    rax,QWORD PTR [rip+0x201595]        # 201fb8 <_DYNAMIC+0x198>
a23:	48 8b 00             	mov    rax,QWORD PTR [rax]
a26:	48 89 c2             	mov    rdx,rax
a29:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
a30:	be 80 00 00 00       	mov    esi,0x80
a35:	48 89 c7             	mov    rdi,rax
a38:	e8 33 fd ff ff       	call   770 <fgets@plt>
a3d:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
a44:	eb 24                	jmp    a6a <set_username+0x9d>
a46:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
a49:	48 98                	cdqe   
a4b:	0f b6 8c 05 70 ff ff 	movzx  ecx,BYTE PTR [rbp+rax*1-0x90]
a52:	ff 
a53:	48 8b 95 68 ff ff ff 	mov    rdx,QWORD PTR [rbp-0x98]
a5a:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
a5d:	48 98                	cdqe   
a5f:	88 8c 02 8c 00 00 00 	mov    BYTE PTR [rdx+rax*1+0x8c],cl
a66:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
a6a:	83 7d fc 28          	cmp    DWORD PTR [rbp-0x4],0x28
a6e:	7f 11                	jg     a81 <set_username+0xb4>
a70:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
a73:	48 98                	cdqe   
a75:	0f b6 84 05 70 ff ff 	movzx  eax,BYTE PTR [rbp+rax*1-0x90]
a7c:	ff 
a7d:	84 c0                	test   al,al
a7f:	75 c5                	jne    a46 <set_username+0x79>
a81:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
a88:	48 8d 90 8c 00 00 00 	lea    rdx,[rax+0x8c]
a8f:	48 8d 05 65 01 00 00 	lea    rax,[rip+0x165]        # bfb <_IO_stdin_used+0x43>
a96:	48 89 d6             	mov    rsi,rdx
a99:	48 89 c7             	mov    rdi,rax
a9c:	b8 00 00 00 00       	mov    eax,0x0
aa1:	e8 aa fc ff ff       	call   750 <printf@plt>
aa6:	c9                   	leave  
```
Call `fgets(temp, 120, stdin)`, store 0 at a variable at `[rbp-0x4]` aka **count** and jump to `a6a` (loop check)

In `a6a`, **count** is compared to 40. If its greater than 40, or **temp[count]** is not 0, the loop exits. 

In the loop at `a44`, do `var1->username[count] = temp[count]` and  `++count`

Once the loop exits at `a81`, call `printf(">: Welcome, %s", var1->username)` and return.

## set_msg
```
932:	55                   	push   rbp
933:	48 89 e5             	mov    rbp,rsp
936:	48 81 ec 10 04 00 00 	sub    rsp,0x410
93d:	48 89 bd f8 fb ff ff 	mov    QWORD PTR [rbp-0x408],rdi
944:	48 8d 85 00 fc ff ff 	lea    rax,[rbp-0x400]
94b:	48 89 c6             	mov    rsi,rax
94e:	b8 00 00 00 00       	mov    eax,0x0
953:	ba 80 00 00 00       	mov    edx,0x80
958:	48 89 f7             	mov    rdi,rsi
95b:	48 89 d1             	mov    rcx,rdx
95e:	f3 48 ab             	rep stos QWORD PTR es:[rdi],rax
961:	48 8d 3d 65 02 00 00 	lea    rdi,[rip+0x265]        # bcd <_IO_stdin_used+0x15>
968:	e8 c3 fd ff ff       	call   730 <puts@plt>
96d:	48 8d 05 6b 02 00 00 	lea    rax,[rip+0x26b]        # bdf <_IO_stdin_used+0x27>
974:	48 89 c7             	mov    rdi,rax
977:	b8 00 00 00 00       	mov    eax,0x0
97c:	e8 cf fd ff ff       	call   750 <printf@plt>
981:	48 8b 05 30 16 20 00 	mov    rax,QWORD PTR [rip+0x201630]        # 201fb8 <_DYNAMIC+0x198>
988:	48 8b 00             	mov    rax,QWORD PTR [rax]
98b:	48 89 c2             	mov    rdx,rax
98e:	48 8d 85 00 fc ff ff 	lea    rax,[rbp-0x400]
995:	be 00 04 00 00       	mov    esi,0x400
99a:	48 89 c7             	mov    rdi,rax
99d:	e8 ce fd ff ff       	call   770 <fgets@plt>
9a2:	48 8b 85 f8 fb ff ff 	mov    rax,QWORD PTR [rbp-0x408]
9a9:	8b 80 b4 00 00 00    	mov    eax,DWORD PTR [rax+0xb4]
9af:	48 63 d0             	movsxd rdx,eax
9b2:	48 8d 8d 00 fc ff ff 	lea    rcx,[rbp-0x400]
9b9:	48 8b 85 f8 fb ff ff 	mov    rax,QWORD PTR [rbp-0x408]
9c0:	48 89 ce             	mov    rsi,rcx
9c3:	48 89 c7             	mov    rdi,rax
9c6:	e8 55 fd ff ff       	call   720 <strncpy@plt>
9cb:	c9                   	leave  
9cc:	c3                   	ret    
```
Allocate 1040 bytes to the stack, loads argument1 **&var1** at `[rbp-0x408]` and loads variable at `[rbp-0x400]` aka **temp*. Call `memset(temp, 0, 128)` then `puts(">: Msg @Unix-Dude")` and `printf(">>: ")`.

Call `fgets(temp, 1024, stdin)` and `strncpy(var1->message, temp, var1->msglen)` and return.

## secret_backdoor
```
88c:	55                   	push   rbp
88d:	48 89 e5             	mov    rbp,rsp
890:	48 83 c4 80          	add    rsp,0xffffffffffffff80
894:	48 8b 05 1d 17 20 00 	mov    rax,QWORD PTR [rip+0x20171d]        # 201fb8 <_DYNAMIC+0x198>
89b:	48 8b 00             	mov    rax,QWORD PTR [rax]
89e:	48 89 c2             	mov    rdx,rax
8a1:	48 8d 45 80          	lea    rax,[rbp-0x80]
8a5:	be 80 00 00 00       	mov    esi,0x80
8aa:	48 89 c7             	mov    rdi,rax
8ad:	e8 be fe ff ff       	call   770 <fgets@plt>
8b2:	48 8d 45 80          	lea    rax,[rbp-0x80]
8b6:	48 89 c7             	mov    rdi,rax
8b9:	e8 82 fe ff ff       	call   740 <system@plt>
8be:	c9                   	leave  
8bf:	c3                   	ret  
```
Loads a variable at `[rbp-0x80]` aka **cmd** and calls `fgets(cmd, 128, stdin)` and then `system(cmd)`

## notes
7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC
```
b *0x8048866
lay asm
focus cmd
tty /dev/pts/1
set disassembly-flavor intel
run < /tmp/level05
x/10s (char*)(*environ)
 x/10x 0x080497e0
```