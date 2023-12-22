# level00
```
objdump -M intel -d level00
objdump -s -j .data level00 -> -s stands for full content, -j stands for section
```
## main
```
 8048494:       55                      push   ebp
 8048495:       89 e5                   mov    ebp,esp
 8048497:       83 e4 f0                and    esp,0xfffffff0
 ```
 - `8048494` to `8048494` Sets up the stack frame by moving the stack pointers  away from the parents esp to the current ebp
 - `8048497` Stack alignment to the closes 8 bytes. The esp moves up by 8 bytes.

 
---

```
 804849a:       83 ec 20                sub    esp,0x20
 804849d:       c7 04 24 f0 85 04 08    mov    DWORD PTR [esp],0x80485f0
 80484a4:       e8 e7 fe ff ff          call   8048390 <puts@plt>
 80484a9:       c7 04 24 14 86 04 08    mov    DWORD PTR [esp],0x8048614
 80484b0:       e8 db fe ff ff          call   8048390 <puts@plt>
 80484b5:       c7 04 24 f0 85 04 08    mov    DWORD PTR [esp],0x80485f0
 80484bc:       e8 cf fe ff ff          call   8048390 <puts@plt>
 ```
- `804849a` bulk allocates 32 bytes in the stack
- `804849d - 804849d` calls
```
puts("***********************************");
puts ("-Level00 -");
puts("***********************************");
```

---

```
 80484c1:       b8 2c 86 04 08          mov    eax,0x804862c
 80484c6:       89 04 24                mov    DWORD PTR [esp],eax
 80484c9:       e8 b2 fe ff ff          call   8048380 <printf@plt>
 ```
 -  `80484c1 - 80484c9` calls printf("Password: ")

 ---
 ```
 80484ce:       b8 36 86 04 08          mov    eax,0x8048636
 80484d3:       8d 54 24 1c             lea    edx,[esp+0x1c]
 80484d7:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 80484db:       89 04 24                mov    DWORD PTR [esp],eax
 80484de:       e8 ed fe ff ff          call   80483d0 <__isoc99_scanf@plt>
 80484e3:       8b 44 24 1c             mov    eax,DWORD PTR [esp+0x1c]
 80484e7:       3d 9c 14 00 00          cmp    eax,0x149c
 ```
- `80484ce` prepares the "%d" string in eax
- `80484d3` loads a variable (pointer is at esp + 0x1c) to edx, which will be used by scanf later. Lets call this `input`
- `80484d7 - 80484de` Calls
```
in_buf = scanf("%d", &input);
```
- `80484e3 - 80484e7` derefrences the pointer to `input` and compares it with 5276

---

```
80484ec:	75 1f                	jne    804850d <main+0x79>
80484ee:	c7 04 24 39 86 04 08 	mov    DWORD PTR [esp],0x8048639
80484f5:	e8 96 fe ff ff       	call   8048390 <puts@plt>
80484fa:	c7 04 24 49 86 04 08 	mov    DWORD PTR [esp],0x8048649
8048501:	e8 9a fe ff ff       	call   80483a0 <system@plt>
8048506:	b8 00 00 00 00       	mov    eax,0x0
804850b:	eb 11                	jmp    804851e <main+0x8a>
804850d:	c7 04 24 51 86 04 08 	mov    DWORD PTR [esp],0x8048651
8048514:	e8 77 fe ff ff       	call   8048390 <puts@plt>
8048519:	b8 01 00 00 00       	mov    eax,0x1
804851e:	c9                   	leave  
804851f:	c3                   	ret    

```
- `80484ec` if the comparison is not equal, jump to `804850d`
- `80484ee - 8048501` calls `puts("Authenticated!")` and runs `system("/bin/sh")`
- `804850b` return 0
- `804850d - 8048514` calls `puts("Invalid Password!")`
- `8048519 - 804851f` return 1
