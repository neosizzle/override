## level06 (enumeration protction / direct jumps)
```clike=
int auth(char *logininput, unsigned int serial_input)
{
    int loginlen;
    int count;
    unsigned int enc_logininput;
    
    logininput[strcspn(logininput, "\n")] = 0;
    loginlen = strlen(logininput);
    if (loginlen < 5) return 1;
    enc_logininput = (logininput[3] ^ 4919) + 6221293;
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1)
    {
        puts("\033[32m.---------------------------.");
        puts("\033[31m| !! TAMPERING DETECTED !!  |");
        puts("\033[32m'---------------------------'");
        return 1;
    }
    count = 0;
    while(count < loginlen)
    {
        // TODO encryption logic here
        if (logininput[count] <= 31)
            return 1;
        
        int stage1 = logininput[count] ^ enc_logininput;
        int stage2 = 0x88233b2b * stage1;
		int stage3 = (stage1 - stage2) >> 1;
        int stage4 = (stage3 + stage2) >> 10 * 1337;
        enc_logininput += (stage1 - stage4);
        
        ++count;
    }
    if (enc_logininput == serial_input)
        return 0;
    return 1;
}

int main(int argc, char **argv)
{
    char logininput[?];
    unsigned int serial_input;
    
    puts("***********************************");
    puts("*    level06    *");
    puts("***********************************");
    printf("-> Enter Login:");
    fgets(logininput, 32, stdin);
    puts("***********************************");
    puts("*    NEW ACOUNT DETECTED    *");
    puts("***********************************");
    printf("-> Enter Serial:");
    scanf("%u", &serial_input);
    
    if (!auth(logininput, serial_input))
    {
        system("/bin/sh");
        return 0;
    }
    return 1;
}
```

The program prompts the user for two inputs, where it will encrypt / hash the first one to check that if it matches the second. **Buffer overflow is protected as there is a canary inside the executable**. Our only way to get a shell is to get the first inputs hash correct with the second input.

We can generate a key of our own now since we know the logic, or **we could just use GDB and inspect the stack instead**. I used gdb and added a breakpoint at `8048866`, which is where the program checks for the output. I used a simple `asdfg` input to get the correct encryption by running the program.

Since they have a debugger check, we will use a **manual jump to jump over the check itself**. We will add a breakpoint before and after the check so that we can manually jump over it without messing up the memory state (break at `80487b5`, jmp to `80487ba`). As we can see, its comparing to the decimal `6229077`
```
cat << EOF > /tmp/level06
ASDFGH
12345
EOF

gdb ./level06

b *0x80487b5
b *0x8048866
lay asm
focus cmd
tty /dev/pts/1
set disassembly-flavor intel
run < /tmp/level06
jump *0x80487ba
x/10d $ebp-0x10
```

![image](https://hackmd.io/_uploads/S1ATR2T86.png)

We change our key to 6229077 and it worked, our password is `GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8`

![image](https://hackmd.io/_uploads/ByXOJapUp.png)


