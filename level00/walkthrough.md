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

