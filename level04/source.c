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