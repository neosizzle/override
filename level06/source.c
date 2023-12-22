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