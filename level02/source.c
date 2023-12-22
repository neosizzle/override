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