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