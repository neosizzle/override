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