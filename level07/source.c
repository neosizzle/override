void clear_stdin()
{
    char curr;
    
    while(1)
    {
        curr = getchar();
        if (curr == '\n' || curr == -1)
            return ;
    }
}

unsigned int get_unum()
{
    unsigned int res;
    
    fflush(stdout);
    scanf("%u", &res);
    clear_stdin();
    return res;
}

int store_number( int *meat)
{    
    unsigned int num_input = 0;
    unsigned int idx_input = 0
    unsigned int temp1 = 0xaaaaaaab;
        
    printf("Number: ")
    num_input = get_unum();
    printf("Index: ")
    idx_input = get_unum();
    
    idx_input += temp1;
    temp1 = temp1 >> 1;
    unsigned int temp2 = temp1;
    temp2 *= 2;
    temp2 += temp1;
    unsigned int temp3 = 0xaaaaaaab - temp2;
    if(temp3 != 0 || num_input >> 0x18 != 0xb7)
    {
        meat[idx_input] = num_input;
        return 0;
    }
    puts(" *** ERROR! ***");
    puts("   This index is reserved for wil!");
    puts(" *** ERROR! ***");
    return 1;
}

int read_number(unsigned int *meat)
{
    int num_input = 0;
    
    printf("Index: ");
    num_input = get_unum() << 2 + meat;
    printf("Number at data[%u] is %u, ", num_input, meat[num_input]); // does << 2 + meat implicitly
    return 0;
}


int main(int argc, char **argv, char **envp)
{
    char **argv_stack = argv;
    char **envp_stack = enp;
    int op_ret = 0;
    char user_cmd[20] = 0; // 4 * 5
    int meat[16]; // 64 / 4
    
    memset(meat, 0, 16);
    while(argv_stack)
    {
        memset(*argv_stack, 0, strlen(*argv_stack));
        ++argv_stack;
    }
    
    while(envp_stack)
    {
        memset(*envp_stack, 0, strlen(*envp_stack));
        ++envp_stack;
    }
    
     puts("----------------------------------------------------\n"\
           "  Welcome to wil's crappy number storage service!   \n"\
           "----------------------------------------------------\n"\
           " Commands:                                          \n"\
           "    store - store a number into the data storage    \n"\
           "    read  - read a number from the data storage     \n"\
           "    quit  - exit the program                        \n"\
           "----------------------------------------------------\n"\
           "   wil has reserved some storage :>                 \n"\
           "----------------------------------------------------\n"\
           "\n");
    
    while(1)
    {
        op_ret = 1；
        printf("Input command: ");
        fgets(user_cmd, 20, stdin);
        user_cmd[strcspn(user_cmd, "\n")] = 0;
        
        if (!strncmp(user_cmd, "store", 5))
            op_ret = store_number(meat);
        else if (!strncmp(user_cmd, "read", 4))
            op_ret = read_number(meat);
        else if (strncmp(user_cmd, "quit", 4))
            break;
        
        if (!op_ret)
            printf("Completed %s command successfully", user_cmd);
        else 
            printf("Failed to do %s command\n", user_cmd);
       
       memset(user_cmd, 0, 20);
       op_ret = 1;
    }
    return 0;
}
