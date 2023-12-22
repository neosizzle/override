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