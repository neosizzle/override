void decrypt(uintptr_t init_addr)
{
    int var1 = 20; // canary?
    int cipher1 = 0x757c7d51; // Q}|u
    int cipher2 = 0x67667360; // `sfg
    int cipher3 = 0x7b66737e; // ~sf{
    int cipher4 = 0x33617c7d; // }|a3
    int cipher5 = 0x00000000;
    int clear_mask = 0xffffffff;
    int cipherlen = 0;
    int count = 0;
    int xor_res = 0;
    int temp = 0;
    
    cipherlen = strlen(&cipher1);
    while (count < cipherlen)
    {
        xor_res = &cipher1[count] ^ init_addr;
        &cipher1[count] = xor_res;
        ++count;
    }
    if (!strncmp(cipher1, "Congratulations!", 17))
    {
        system("/bin/sh");
        return ;
    }
    puts("Invalid Password");
}

void test(int pwinput, uintptr_t init_addr)
{
    uintptr_t res = init_addr - pwinput;
    
    if (init_addr > 21)
    {
        decrypt(rand());
    }
    else {
        sub *= 4;
        sub += 0x80489f0;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
        decrypt(res); return;
    }
}

int main()
{
    int pwinput;
    
    srand(time(0));
    puts("***********************************");
    puts("*               level03         **");
    puts("***********************************");
    printf("Password:");
    scanf("%d", &pwinput);
    test(pwinput, 0x1337d00d);
}