## level03 (XOR cipher)
```clike!
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
```

The program takes in a decimal as the password and runs some decryption methods to check for the password. Looking at the code, it seems like we are not going to be doing any overflows since there is an existence of a canary. Hence, we will need to work on the decryption itself.

We noticed that this is a [XOR Cipher](https://en.wikipedia.org/wiki/XOR_cipher) where every bit in the plaintext is XOR'ed against every bit in a key. It is a good fundamental encryption becase in XOR encryption, **It is clear that if nothing is known about the key or plaintext, nothing can be determined from the ciphertext alone**.

in a nutshell, our `decrypt` function takes in `init_addr`, this will be our key. The plaintext in this case is the consecutive bytes in `cipher1` to `cipher5`.The encrypted text is `"Congratulations!"`. The program takes the key as the input an encrypts the plaintext with it to compare if the ciphertext is correct. If it is, we will be able to access shell.

If we look at this table, we can see some basic operations of the XOR cipher. If we have the ciphertext and the plaintext, **to get key, we can use `plaintext ^ ciphertext`**
![image](https://hackmd.io/_uploads/BkjPPUj8a.png)

As we can see, using a decoder, the key is `18` for all characters 
![image](https://hackmd.io/_uploads/SkAOoTiIT.png)

And since the input needs to be deducted by `0x1337d00d` to get the key, our input should be `0x1337d00d - 0x12(18)` which is `0x1337cffb` or `322424827` in base 10. We are able to get the password `kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf`

![image](https://hackmd.io/_uploads/H1-rn6jLT.png)


