int main()
{
    int count = 0;
    char inputbuf[?];
    
    fgets(inputbuf, 100, stdin);
    count = 0;
    while(strlen(inputbuf) > count)
    {
        if (inputbuf[count] <= 64 && inputbuf[count] > 90)
        {
            ++count;
            continue;
        }
        else
        {
            inputbuf[count] = inputbuf[count] ^ 32;
            ++count;
        }
    }
    printf(inputbuf);
    exit(0);
}