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