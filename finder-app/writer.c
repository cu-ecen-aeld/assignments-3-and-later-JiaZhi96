#include "syslog.h"
#include "stdio.h"
#include "stdbool.h"
#include "string.h"

int main(int argc, char **argv)
{
    openlog(NULL, 0, LOG_USER);

    if (argc != 3)
    {
        syslog(LOG_ERR, "Need 2 arguments, filename and writestring");
        return 1;
    }

    const char *fileName = argv[1];
    const char *writeStr = argv[2];

    syslog(LOG_DEBUG, "Writing %s to %s", writeStr, fileName);

    FILE *fp = fopen(fileName, "w");
    if (NULL == fp)
    {
        syslog(LOG_ERR, "Failed to open file %s", fileName);
        return 1;
    }

    bool isFileWriteSucceed = true;
    size_t writeLen = strlen(writeStr);
    size_t len = fwrite(writeStr, sizeof(char), writeLen, fp);
    if (len != writeLen)
    {
        syslog(LOG_ERR, "Failed to write to file %zu %zu", len, writeLen);
        isFileWriteSucceed = false;
    }

    fclose(fp);
    
    return (isFileWriteSucceed) ? 0 : 1;
}