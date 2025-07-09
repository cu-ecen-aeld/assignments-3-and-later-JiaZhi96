#include "stdio.h"
#include "errno.h"
#include "syslog.h"
#include "string.h"
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <fcntl.h>

static int m_signalReceived = 0;
void handleSignal(int signum) {
    m_signalReceived = 1;
}

int redirectStdIo(void) {
    int devNullInFd = open("/dev/null", O_RDONLY);
    if (devNullInFd == -1) {
        perror("open /dev/null for stdin");
        return -1;
    }

    // Open /dev/null for writing (for stdout and stderr)
    int devNullOutFd = open("/dev/null", O_WRONLY);
    if (devNullOutFd == -1) {
        perror("open /dev/null for stdout/stderr");
        close(devNullInFd);
        return -1;
    }

    // Redirect stdin (file descriptor 0) to /dev/null
    if (dup2(devNullInFd, STDIN_FILENO) == -1) {
        perror("dup2 stdin");
        close(devNullInFd);
        close(devNullOutFd);
        return -1;
    }

    // Redirect stdout (file descriptor 1) to /dev/null
    if (dup2(devNullOutFd, STDOUT_FILENO) == -1) {
        perror("dup2 stdout");
        close(devNullInFd);
        close(devNullOutFd);
        return -1;
    }

    // Redirect stderr (file descriptor 2) to /dev/null
    if (dup2(devNullOutFd, STDERR_FILENO) == -1) {
        perror("dup2 stderr");
        close(devNullInFd);
        close(devNullOutFd);
        return -1;
    }
        
    close(devNullInFd);
    close(devNullOutFd);

    return 0;
}

int main(int argc, char **argv)
{
    bool isDaemonMode = false;
    if (argc == 2) {
        char *arg = argv[1];
        if(strncmp(arg, "-d", 2) == 0) {
            isDaemonMode = true;
        }
    }

    if (isDaemonMode) {
        int pid = fork();
        bool isParent = (pid != 0);
        
        if (isParent) {
            exit(0);
        }
        else {
            setsid();
            if(redirectStdIo() != 0) {
                exit(-1);
            }
        }
    }

    struct sigaction sa;
    sa.sa_handler = handleSignal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    openlog(NULL, LOG_PERROR, LOG_USER);

    int so = socket(PF_INET, SOCK_STREAM, 0);

    int status;
    struct addrinfo *servinfo;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    if ((status = getaddrinfo(NULL, "9000", &hints, &servinfo)) != 0) {
        syslog(LOG_ERR, "getaddrinfo error: %s", gai_strerror(status));
        exit(-1);
    }

    if ((status = bind(so, servinfo->ai_addr, servinfo->ai_addrlen)) != 0) {
        syslog(LOG_ERR, "bind error: %s", strerror(errno));
        exit(-1);
    }

    freeaddrinfo(servinfo);

    if ((status = listen(so, 1)) != 0) {
        syslog(LOG_ERR, "listen error: %s", strerror(errno));
        exit(-1);
    }
   
    char *recvBuf = malloc(4096);
    if (recvBuf == NULL) {
        syslog(LOG_ERR, "malloc failed");
        exit(-1);
    }

    const char bufFile[] = "/var/tmp/aesdsocketdata";
    FILE *fp = fopen(bufFile, "w+");
    if (NULL == fp) {
        syslog(LOG_ERR, "Failed to open file %s", bufFile);
    }

    int isHasError = 0;
    while (!m_signalReceived && !isHasError) {
        struct sockaddr clientAddr;
        memset(&clientAddr, 0, sizeof(clientAddr));
        socklen_t clientAddrLen = 0;
        int acceptedFd = accept(so, &clientAddr, &clientAddrLen);
        if (acceptedFd == -1) {
            syslog(LOG_ERR, "accept error: %s", strerror(errno));
            break;
        }

        struct sockaddr_in *clientAddrIn = (struct sockaddr_in*)(&clientAddr);
        uint8_t *ipV4Val = (uint8_t*)(&(clientAddrIn->sin_addr));
        syslog(LOG_INFO, "Accepted connection from %u.%u.%u.%u", ipV4Val[0], ipV4Val[1], ipV4Val[2], ipV4Val[3]);


        while (!m_signalReceived && !isHasError) {
            ssize_t recvLen = recv(acceptedFd, recvBuf, 4096, 0);
            if (recvLen == -1) {
                syslog(LOG_ERR, "recv error: %s", strerror(errno));
                if (errno == EINTR) {
                    isHasError = 1;
                    break;
                }
            } else if (recvLen == 0) {
                syslog(LOG_ERR, "socket closed");
                break;
            }
            
            int isEndCharFound = 0;
            size_t writeLen = recvLen;
            char *endChar = memchr(recvBuf, '\n', recvLen);
            if (endChar != NULL) {
                writeLen = (endChar - recvBuf) + 1;
                isEndCharFound = 1;
            }

            size_t writtenLen = fwrite(recvBuf, sizeof(char), writeLen, fp);
            if(writtenLen != writeLen) {
                syslog(LOG_ERR, "fwrite error: %s", strerror(errno));
                isHasError = 1;
                break;
            }

            if (isEndCharFound) {
                long writePos = ftell(fp);

                int ret = fseek(fp, 0, SEEK_SET);
                if (ret != 0) {
                    syslog(LOG_ERR, "fseek error: %s", strerror(errno));
                    isHasError = 1;
                }
                
                size_t readLen;
                do {
                    readLen = fread(recvBuf, sizeof(char), 4095, fp);
                    recvBuf[readLen] = '\0';
                    ssize_t sendLen = send(acceptedFd, recvBuf, readLen, 0);
                    if (sendLen == -1) {
                        syslog(LOG_ERR, "send error: %s", strerror(errno));
                        isHasError = 1;
                        break;
                    }
                    printf("%s", recvBuf);
                } while(readLen == 4095);
    
                int ferrVal = ferror(fp);
                if (ferrVal != 0) {
                    syslog(LOG_ERR, "fread error: %d", ferrVal);
                    isHasError = 1;
                    break;
                }

                ret = fseek(fp, writePos, SEEK_SET);
                if (ret != 0) {
                    syslog(LOG_ERR, "fseek error: %s", strerror(errno));
                    isHasError = 1;
                }
            }
        }

        close(acceptedFd);
        syslog(LOG_ERR, "Close connection from %u.%u.%u.%u", ipV4Val[0], ipV4Val[1], ipV4Val[2], ipV4Val[3]);
    }

    free(recvBuf);
    fclose(fp);
    remove(bufFile);
    close(so);
    // complet open connection, close close socket, delete /var/tmp/aesdsocketdata
    syslog(LOG_ERR, "Caught signal, exiting");

    exit(0);
}