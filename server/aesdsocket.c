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
#include <time.h>
#include <stdbool.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>

#define USE_AESD_CHAR_DEVICE

static bool m_signalReceived = 0;

#ifdef USE_AESD_CHAR_DEVICE
const char BUF_FILE_NAME[] = "/dev/aesdchar";
#else
const char BUF_FILE_NAME[] = "/var/tmp/aesdsocketdata";
#endif

#ifndef USE_AESD_CHAR_DEVICE
struct timerParam {
    pthread_mutex_t *fileMutex;
    FILE *fp;
};
#endif

struct socketParam {
    pthread_t thread;
    int acceptedFd;
    uint8_t ipv4[4];
    pthread_mutex_t *fileMutex;
    FILE *fp;
    bool *stopFlag;
};

struct node {
    struct socketParam data;
    struct node* next;
};

void handleSignal(int signum) {
    m_signalReceived = 1;
}

static void* socketThread(void *threadParam) {
    struct socketParam* param = (struct socketParam*)threadParam;
    int acceptedFd = param->acceptedFd;
    uint8_t *ipv4 = param->ipv4;
    pthread_mutex_t *fileMutex = param->fileMutex;
    FILE *fp = param->fp;
    bool *stopFlag = param->stopFlag;
    int isHasError = 0;

    char *recvBuf = malloc(4096);
    if (recvBuf == NULL) {
        syslog(LOG_ERR, "malloc failed");
        return threadParam;
    }

    syslog(LOG_INFO, "Accepted connection from %u.%u.%u.%u", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
    while (!(*stopFlag) && !isHasError) {
        int rc;
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

        if((rc = pthread_mutex_lock(fileMutex)) != 0) {
            syslog(LOG_ERR, "Failed to lock mutex, rc:%d", rc);
            isHasError = true;
            break;
        }

        size_t writtenLen = fwrite(recvBuf, sizeof(char), writeLen, fp);
        if(writtenLen != writeLen) {
            syslog(LOG_ERR, "fwrite error: %s", strerror(errno));
            isHasError = 1;
        }

        if (isEndCharFound && !isHasError) {
#ifdef USE_AESD_CHAR_DEVICE
            FILE *readFp = fopen(BUF_FILE_NAME, "r");
            if (NULL == fp) {
                syslog(LOG_ERR, "Failed to open file for read %s", BUF_FILE_NAME);
                isHasError = 1;
            }
#else
            FILE *readFp = fp
            long writePos = ftell(fp);

            int ret = fseek(fp, 0, SEEK_SET);
            if (ret != 0) {
                syslog(LOG_ERR, "fseek error: %s", strerror(errno));
                isHasError = 1;
            }
#endif
            
            // Set to non-zero value
            size_t readLen = 4095;
            while(!isHasError && readLen != 0) {
                readLen = fread(recvBuf, sizeof(char), 4095, readFp);
                recvBuf[readLen] = '\0';
                ssize_t sendLen = send(acceptedFd, recvBuf, readLen, 0);
                if (sendLen == -1) {
                    syslog(LOG_ERR, "send error: %s", strerror(errno));
                    isHasError = 1;
                }
                printf("%s", recvBuf);
            };

            int ferrVal = ferror(readFp);
            if (ferrVal != 0) {
                syslog(LOG_ERR, "fread error: %d", ferrVal);
                isHasError = 1;
            }

#ifdef USE_AESD_CHAR_DEVICE
            fclose(readFp);
#else
            ret = fseek(fp, writePos, SEEK_SET);
            if (ret != 0) {
                syslog(LOG_ERR, "fseek error: %s", strerror(errno));
                isHasError = 1;
            }
#endif
        }

        if((rc = pthread_mutex_unlock(fileMutex)) != 0) {
            syslog(LOG_ERR, "Failed to unlock mutex, rc:%d", rc);
            isHasError = true;
            break;
        }
    }
    free(recvBuf);
    close(acceptedFd);
    syslog(LOG_ERR, "Close connection from %u.%u.%u.%u", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);

    return threadParam;
}

static void insertNode(struct node* head, struct node* newNode) {
    struct node** lastNodePtr = &head;
    while((*lastNodePtr) != NULL) {
        lastNodePtr = &(head->next);
    }
    *lastNodePtr = newNode;
}

static int injectNewThread(struct node* head, int acceptedFd, uint8_t* ipv4, pthread_mutex_t *fileMutex, FILE *fp, bool* stopFlag)
{
    struct node* newNode = calloc(1, sizeof(struct node));
    if (newNode == NULL) {
        syslog(LOG_ERR, "new thead node malloc failed");
        return -1;
    }

    newNode->data.acceptedFd = acceptedFd;
    newNode->data.fileMutex = fileMutex;
    newNode->data.fp = fp;
    memcpy(newNode->data.ipv4, ipv4, 4);
    newNode->data.stopFlag = stopFlag;

    int rc = pthread_create(&newNode->data.thread, NULL, socketThread, &newNode->data);
    if (rc != 0) {
        syslog(LOG_ERR, "Failed to create thread:%d", rc);
        free(newNode);
        return -1;
    }

    insertNode(head, newNode);
    return 0;
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

#ifndef USE_AESD_CHAR_DEVICE
static void timerThread(union sigval sigval)
{
    struct timerParam *param = (struct timerParam*) sigval.sival_ptr;
    pthread_mutex_t *fileMutex = param->fileMutex;
    FILE *fp = param->fp;
    int rc;

    if((rc = pthread_mutex_lock(fileMutex)) != 0) {
        syslog(LOG_ERR, "Failed to lock mutex, rc:%d", rc);
        return;
    }

    char timeBuf[80];
    time_t rawTime;
    struct tm localTime;
    time(&rawTime);
    localtime_r(&rawTime, &localTime);

    size_t timeSize = strftime(timeBuf, sizeof(timeBuf), "timestamp:%Y-%m-%d %H%M\n", &localTime);

    size_t writtenLen = fwrite(timeBuf, sizeof(char), timeSize, fp);
    if(writtenLen != timeSize) {
        syslog(LOG_ERR, "fwrite error: %s", strerror(errno));
    }

    if((rc = pthread_mutex_unlock(fileMutex)) != 0) {
        syslog(LOG_ERR, "Failed to unlock mutex, rc:%d", rc);
    }

    return;
}

int startTimer(timer_t *timerId, struct timerParam *param)
{
    struct sigevent sev;
    int ret;
    memset(&sev, 0, sizeof(struct sigevent));

    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_value.sival_ptr = param;
    sev.sigev_notify_function = timerThread;
    if ((ret = timer_create(CLOCK_MONOTONIC, &sev, timerId)) != 0) {
        syslog(LOG_ERR, "timer create failed:%d", ret);
        return -1;
    }

    struct itimerspec timespec;
    memset(&timespec, 0, sizeof(struct itimerspec));
    timespec.it_value.tv_sec = 10;
    timespec.it_interval.tv_sec = 10;
    if ((ret = timer_settime(*timerId, 0, &timespec, NULL)) != 0) {
        syslog(LOG_ERR, "timer settime failed %d", ret);
        int rc;
        if ((rc = timer_delete(*timerId)) != 0) {
            syslog(LOG_ERR, "timer delete failed %d", rc);
        }
        return -1;
    }

    return 0;
}
#endif

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

    struct node* head = NULL;
    pthread_mutex_t fileMutex;
    if ((status = pthread_mutex_init(&fileMutex, NULL)) != 0) {
        syslog(LOG_ERR, "Mutex create err:%d", status);
        exit(-1);
    }

    FILE *fp = fopen(BUF_FILE_NAME, "w+");
    if (NULL == fp) {
        syslog(LOG_ERR, "Failed to open file %s", BUF_FILE_NAME);
        exit(-1);
    }

#ifndef USE_AESD_CHAR_DEVICE
    timer_t timerId;
    struct timerParam timerParam;
    timerParam.fileMutex = &fileMutex;
    timerParam.fp = fp;
    if ((status = startTimer(&timerId, &timerParam)) != 0) {
        syslog(LOG_ERR, "Failed to start timer");
        exit(-1);
    }
#endif

    while (!m_signalReceived) {
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

        // start thread
        int ret = injectNewThread(head, acceptedFd, ipV4Val, &fileMutex, fp, &m_signalReceived);
        if (ret != 0) {
            close(acceptedFd);
            break;
        }
    }

    struct node* tail = head;
    while (tail != NULL) {
        struct node* currNode = tail;
        if ((status = pthread_join(currNode->data.thread, NULL)) != 0) {
            uint8_t *ipv4 = currNode->data.ipv4;
            syslog(LOG_ERR, "join thread for %u.%u.%u.%u err:%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3], status);
        }
        tail = tail->next;
        free(currNode);
    }

#ifndef USE_AESD_CHAR_DEVICE
    timer_delete(timerId);
#endif
    fclose(fp);
#ifndef USE_AESD_CHAR_DEVICE
    remove(BUF_FILE_NAME);
#endif
    close(so);
    syslog(LOG_ERR, "Caught signal, exiting");

    exit(0);
}