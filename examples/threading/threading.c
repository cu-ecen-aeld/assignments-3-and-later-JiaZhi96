#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    struct thread_data *param = (struct thread_data *)thread_param;
    int rc = 0;

    if(param->wait_before_obtain_ms > 0)
    {
        DEBUG_LOG("Wait %dms", param->wait_before_obtain_ms);
        rc = usleep(param->wait_before_obtain_ms * 1000);
        if(rc != 0)
        {
            ERROR_LOG("Early wake sleep before obtain mutex, time left: %dms", rc);
            return thread_param;
        }
    }

    DEBUG_LOG("Lock mutex");
    rc = pthread_mutex_lock(param->mutex);
    if(rc != 0)
    {
        ERROR_LOG("Failed to lock mutex, rc:%d", rc);
        return thread_param;
    }

    if(param->wait_before_release_ms > 0)
    {
        DEBUG_LOG("Wait %dms", param->wait_before_release_ms);
        rc = usleep(param->wait_before_release_ms * 1000);
        if(rc != 0)
        {
            ERROR_LOG("Early wake sleep before releasing mutex, time left: %dms", rc);
            // No return because we must release the mutex
        }
    }

    DEBUG_LOG("Unlock mutex");
    rc = pthread_mutex_unlock(param->mutex);
    if(rc != 0)
    {
        ERROR_LOG("Failed to unlock mutex, rc:%d", rc);
        return thread_param;
    }

    param->thread_complete_success = true;
    
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
    struct thread_data* thread_param = malloc(sizeof(struct thread_data));
    if(NULL == thread_param)
    {
        ERROR_LOG("Failed to malloc for thread_data");
        return false;
    }
    thread_param->mutex = mutex;
    thread_param->wait_before_obtain_ms = wait_to_obtain_ms;
    thread_param->wait_before_release_ms = wait_to_release_ms;
    thread_param->thread_complete_success = false;

    int rc;
    rc = pthread_create(thread, NULL, threadfunc, thread_param);
    if(rc != 0)
    {
        ERROR_LOG("Failed to created pthread, rc:%d", rc);
        return false;
    }

    return true;
}

