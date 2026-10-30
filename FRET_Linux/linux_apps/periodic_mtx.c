/*periodic_mtx.c */

#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <sched.h>


#define PERIOD_NS   10000L   // 10us
                               
#define N_JOBS      3        
                            


#define LOW_WORK_BASE      1500U
#define LOW_WORK_SCALE      280U
#define MSG_WORK_BASE       900U
#define MSG_WORK_SCALE      180U
#define HI_SPAN_BASE        128U
#define HI_SPAN_SCALE       256U


volatile char fuzz_input_buffer[1024];  // fuzzer input
volatile int  fuzz_data_ready = 1;      // flag


volatile char fuzz_snapshot_trigger = 0;

__attribute__((noinline))
static void fuzz_snapshot_point(void)
{
    
    fuzz_snapshot_trigger++;
}

static pthread_mutex_t control_mutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  control_cv     = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t resource_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned low_req_seq = 0;
static unsigned low_done_seq = 0;
static unsigned low_lock_seq = 0;
static unsigned low_req_iters = 0;

static unsigned msg_req_seq = 0;
static unsigned msg_done_seq = 0;
static unsigned msg_payload = 0;

volatile unsigned message_counter = 0;


static unsigned long process_input(const volatile char *buf, int len)
{
    unsigned long acc  = 0x517CC1B727220A95UL;
    unsigned long acc2 = 0;
    int i, j, k;

    
    for (i = 0; i < len; i++) {
        unsigned char b = (unsigned char)buf[i];
        int depth = (b & 0x3F) + 1;
        for (j = 0; j < depth; j++) {
            acc = acc * 6364136223846793005UL + (unsigned long)b + j;
            acc2 ^= acc >> 17;
        }
    }

    for (i = 0; i < len; i += 4) {
        unsigned char b = (unsigned char)buf[i];
        if (acc & 1) {
            for (j = 0; j < 8; j++) {
                acc  ^= (acc >> j) | ((unsigned long)(unsigned char)buf[(i + j) % len] << (j * 3 % 57));
                acc2 += acc;
            }
        } else {
            acc ^= (unsigned long)b << 7;
            acc2 -= acc;
        }
    }

    
    {
        int scan_dist = (int)(acc & 0x3F) + 1;
        for (k = len - 1; k >= 0 && (len - 1 - k) < scan_dist; k--) {
            acc  ^= (unsigned long)(unsigned char)buf[k];
            acc2 += (unsigned long)(unsigned char)buf[k] + (len - k);
        }
    }

    return acc ^ acc2;
}

static void busy_mix(unsigned iters, unsigned long seed)
{
    unsigned i;
    unsigned long x = seed ^ 0x9E3779B97F4A7C15UL;

    for (i = 0; i < iters; i++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
    }

    message_counter ^= (unsigned)(x & 0xFFFFU);
}

static unsigned trigger_low_task(unsigned iters)
{
    unsigned seq;
    pthread_mutex_lock(&control_mutex);
    low_req_iters = iters;
    low_req_seq++;
    seq = low_req_seq;
    pthread_cond_broadcast(&control_cv);
    pthread_mutex_unlock(&control_mutex);
    return seq;
}

static unsigned trigger_message_task(unsigned payload)
{
    unsigned seq;
    pthread_mutex_lock(&control_mutex);
    msg_payload = payload;
    msg_req_seq++;
    seq = msg_req_seq;
    pthread_cond_broadcast(&control_cv);
    pthread_mutex_unlock(&control_mutex);
    return seq;
}

static void wait_low_holding(unsigned seq)
{
    pthread_mutex_lock(&control_mutex);
    while (low_lock_seq < seq) {
        pthread_cond_wait(&control_cv, &control_mutex);
    }
    pthread_mutex_unlock(&control_mutex);
}

static void wait_low_done(unsigned seq)
{
    pthread_mutex_lock(&control_mutex);
    while (low_done_seq < seq) {
        pthread_cond_wait(&control_cv, &control_mutex);
    }
    pthread_mutex_unlock(&control_mutex);
}

static void wait_message_done(unsigned seq)
{
    pthread_mutex_lock(&control_mutex);
    while (msg_done_seq < seq) {
        pthread_cond_wait(&control_cv, &control_mutex);
    }
    pthread_mutex_unlock(&control_mutex);
}

static void *low_task_thread(void *arg)
{
    unsigned seen = 0;
    (void)arg;

    while (1) {
        unsigned iters;

        pthread_mutex_lock(&control_mutex);
        while (low_req_seq == seen) {
            pthread_cond_wait(&control_cv, &control_mutex);
        }
        seen = low_req_seq;
        iters = low_req_iters;
        pthread_mutex_unlock(&control_mutex);

        pthread_mutex_lock(&resource_mutex);
        pthread_mutex_lock(&control_mutex);
        low_lock_seq = seen;
        pthread_cond_broadcast(&control_cv);
        pthread_mutex_unlock(&control_mutex);

        busy_mix(iters, 0x11111111UL + seen);

        pthread_mutex_unlock(&resource_mutex);

        pthread_mutex_lock(&control_mutex);
        low_done_seq = seen;
        pthread_cond_broadcast(&control_cv);
        pthread_mutex_unlock(&control_mutex);
    }
    return NULL;
}

static void *medium_task_thread(void *arg)
{
    unsigned seen = 0;
    (void)arg;

    while (1) {
        unsigned payload;
        unsigned local_seq;

        pthread_mutex_lock(&control_mutex);
        while (msg_req_seq == seen) {
            pthread_cond_wait(&control_cv, &control_mutex);
        }
        seen = msg_req_seq;
        local_seq = seen;
        payload = msg_payload;
        pthread_mutex_unlock(&control_mutex);

        busy_mix(MSG_WORK_BASE + payload * MSG_WORK_SCALE,
                 0x22222222UL + payload + local_seq);

        pthread_mutex_lock(&control_mutex);
        msg_done_seq = local_seq;
        message_counter++;
        pthread_cond_broadcast(&control_cv);
        pthread_mutex_unlock(&control_mutex);
    }
    return NULL;
}



__attribute__((noinline))
static void fuzz_checkpoint(unsigned long result)
{
    (void)result;
    syscall(SYS_getpid);   // getpid
}


int main(void)
{
    struct timespec    wake;
    unsigned long      acc = 0;
    pthread_t          low_tid;
    pthread_t          med_tid;
    pthread_attr_t     attr;
    struct sched_param param;
    int i;

    volatile char touch = 0;
    for (int k = 0; k < 1024; k++) {
        touch ^= fuzz_input_buffer[k];
    }
    (void)touch;

    // HIGH = main thread, prio 90
    FILE *f = fopen("/root/rt_test.log", "w");
    if (!f) f = stdout;

    param.sched_priority = 90;
    if (sched_setscheduler(0, SCHED_FIFO, &param) == -1) {
        fprintf(f, "=== RT_TEST: sched_setscheduler FAILED for HIGH (main) ===\n");
    } else {
        fprintf(f, "=== RT_TEST: sched_setscheduler SUCCESS for HIGH (main) ===\n");
    }
    fflush(f);
    if (f != stdout) fclose(f);
    sync();




    pthread_attr_init(&attr);
    pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
    pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);

    param.sched_priority = 50;  // low holds mutex
    pthread_attr_setschedparam(&attr, &param);
    if (pthread_create(&low_tid, &attr, low_task_thread, NULL) != 0) {
        printf("=== RT_TEST: pthread_create failed for LOW ===\n");
    }

    param.sched_priority = 70;  // med indep
    pthread_attr_setschedparam(&attr, &param);
    if (pthread_create(&med_tid, &attr, medium_task_thread, NULL) != 0) {
        printf("=== RT_TEST: pthread_create failed for MEDIUM ===\n");
    }


    pthread_attr_destroy(&attr);

    while (1) {

        fuzz_snapshot_point();

        clock_gettime(CLOCK_MONOTONIC, &wake);

        for (i = 0; i < N_JOBS; i++) {
            unsigned idx;
            unsigned flags;
            unsigned low_iters;
            unsigned payload;
            unsigned hi_span;
            unsigned low_seq = 0;
            unsigned msg_seq = 0;

            wake.tv_nsec += PERIOD_NS;
            if (wake.tv_nsec >= 1000000000L) {
                wake.tv_nsec -= 1000000000L;
                wake.tv_sec  += 1;
            }

            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &wake, NULL);

            idx = (unsigned)(i * 16) & 0x3FFU;
            flags = (unsigned char)fuzz_input_buffer[idx + 0];
            low_iters = LOW_WORK_BASE +
                        ((unsigned char)fuzz_input_buffer[idx + 1] * LOW_WORK_SCALE);
            payload = (unsigned char)fuzz_input_buffer[idx + 2];
            hi_span = HI_SPAN_BASE +
                      ((unsigned char)fuzz_input_buffer[idx + 3] & 0x7FU) * 2U;

            
            if (flags & 0x01U) {
                msg_seq = trigger_message_task(payload);
                if (flags & 0x02U) {
                    wait_message_done(msg_seq);
                }
            }

            if (flags & 0x04U) {
                low_seq = trigger_low_task(low_iters);
                wait_low_holding(low_seq);

                if (flags & 0x08U) {
                    msg_seq = trigger_message_task(payload ^ 0xA5U);
                }

                pthread_mutex_lock(&resource_mutex);
                acc ^= process_input(&fuzz_input_buffer[idx],
                                     (int)((hi_span < 1024U) ? hi_span : 1024U));
                pthread_mutex_unlock(&resource_mutex);

                wait_low_done(low_seq);
                if (flags & 0x08U) {
                    wait_message_done(msg_seq);
                }
            } else {
                pthread_mutex_lock(&resource_mutex);
                acc ^= process_input(&fuzz_input_buffer[idx],
                                     (int)((hi_span < 1024U) ? hi_span : 1024U));
                pthread_mutex_unlock(&resource_mutex);
            }

            acc ^= process_input(fuzz_input_buffer, 256);
        }

        fuzz_checkpoint(acc);
    }
    return 0;
}
