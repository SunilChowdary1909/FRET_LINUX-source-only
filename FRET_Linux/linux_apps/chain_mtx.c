/*
 * chain_mtx.c 
 */

#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <sched.h>
#include <mqueue.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>

static void debug_sig_handler(int sig) {
    // async-signal-safe write, not printf
    char buf[32];
    buf[0] = 'S'; buf[1] = 'I'; buf[2] = 'G'; buf[3] = '\n';
    write(2, buf, 4);
}

#define PERIOD_NS       10000L   // 10us
#define N_JOBS          3        // jobs per run

#define LOW_HOLD_BASE       2000U
#define LOW_HOLD_SCALE       400U
#define MEDA_WORK_BASE      1000U
#define MEDA_WORK_SCALE      200U
#define MEDB_WORK_BASE      1500U
#define MEDB_WORK_SCALE      300U
#define HIGH_SPAN_BASE       128U
#define HIGH_SPAN_SCALE      256U


volatile char fuzz_input_buffer[1024];
volatile int  fuzz_data_ready = 1;

static mqd_t mq_low_meda  = (mqd_t)-1;  // low to med_a
static mqd_t mq_meda_high = (mqd_t)-1;  // med_a to high
static mqd_t mq_trigger_low  = (mqd_t)-1;  // trigger low
static mqd_t mq_trigger_medb = (mqd_t)-1;  // trigger med_b
static mqd_t mq_medb_done    = (mqd_t)-1;  // med_b done

// msg struct
typedef struct {
    unsigned long value;
    unsigned      iters;
    unsigned      payload_off;
    unsigned      seq;
} msg_t;

volatile unsigned global_counter = 0;

static unsigned long compute_nonlinear(const volatile char *buf, int len)
{
    unsigned long acc  = 0x9E3779B97F4A7C15UL;
    unsigned long acc2 = 0;
    int i, j, k;

    // phase a
    for (i = 0; i < len - 1; i++) {
        unsigned char b0 = (unsigned char)buf[i];
        unsigned char b1 = (unsigned char)buf[i + 1];
        int depth = (int)((b0 * b1) >> 4) + 1;
        if (depth > 64) depth = 64;
        for (j = 0; j < depth; j++) {
            acc  = acc * 6364136223846793005UL + (unsigned long)b0 * j;
            acc2 ^= (acc >> 13) ^ ((unsigned long)b1 << (j % 32));
        }
    }

    // phase b tree
    {
        unsigned char f0 = (unsigned char)buf[0];
        unsigned char f1 = (unsigned char)buf[1];
        unsigned char f2 = (unsigned char)buf[2];

        if (acc & 1) {
            if (f0 > 128) {
                for (i = 0; i < len; i++) {
                    acc ^= (unsigned long)(unsigned char)buf[i] * (i + 1);
                    acc2 += acc >> 7;
                }
            } else {
                for (i = 0; i < len; i += 2) {
                    acc ^= (unsigned long)(unsigned char)buf[i];
                    acc2 ^= acc;
                }
            }
            if (f1 > 64) {
                for (j = 0; j < (int)(f2 & 0x1F) + 1; j++) {
                    acc = acc * 1664525UL + 1013904223UL;
                    acc2 += (unsigned long)j * acc;
                }
            }
        } else {
            if (f0 < 64) {
                for (i = len - 1; i >= 0; i--) {
                    acc ^= (unsigned long)(unsigned char)buf[i];
                    acc2 -= acc;
                }
            } else {
                acc ^= (unsigned long)f0 * f1 * f2;
                acc2 ^= acc;
            }
        }
    }

    // phase c scatter
    {
        int scatter = (int)(acc & 0x3F) + 1;
        for (k = 0; k < scatter && k < len; k++) {
            int idx = (int)((acc >> k) & 0xFF) % len;
            acc  ^= (unsigned long)(unsigned char)buf[idx] * (k + 1);
            acc2 += (unsigned long)(unsigned char)buf[(idx + k) % len];
        }
    }
    return acc ^ acc2;
}

static void busy_burn(unsigned iters, unsigned long seed)
{
    unsigned i;
    unsigned long x = seed ^ 0x6C62272E07BB0142UL;
    for (i = 0; i < iters; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    }
    global_counter ^= (unsigned)(x & 0xFFFFU);
}

// low task loop
static void *low_task_thread(void *arg)
{
    (void)arg;
    msg_t in, out;
    write(2, "ENTERED: low_task_thread\n", 25);
    while (1) {
        write(2, "low_task_thread: waiting on mq_trigger_low\n", 43);
        while (mq_receive(mq_trigger_low, (char *)&in, sizeof(in), NULL) < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("mq_receive low");
            usleep(10000);
        }
        write(2, "low_task_thread: RECEIVED from mq_trigger_low\n", 46);

        busy_burn(in.iters, 0xAAAAAAAAUL + in.seq);

        out.value       = compute_nonlinear(
                              &fuzz_input_buffer[in.payload_off % 128], 256);
        out.iters       = in.iters;
        out.payload_off = in.payload_off;
        out.seq         = in.seq;

        // send to med_a
        write(2, "low_task_thread: sending to mq_low_meda\n", 40);
        while (mq_send(mq_low_meda, (const char *)&out, sizeof(out), 0) < 0) {
            continue;
        }
        write(2, "low_task_thread: SENT to mq_low_meda\n", 37);
    }
    return NULL;
}

static void *med_a_task_thread(void *arg)
{
    (void)arg;
    msg_t in, out;
    write(2, "ENTERED: med_a_task_thread\n", 27);
    while (1) {
        write(2, "med_a_task_thread: waiting on mq_low_meda\n", 42);
        while (mq_receive(mq_low_meda, (char *)&in, sizeof(in), NULL) < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("mq_receive meda");
            usleep(10000);
        }
        write(2, "med_a_task_thread: RECEIVED from mq_low_meda\n", 45);

        unsigned long result = compute_nonlinear(
            &fuzz_input_buffer[in.payload_off % 128],
            (int)(MEDA_WORK_BASE + in.iters * MEDA_WORK_SCALE < 512 ?
                  MEDA_WORK_BASE + in.iters * MEDA_WORK_SCALE : 512));

        if (result & 0x01) {
            result ^= compute_nonlinear(&fuzz_input_buffer[in.payload_off % 256], 256);
        }

        out.value       = result;
        out.seq         = in.seq;
        out.iters       = in.iters;
        out.payload_off = in.payload_off;

        write(2, "med_a_task_thread: sending to mq_meda_high\n", 43);
        while (mq_send(mq_meda_high, (const char *)&out, sizeof(out), 0) < 0) {
            continue;
        }
        write(2, "med_a_task_thread: SENT to mq_meda_high\n", 40);
    }
    return NULL;
}

// med_b task loop
static void *med_b_task_thread(void *arg)
{
    (void)arg;
    msg_t in, done;
    write(2, "ENTERED: med_b_task_thread\n", 27);
    while (1) {
        write(2, "med_b_task_thread: waiting on mq_trigger_medb\n", 46);
        while (mq_receive(mq_trigger_medb, (char *)&in, sizeof(in), NULL) < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("mq_receive medb");
            usleep(10000);
        }
        write(2, "med_b_task_thread: RECEIVED from mq_trigger_medb\n", 49);

        busy_burn(MEDB_WORK_BASE + in.iters * MEDB_WORK_SCALE,
                  0x55555555UL + in.seq);

        done.value = global_counter;
        done.seq   = in.seq;
        write(2, "med_b_task_thread: sending to mq_medb_done\n", 43);
        while (mq_send(mq_medb_done, (const char *)&done, sizeof(done), 0) < 0) {
            continue;
        }
        write(2, "med_b_task_thread: SENT to mq_medb_done\n", 40);
    }
    return NULL;
}

volatile char fuzz_snapshot_trigger = 0;

__attribute__((noinline))
static void fuzz_snapshot_point(void)
{
    fuzz_snapshot_trigger++;
}

__attribute__((noinline))
static void fuzz_checkpoint(unsigned long result)
{
    (void)result;
    syscall(SYS_getpid);
}

// mq setup
static mqd_t mk_queue(const char *name)
{
    struct mq_attr attr;
    attr.mq_flags   = 0;
    attr.mq_maxmsg  = 4;
    attr.mq_msgsize = sizeof(msg_t);
    attr.mq_curmsgs = 0;
    mq_unlink(name);
    return mq_open(name, O_CREAT | O_RDWR, 0644, &attr);
}

int main(void)
{
    struct timespec wake;
    unsigned long   acc = 0;
    pthread_t       low_tid, meda_tid, medb_tid;
    pthread_attr_t  attr;
    struct sched_param param;
    int i;
    unsigned seq = 0;

    for (int s = 1; s < 32; s++) {
        if (s != SIGKILL && s != SIGSTOP) {
            signal(s, debug_sig_handler);
        }
    }

    /* Create all message queues */
    mq_low_meda     = mk_queue("/fret_low_meda");
    if (mq_low_meda == (mqd_t)-1) write(2, "OPEN FAIL: mq_low_meda\n", 23); else write(2, "OPENED: mq_low_meda\n", 20);
    
    mq_meda_high    = mk_queue("/fret_meda_high");
    if (mq_meda_high == (mqd_t)-1) write(2, "OPEN FAIL: mq_meda_high\n", 24); else write(2, "OPENED: mq_meda_high\n", 21);
    
    mq_trigger_low  = mk_queue("/fret_trig_low");
    if (mq_trigger_low == (mqd_t)-1) write(2, "OPEN FAIL: mq_trigger_low\n", 26); else write(2, "OPENED: mq_trigger_low\n", 23);
    
    mq_trigger_medb = mk_queue("/fret_trig_medb");
    if (mq_trigger_medb == (mqd_t)-1) write(2, "OPEN FAIL: mq_trigger_medb\n", 27); else write(2, "OPENED: mq_trigger_medb\n", 24);
    
    mq_medb_done    = mk_queue("/fret_medb_done");
    if (mq_medb_done == (mqd_t)-1) write(2, "OPEN FAIL: mq_medb_done\n", 24); else write(2, "OPENED: mq_medb_done\n", 21);

    clock_gettime(CLOCK_MONOTONIC, &wake); write(2, "AFTER clock_gettime\n", 20);

    // main thread prio 90
    param.sched_priority = 90;
    sched_setscheduler(0, SCHED_FIFO, &param);

    pthread_attr_init(&attr); write(2, "AFTER attr_init\n", 16);
    pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
    pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);

    param.sched_priority = 50;  // low
    pthread_attr_setschedparam(&attr, &param);
    if (pthread_create(&low_tid, &attr, low_task_thread, NULL) != 0)
        write(2, "THREAD CREATE FAILED: low_tid\n", 30);
    else
        write(2, "THREAD CREATED: low_tid\n", 24); write(2, "AFTER pthread_create 1\n", 23);

    param.sched_priority = 70;  // med_a
    pthread_attr_setschedparam(&attr, &param);
    if (pthread_create(&meda_tid, &attr, med_a_task_thread, NULL) != 0)
        write(2, "THREAD CREATE FAILED: meda_tid\n", 31);
    else
        write(2, "THREAD CREATED: meda_tid\n", 25); write(2, "AFTER pthread_create 2\n", 23);

    param.sched_priority = 60;  // med_b
    pthread_attr_setschedparam(&attr, &param);
    if (pthread_create(&medb_tid, &attr, med_b_task_thread, NULL) != 0)
        write(2, "THREAD CREATE FAILED: medb_tid\n", 31);
    else
        write(2, "THREAD CREATED: medb_tid\n", 25); write(2, "AFTER pthread_create 3\n", 23);

    pthread_attr_destroy(&attr);

    write(2, "ENTERED: main loop\n", 19);
    while (1) {
        while (*fuzz_data_ready == 0) {
            usleep(10000); // 10ms instead of 100us to prevent starvation
        }
        *fuzz_data_ready = 0;

        fuzz_snapshot_point();

        for (i = 0; i < N_JOBS; i++) {
            unsigned idx = (unsigned)(i * 16) & 0x3FFU;

            unsigned flags     = (unsigned char)fuzz_input_buffer[idx + 0];
            unsigned low_iters = LOW_HOLD_BASE +
                ((unsigned char)fuzz_input_buffer[idx + 1] * LOW_HOLD_SCALE);
            unsigned meda_iters= (unsigned char)fuzz_input_buffer[idx + 2];
            unsigned medb_iters= (unsigned char)fuzz_input_buffer[idx + 3];
            unsigned hi_span   = HIGH_SPAN_BASE +
                ((unsigned char)fuzz_input_buffer[idx + 4] & 0x7FU)
                * HIGH_SPAN_SCALE;
            unsigned pay_off   = (unsigned char)fuzz_input_buffer[idx + 5];

            if (hi_span > 1024U) hi_span = 1024U;

            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            wake.tv_sec  = now.tv_sec;
            wake.tv_nsec = now.tv_nsec + PERIOD_NS;
            if (wake.tv_nsec >= 1000000000L) {
                wake.tv_nsec -= 1000000000L;
                wake.tv_sec  += 1;
            }
            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &wake, NULL);

            if (flags & 0x01U) {
                msg_t trig, result;
                seq++;

                if (flags & 0x02U) {
                    msg_t mb = { 0, medb_iters, pay_off, seq };
                    write(2, "main: sending to mq_trigger_medb\n", 33);
                    while (mq_send(mq_trigger_medb, (const char *)&mb, sizeof(mb), 0) < 0) {
                        continue;
                    }
                    write(2, "main: SENT to mq_trigger_medb\n", 30);
                }

                trig.value = 0;
                trig.iters = low_iters;
                trig.payload_off = pay_off;
                trig.seq = seq;
                write(2, "main: sending to mq_trigger_low\n", 32);
                while (mq_send(mq_trigger_low, (const char *)&trig, sizeof(trig), 0) < 0) {
                    continue;
                }
                write(2, "main: SENT to mq_trigger_low\n", 29);

                write(2, "main: waiting on mq_meda_high\n", 30);
                while (mq_receive(mq_meda_high, (char *)&result, sizeof(result), NULL) < 0) {
                    continue;
                }
                write(2, "main: RECEIVED from mq_meda_high\n", 33);
                acc ^= result.value;

                if (flags & 0x04U) {
                    acc ^= compute_nonlinear(
                        &fuzz_input_buffer[idx + 7],
                        (int)((hi_span < 1024U) ? hi_span : 1024U));
                }

                // wait med_b
                if (flags & 0x02U) {
                    msg_t mbd;
                    write(2, "main: waiting on mq_medb_done\n", 30);
                    while (mq_receive(mq_medb_done, (char *)&mbd, sizeof(mbd), NULL) < 0) {
                        continue;
                    }
                    write(2, "main: RECEIVED from mq_medb_done\n", 33);
                }

                if (flags & 0x08U) {
                    seq++;
                    trig.seq = seq;
                    trig.iters = low_iters ^ 0xFFU;
                    write(2, "main: sending to mq_trigger_low (2)\n", 36);
                    while (mq_send(mq_trigger_low, (const char *)&trig, sizeof(trig), 0) < 0) {
                        continue;
                    }
                    write(2, "main: SENT to mq_trigger_low (2)\n", 33);
                    
                    write(2, "main: waiting on mq_meda_high (2)\n", 34);
                    while (mq_receive(mq_meda_high, (char *)&result, sizeof(result), NULL) < 0) {
                        continue;
                    }
                    write(2, "main: RECEIVED from mq_meda_high (2)\n", 37);
                    acc ^= result.value;
                }
            } else {
                acc ^= compute_nonlinear(
                    &fuzz_input_buffer[idx + 7],
                    (int)((hi_span < 1024U) ? hi_span : 1024U));
            }

            acc ^= compute_nonlinear(fuzz_input_buffer, 256);
        }

        fuzz_checkpoint(acc);
    }
    return 0;
}