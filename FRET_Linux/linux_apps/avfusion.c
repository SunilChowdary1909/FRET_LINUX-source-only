/* avfusion.c
 *
 *   ctrl  (90) main thread, this is what we measure. waits on radar.
 *   ota   (75) just preempts ctrl, no dependencies.
 *   radar (70) stage 3, waits on cam, sends to ctrl.
 *   cam   (60) stage 2, waits on diag, sends to radar.
 *   diag  (50) stage 1, sends to cam.
 */

#define _GNU_SOURCE
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

static void debug_sig_handler(int sig)
{
    (void)sig;
    write(2, "SIG\n", 4);
}

#define N_JOBS          3
#define PERIOD_NS       10000L

#define STAGE_LEN_BASE   64U
#define STAGE_LEN_SCALE  2U
#define STAGE_LEN_MAX    384U

/* how many times each stage repeats compute_nonlinear, to get to the same
 * ms-scale delays chain_mtx gets from its busy_burn loop. fuzzer-controlled. */
#define WORK_REP_BASE    2U
#define WORK_REP_SCALE   1U
#define WORK_REP_MAX     40U

#define PRIO_CTRL   90
#define PRIO_OTA    75
#define PRIO_RADAR  70
#define PRIO_CAM    60
#define PRIO_DIAG   50

/* ---- fuzzer interface (identical protocol to chain_mtx) ---------------- */
volatile char fuzz_input_buffer[1024];
volatile int  fuzz_data_ready = 1;

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

// message + queues 
typedef struct {
    unsigned long value;
    unsigned      len;      /* compute length for the receiving stage        */
    unsigned      rep;      /* how many times to repeat the heavy compute     */
    unsigned      go;       /* remaining gate bits: does the chain go deeper  */
    unsigned      seq;
} msg_t;

static mqd_t mq_trig_diag  = (mqd_t)-1;   /* main   -> diag  (tail trigger)  */
static mqd_t mq_diag_cam   = (mqd_t)-1;   /* diag   -> cam                   */
static mqd_t mq_cam_radar  = (mqd_t)-1;   /* cam    -> radar                 */
static mqd_t mq_radar_ctrl = (mqd_t)-1;   /* radar  -> ctrl (measured wait)  */
static mqd_t mq_trig_cam   = (mqd_t)-1;   /* main   -> cam   (shallow start) */
static mqd_t mq_trig_radar = (mqd_t)-1;   /* main   -> radar (shallow start) */
static mqd_t mq_trig_ota   = (mqd_t)-1;   /* main   -> ota                   */

static volatile unsigned global_counter = 0;

/* ---- heavy, data-dependent work (from chain_mtx) ----------------------- */
static unsigned long compute_nonlinear(const volatile char *buf, int len)
{
    unsigned long acc  = 0x9E3779B97F4A7C15UL;
    unsigned long acc2 = 0;
    int i, j, k;

    if (len < 3) len = 3;

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

static void set_rt_prio(int prio)
{
    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = prio;
    (void)sched_setscheduler(0, SCHED_FIFO, &sp);
}

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

static void mq_get(mqd_t q, msg_t *m)
{
    while (mq_receive(q, (char *)m, sizeof(*m), NULL) < 0) {
        if (errno == EINTR) continue;
        usleep(500);
    }
}

static void mq_put(mqd_t q, const msg_t *m)
{
    while (mq_send(q, (const char *)m, sizeof(*m), 0) < 0) {
        if (errno == EINTR) continue;
        usleep(500);
    }
}

static unsigned clamp_len(unsigned v)
{
    if (v < 3U) v = 3U;
    return (v > STAGE_LEN_MAX) ? STAGE_LEN_MAX : v;
}

/* repeat the compute `rep` times so we get ms-scale delays like chain_mtx */
static unsigned long heavy_work(unsigned off, unsigned len, unsigned rep)
{
    unsigned long v = 0;
    unsigned r;
    if (rep < 1U) rep = 1U;
    if (rep > WORK_REP_MAX) rep = WORK_REP_MAX;
    for (r = 0; r < rep; r++)
        v ^= compute_nonlinear(&fuzz_input_buffer[(off + r) & 0x3FFU], (int)clamp_len(len));
    return v;
}

/* gate bits in msg.go decide which stages actually depend on each other:
 *   bit0: cam waits on diag
 *   bit1: radar waits on cam
 * diag/cam/radar always run either way, the bits just decide if ctrl ends
 * up waiting on the deeper stages too. */

/* ---- diag (prio 50): tail. always computes, forwards to cam. ----------- */
static void *diag_fn(void *arg)
{
    (void)arg;
    msg_t in, out;
    set_rt_prio(PRIO_DIAG);

    while (1) {
        mq_get(mq_trig_diag, &in);
        out.value = heavy_work(16, in.len, in.rep);
        out.len   = in.len;
        out.rep   = in.rep;
        out.go    = in.go;
        out.seq   = in.seq;
        mq_put(mq_diag_cam, &out);
    }
    return NULL;
}

/* ---- cam (prio 60): stage 2, waits on diag if gate bit0 is set ---------- */
static void *cam_fn(void *arg)
{
    (void)arg;
    msg_t in, out;
    set_rt_prio(PRIO_CAM);

    while (1) {
        mq_get(mq_trig_cam, &in);
        if (in.go & 0x1u) {
            msg_t d;
            mq_get(mq_diag_cam, &d);        /* pull diag's result if bit0 set */
            in.value ^= d.value;
        }
        out.value = in.value ^ heavy_work(32, in.len, in.rep);
        out.len   = in.len;
        out.rep   = in.rep;
        out.go    = in.go;
        out.seq   = in.seq;
        mq_put(mq_cam_radar, &out);
    }
    return NULL;
}

/* ---- radar (prio 70): stage 3, waits on cam if gate bit1 is set --------- */
static void *radar_fn(void *arg)
{
    (void)arg;
    msg_t in, out;
    set_rt_prio(PRIO_RADAR);

    while (1) {
        mq_get(mq_trig_radar, &in);
        if (in.go & 0x2u) {
            msg_t c;
            mq_get(mq_cam_radar, &c);       /* pull cam's result if bit1 set */
            in.value ^= c.value;
        }
        out.value = in.value ^ heavy_work(48, in.len, in.rep);
        out.len   = in.len;
        out.rep   = in.rep;
        out.go    = in.go;
        out.seq   = in.seq;
        mq_put(mq_radar_ctrl, &out);
    }
    return NULL;
}

/* ---- ota (prio 75): pure preemptor. fires into the measured window. ----- */
static void *ota_fn(void *arg)
{
    (void)arg;
    msg_t in;
    set_rt_prio(PRIO_OTA);

    while (1) {
        mq_get(mq_trig_ota, &in);
        (void)heavy_work(64, in.len, in.rep);
        global_counter++;
    }
    return NULL;
}

/* ---- per-job input decode ---------------------------------------------- */
/* each job is 16 bytes, idx = i*16:
 *   +0 flags: bit0 cam<-diag, bit1 radar<-cam, bit2 ota fires, bit3 order-enable
 *   +1 order: has to be 0 too for the deep path to happen
 *   +2..+5   len bytes for diag/cam/radar/ota
 */
static unsigned job_flags, job_order;
static unsigned diag_len, cam_len, radar_len, ota_len;
static unsigned diag_rep, cam_rep, radar_rep, ota_rep;
static unsigned gate_bits, ota_fire, order_ok;

static void decode_job_input(unsigned idx)
{
    job_flags = (unsigned char)fuzz_input_buffer[idx & 0x3FFU];
    job_order = (unsigned char)fuzz_input_buffer[(idx + 1u) & 0x3FFU];

    gate_bits = (job_flags & 0x03u);            /* bit0 cam<-diag, bit1 radar<-cam */
    ota_fire  = (job_flags & 0x04u) != 0;
    order_ok  = (job_flags & 0x08u) != 0 && ((job_order & 0x03u) == 0x00u);

    diag_len  = STAGE_LEN_BASE + (unsigned char)fuzz_input_buffer[(idx + 2u) & 0x3FFU] * STAGE_LEN_SCALE;
    cam_len   = STAGE_LEN_BASE + (unsigned char)fuzz_input_buffer[(idx + 3u) & 0x3FFU] * STAGE_LEN_SCALE;
    radar_len = STAGE_LEN_BASE + (unsigned char)fuzz_input_buffer[(idx + 4u) & 0x3FFU] * STAGE_LEN_SCALE;
    ota_len   = STAGE_LEN_BASE + (unsigned char)fuzz_input_buffer[(idx + 5u) & 0x3FFU] * STAGE_LEN_SCALE;

    diag_rep  = WORK_REP_BASE + (unsigned char)fuzz_input_buffer[(idx + 6u) & 0x3FFU] * WORK_REP_SCALE;
    cam_rep   = WORK_REP_BASE + (unsigned char)fuzz_input_buffer[(idx + 7u) & 0x3FFU] * WORK_REP_SCALE;
    radar_rep = WORK_REP_BASE + (unsigned char)fuzz_input_buffer[(idx + 8u) & 0x3FFU] * WORK_REP_SCALE;
    ota_rep   = WORK_REP_BASE + (unsigned char)fuzz_input_buffer[(idx + 9u) & 0x3FFU] * WORK_REP_SCALE;

#ifdef AVFUSION_ORACLE
    /* force full depth-3: both gate bits set, order ok, ota fires, max lengths */
    job_flags = 0x0F;
    job_order  = 0x00;
    gate_bits = 0x03;
    ota_fire  = 1;
    order_ok  = 1;
    diag_len  = STAGE_LEN_MAX;
    cam_len   = STAGE_LEN_MAX;
    radar_len = STAGE_LEN_MAX;
    ota_len   = STAGE_LEN_MAX;
    diag_rep  = WORK_REP_MAX;
    cam_rep   = WORK_REP_MAX;
    radar_rep = WORK_REP_MAX;
    ota_rep   = WORK_REP_MAX;
#endif
}

/* ---- main (ctrl, prio 90, measured) ------------------------------------ */
int main(void)
{
    pthread_t t_radar, t_cam, t_diag, t_ota;
    pthread_attr_t attr;
    struct sched_param param;
    struct timespec wake;
    unsigned long acc = 0;
    int i, s;
    unsigned seq = 0;

    for (s = 1; s < 32; s++) {
        if (s != SIGKILL && s != SIGSTOP)
            signal(s, debug_sig_handler);
    }

    mq_trig_diag  = mk_queue("/avf_trig_diag");
    mq_diag_cam   = mk_queue("/avf_diag_cam");
    mq_cam_radar  = mk_queue("/avf_cam_radar");
    mq_radar_ctrl = mk_queue("/avf_radar_ctrl");
    mq_trig_cam   = mk_queue("/avf_trig_cam");
    mq_trig_radar = mk_queue("/avf_trig_radar");
    mq_trig_ota   = mk_queue("/avf_trig_ota");

    param.sched_priority = PRIO_CTRL;
    sched_setscheduler(0, SCHED_FIFO, &param);

    pthread_attr_init(&attr);
    pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
    pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);

    param.sched_priority = PRIO_DIAG;
    pthread_attr_setschedparam(&attr, &param);
    pthread_create(&t_diag, &attr, diag_fn, NULL);

    param.sched_priority = PRIO_CAM;
    pthread_attr_setschedparam(&attr, &param);
    pthread_create(&t_cam, &attr, cam_fn, NULL);

    param.sched_priority = PRIO_RADAR;
    pthread_attr_setschedparam(&attr, &param);
    pthread_create(&t_radar, &attr, radar_fn, NULL);

    param.sched_priority = PRIO_OTA;
    pthread_attr_setschedparam(&attr, &param);
    pthread_create(&t_ota, &attr, ota_fn, NULL);

    pthread_attr_destroy(&attr);

    write(2, "ENTERED: main loop\n", 19);

    while (1) {
        while (fuzz_data_ready == 0) {
            usleep(10000);
        }
        fuzz_data_ready = 0;
        fuzz_snapshot_point();

        for (i = 0; i < N_JOBS; i++) {
            unsigned idx = (unsigned)(i * 16) & 0x3FFU;
            msg_t start, result;
            unsigned depth_go;

            decode_job_input(idx);
            seq++;

            /* periodic release, ctrl becomes runnable here, same as chain_mtx */
            clock_gettime(CLOCK_MONOTONIC, &wake);
            wake.tv_nsec += PERIOD_NS;
            if (wake.tv_nsec >= 1000000000L) { wake.tv_nsec -= 1000000000L; wake.tv_sec++; }
            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &wake, NULL);
            /* ---- measured window opens ---- */

            /* need both gate bits AND order_ok for the deep path */
            depth_go = order_ok ? gate_bits : 0u;

            if (ota_fire)
                { start.value = 0; start.len = ota_len; start.rep = ota_rep; start.go = 0; start.seq = seq;
                  mq_put(mq_trig_ota, &start); }

            if (depth_go & 0x1u) {
                /* deep: diag -> cam -> radar -> ctrl */
                start.value = 0; start.len = diag_len; start.rep = diag_rep; start.go = depth_go; start.seq = seq;
                mq_put(mq_trig_diag, &start);
                /* go already has bit0 set so cam knows to wait on diag */
                start.len = cam_len; start.rep = cam_rep;
                mq_put(mq_trig_cam, &start);
                start.len = radar_len; start.rep = radar_rep; start.go = depth_go;
                mq_put(mq_trig_radar, &start);
            } else {
                /* shallow: radar computes directly, no dependency on cam/diag */
                start.value = 0; start.len = cam_len; start.rep = cam_rep; start.go = 0; start.seq = seq;
                mq_put(mq_trig_cam, &start);
                start.len = radar_len; start.rep = radar_rep; start.go = 0;
                mq_put(mq_trig_radar, &start);
            }

            /* ctrl waits on radar, then does its own heavy work scaled by
             * depth - that's what FRET actually measures as the WORT. shallow
             * chain = low WORT, full depth-3 = high WORT. */
            mq_get(mq_radar_ctrl, &result);
            acc ^= result.value;

            {
                unsigned depth = 1u;          /* radar always runs */
                if (depth_go & 0x2u) depth++; /* cam fed radar */
                if (depth_go & 0x1u) depth++; /* diag fed cam */
                unsigned ctrl_rep = radar_rep * depth;
                acc ^= heavy_work(0, radar_len, ctrl_rep);
            }
            /* ---- measured window closes ---- */
        }

        fuzz_checkpoint(acc);
    }

    return 0;
}