/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2026, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

// Multi-process stress: topic (3 pub, 6 sub) + service (4 requester, replier, logger).
// "kill" mode SIGKILLs random workers and respawns them (they cdipc_recover first).
#include <time.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <cdipc/cdipc.h>
#include <cdipc/utils/cd_utils.h>

#define T "cdipc_test_stress_t"
#define S "cdipc_test_stress_s"
enum { TP, TS, SR, SP, SL }; // topic pub/sub, service requester/replier/logger
static struct { int role, id; } W[] = {
    {TP, 0}, {TP, 1}, {TP, 2}, {TS, 0}, {TS, 1}, {TS, 2}, {TS, 3}, {TS, 4}, {TS, 5},
    {SR, 0}, {SR, 1}, {SR, 2}, {SR, 3}, {SP, 0}, {SL, 1},
};
#define NW (int)(sizeof(W) / sizeof(W[0]))
static volatile int *done; // shared with workers
static long *stat;         // [0] topic msgs, [1] replies, [2] cancelled

static struct timespec after_us(long us)
{
    struct timespec now, t;
    clock_gettime(CLOCK_MONOTONIC, &now);
    us2tv(tv2us(&now) + us, &t);
    return t;
}

static void worker(int w)
{
    cdipc_ch_t ch;
    struct timespec t;
    cdipc_nd_t *nd;
    int id = W[w].id, k = 0;
    const char *name = W[w].role <= TS ? T : S;
    cdipc_role_t role = (W[w].role == TP || W[w].role == SR) ? CDIPC_PUB : CDIPC_SUB;

    srand(getpid());
    setvbuf(stdout, NULL, _IONBF, 0); // workers die by SIGKILL/_exit
    if (cdipc_open(&ch, name, role, id))
        _exit(2);
    cdipc_recover(&ch);
    while (true) {
        switch (W[w].role) {
        case TP:
            if (*done)
                _exit(0);
            t = after_us(2000000);
            if (!(nd = cdipc_pub_alloc(&ch, &t)))
                break;
            nd->len = snprintf((char *)nd->dat, 64, "p%d-%d", id, k++);
            if (k % 7 == 0 || cdipc_pub_put(&ch, nd, &t))
                cdipc_pub_free(&ch, nd);
            else
                __sync_fetch_and_add(&stat[0], 1);
            break;
        case SR:
            if (*done)
                _exit(0);
            t = after_us(2000000);
            if (!(nd = cdipc_pub_alloc(&ch, &t)))
                break;
            nd->len = 8;
            if (!cdipc_pub_put(&ch, nd, &t)) {
                t = after_us(rand() % 3000); // short timeouts exercise cancel paths
                int r = cdipc_pub_wait(&ch, nd, &t);
                __sync_fetch_and_add(&stat[r ? 2 : 1], 1);
            }
            cdipc_pub_free(&ch, nd);
            break;
        case TS:
        case SL:
        case SP:
            t = after_us(200000);
            if (!(nd = cdipc_sub_get(&ch, &t))) {
                if (*done)
                    _exit(0);
                break;
            }
            if (W[w].role == SP) {
                if (rand() % 4 == 0)
                    usleep(rand() % 2000);
                memcpy(nd->dat + ch.hdr->max_len, "ok", 2);
                nd->len_r = 2;
                cdipc_sub_ret(&ch, nd);
            } else {
                cdipc_sub_free(&ch, nd);
            }
            break;
        }
    }
}

static int fails;
static void check(const char *name)
{
    cdipc_ch_t c;
    rlist_node_t *rnode, *node;
    int i, nfree = 0, held = 0;
    if (cdipc_open(&c, name, -1, -1)) { // e.g. header overwritten
        printf("  %s: open failed -> BAD\n", name);
        fails++;
        return;
    }
    cdipc_hdr_t *hdr = c.hdr;
    for (rnode = hdr->free.rfirst; rnode && nfree <= hdr->max_nd; rnode = node->rnext, nfree++)
        node = (void *)rnode + (ptrdiff_t)hdr;
    for (i = 0; i < hdr->max_nd; i++) {
        cdipc_nd_t *nd = (void *)c.nds + c.nd_len * i;
        if (nd->sub_ref || nd->pub_id >= 0) {
            held++;
            printf("  %s node %d still held: sub_ref %#" PRIx64 " pub_id %d abort %d\n",
                    name, nd->id, nd->sub_ref, nd->pub_id, nd->abort);
        }
    }
    int pend = 0;
    for (i = 0; i < hdr->max_sub; i++)
        pend += c.subs[i].pend_head.len;
    bool ok = nfree == hdr->max_nd && nfree == (int)hdr->free.len && !held && !pend &&
            !hdr->mutex && !hdr->busy;
    printf("  %s: free %d/%u of %d, pend %d, held %d, mutex %#x, busy %d -> %s\n", name,
            nfree, hdr->free.len, hdr->max_nd, pend, held, hdr->mutex, hdr->busy, ok ? "ok" : "BAD");
    fails += !ok;
    cdipc_close(&c);
}

static pid_t spawn(int w)
{
    pid_t pid = fork();
    if (pid == 0)
        worker(w);
    return pid;
}

int main(int argc, char **argv)
{
    bool kill_mode = argc > 1 && !strcmp(argv[1], "kill");
    int secs = argc > 2 ? atoi(argv[2]) : 3, kills = 0;
    pid_t pids[NW];
    void *shm = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    done = shm;
    stat = (long *)shm + 1;

    shm_unlink(T);
    shm_unlink(S);
    cdipc_create(T, CDIPC_TOPIC, 3, 6, 16, 64, 0);
    cdipc_create(S, CDIPC_SERVICE, 4, 2, 8, 64, 64);
    for (int i = 0; i < 6; i++) {
        cdipc_ch_t c;
        cdipc_open(&c, T, CDIPC_SUB, i);
        cdipc_sub_cfg(&c, i < 3 ? 4 : 2, i < 3); // 0-2 block pubs, 3-5 drop oldest
        cdipc_close(&c);
    }
    for (int i = 0; i < 2; i++) {
        cdipc_ch_t c;
        cdipc_open(&c, S, CDIPC_SUB, i);
        cdipc_sub_cfg(&c, i ? 2 : 4, false);
        cdipc_close(&c);
    }

    fflush(stdout);
    for (int w = 0; w < NW; w++)
        pids[w] = spawn(w);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        usleep(20000);
        if (kill_mode) {
            int w = rand() % NW;
            kill(pids[w], SIGKILL);
            waitpid(pids[w], NULL, 0);
            pids[w] = spawn(w);
            kills++;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while (t1.tv_sec - t0.tv_sec < secs);
    *done = 1;

    alarm(30); // hang guard
    for (int w = 0; w < NW; w++) {
        int st;
        waitpid(pids[w], &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st))
            printf("  worker %d exit status %#x\n", w, st);
    }
    printf("%s mode, %ds: topic msgs %ld, replies %ld, cancelled %ld, kills %d\n",
            kill_mode ? "kill" : "normal", secs, stat[0], stat[1], stat[2], kills);
    check(T);
    check(S);
    cdipc_unlink(T);
    cdipc_unlink(S);
    printf("%s\n", fails ? "FAIL" : "PASS");
    return !!fails;
}
