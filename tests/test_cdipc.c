/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2026, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <d@d-l.io>
 */

// Regression tests, every case ends with a shared memory invariant check.
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <inttypes.h>
#include <cdipc/cdipc.h>
#include <cdipc/utils/cd_utils.h>

static int fails;
#define EXPECT(c, ...) do { if (!(c)) { fails++; printf("  FAIL %s:%d: ", __func__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static struct timespec after_ms(int ms)
{
    struct timespec now, t;
    clock_gettime(CLOCK_MONOTONIC, &now);
    us2tv(tv2us(&now) + ms * 1000LL, &t);
    return t;
}

static long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

// lists consistent, no leak, no node both free and referenced
static void check(cdipc_ch_t *ch, const char *tag)
{
    cdipc_hdr_t *hdr = ch->hdr;
    rlist_node_t *rnode, *node;
    int i, nfree = 0, unref = 0;

    EXPECT(!hdr->busy && !hdr->mutex, "%s: busy %d, mutex %#x", tag, hdr->busy, hdr->mutex);
    for (rnode = hdr->free.rfirst; rnode; rnode = node->rnext) {
        node = (void *)rnode + (ptrdiff_t)hdr;
        cdipc_nd_t *nd = rlist_entry(node, cdipc_nd_t);
        EXPECT(!nd->sub_ref && nd->pub_id < 0, "%s: free node %d still referenced", tag, nd->id);
        if (++nfree > hdr->max_nd) { EXPECT(0, "%s: free list loops", tag); return; }
    }
    EXPECT(nfree == (int)hdr->free.len, "%s: free.len %u != %d", tag, hdr->free.len, nfree);
    for (i = 0; i < hdr->max_sub; i++) {
        cdipc_sub_t *sub = ch->subs + i;
        int n = 0;
        for (rnode = sub->pend_head.rfirst, node = NULL; rnode; rnode = node->rnext) {
            node = (void *)rnode + (ptrdiff_t)hdr;
            cdipc_wp_t *wp = rlist_entry(node, cdipc_wp_t);
            cdipc_nd_t *nd = cdipc_wp2nd(ch, wp);
            EXPECT((wp - ch->wps) / hdr->max_nd == i, "%s: sub %d pends a wrapper of another sub", tag, i);
            EXPECT(nd->sub_ref & (1ULL << i), "%s: sub %d pends node %d without ref bit", tag, i, nd->id);
            if (++n > hdr->max_nd) { EXPECT(0, "%s: pend list loops", tag); return; }
        }
        EXPECT(n == (int)sub->pend_head.len, "%s: sub %d pend.len %u != %d", tag, i, sub->pend_head.len, n);
        EXPECT(sub->pend_head.rlast == (node ? (void *)node - (ptrdiff_t)hdr : NULL), "%s: sub %d bad rlast", tag, i);
    }
    for (i = 0; i < hdr->max_nd; i++) {
        cdipc_nd_t *nd = (void *)ch->nds + ch->nd_len * i;
        unref += !nd->sub_ref && nd->pub_id < 0;
    }
    EXPECT(unref == nfree, "%s: %d unreferenced nodes but %d in free list (leak)", tag, unref, nfree);
}

static void mk(const char *n, cdipc_type_t t, int pubs, int subs, int nds)
{
    shm_unlink(n);
    if (cdipc_create(n, t, pubs, subs, nds, 64, t == CDIPC_SERVICE ? 64 : 0))
        printf("  create %s failed\n", n);
}

static void cfg(const char *n, int id, int max_len, bool wait)
{
    cdipc_ch_t c;
    cdipc_open(&c, n, CDIPC_SUB, id);
    cdipc_sub_cfg(&c, max_len, wait);
    cdipc_close(&c);
}

static void t1_service_no_replier(void)
{
    const char *N = "cdipc_test_1";
    cdipc_ch_t p;
    mk(N, CDIPC_SERVICE, 1, 1, 5);
    cdipc_open(&p, N, CDIPC_PUB, 0);
    for (int k = 0; k < 6; k++) {
        struct timespec t = after_ms(50);
        cdipc_nd_t *nd = cdipc_pub_alloc(&p, &t);
        EXPECT(cdipc_pub_put(&p, nd, &t) == -1, "put without replier should fail");
        EXPECT(cdipc_pub_free(&p, nd) == 0, "free");
    }
    EXPECT(p.hdr->free.len == 5, "free.len %u", p.hdr->free.len);
    cdipc_nd_t *held[6];
    int got = 0;
    for (int k = 0; k < 6; k++) {
        struct timespec t = after_ms(50);
        if ((held[k] = cdipc_pub_alloc(&p, &t)))
            got++;
        EXPECT(!held[k] || (void *)held[k] >= (void *)p.nds, "alloc returned header area");
    }
    EXPECT(got == 5, "allocated %d of 5", got);
    for (int k = 0; k < got; k++)
        cdipc_pub_free(&p, held[k]);
    check(&p, "t1");
    cdipc_close(&p);
    cdipc_unlink(N);
}

static void t2_sub_id_above_31(void)
{
    const char *N = "cdipc_test_2";
    cdipc_ch_t p, s;
    mk(N, CDIPC_TOPIC, 1, 64, 4);
    EXPECT(cdipc_create("cdipc_test_2x", CDIPC_TOPIC, 1, 65, 4, 64, 0) == -1, "max_sub 65 accepted");
    cfg(N, 33, 2, false);
    cfg(N, 63, 2, false);
    cdipc_open(&p, N, CDIPC_PUB, 0);
    struct timespec t = after_ms(50);
    cdipc_nd_t *nd = cdipc_pub_alloc(&p, &t);
    cdipc_pub_put(&p, nd, &t);
    EXPECT(nd->sub_ref == ((1ULL << 33) | (1ULL << 63)), "sub_ref %#" PRIx64, nd->sub_ref);
    cdipc_open(&s, N, CDIPC_SUB, 63);
    cdipc_sub_free(&s, cdipc_sub_get(&s, &t));
    EXPECT(nd->sub_ref == 1ULL << 33, "after sub 63 free: %#" PRIx64, nd->sub_ref);
    cdipc_close(&s);
    check(&p, "t2");
    cdipc_close(&p);
    cdipc_unlink(N);
}

static void t3_dead_owner(void)
{
    const char *N = "cdipc_test_3";
    cdipc_ch_t p;
    mk(N, CDIPC_TOPIC, 1, 1, 4);
    cfg(N, 0, 2, false);
    cdipc_open(&p, N, CDIPC_PUB, 0);
    pid_t pid = fork();
    if (pid == 0) {
        cdipc_ch_t c;
        cdipc_open(&c, N, CDIPC_PUB, 0);
        cd_mutex_lock(&c.hdr->mutex, NULL);
        _exit(0);
    }
    waitpid(pid, NULL, 0);
    int r = cd_mutex_lock(&p.hdr->mutex, NULL);
    EXPECT(r == EOWNERDEAD, "lock after owner died: %d", r);
    EXPECT(p.hdr->mutex == (int)syscall(SYS_gettid), "lock word %#x", p.hdr->mutex);
    cd_mutex_unlock(&p.hdr->mutex);
    EXPECT(p.hdr->mutex == 0, "unlock word %#x", p.hdr->mutex);
    EXPECT(cdipc_recover(&p) >= 0, "recover");
    struct timespec t = after_ms(50);
    cdipc_nd_t *nd = cdipc_pub_alloc(&p, &t);
    EXPECT(nd && cdipc_pub_put(&p, nd, &t) == 0, "put after takeover");
    check(&p, "t3");
    cdipc_close(&p);
    cdipc_unlink(N);
}

static void t4_fork_tid(void)
{
    const char *N = "cdipc_test_4";
    cdipc_ch_t p;
    int pfd[2];
    mk(N, CDIPC_TOPIC, 1, 1, 4);
    cdipc_open(&p, N, CDIPC_PUB, 0);
    cdipc_recover(&p); // caches tid in parent
    if (pipe(pfd)) return;
    pid_t pid = fork();
    if (pid == 0) {
        cd_mutex_lock(&p.hdr->mutex, NULL);
        int ok = p.hdr->mutex == (int)syscall(SYS_gettid);
        if (write(pfd[1], &ok, sizeof(ok)) < 0) _exit(1);
        usleep(200000);
        cd_mutex_unlock(&p.hdr->mutex);
        _exit(0);
    }
    int ok = 0;
    if (read(pfd[0], &ok, sizeof(ok)) < 0) ok = -1;
    EXPECT(ok == 1, "child lock word is not child tid");
    long t0 = now_ms();
    int r = cd_mutex_lock(&p.hdr->mutex, NULL);
    long dt = now_ms() - t0;
    EXPECT(r == 0 && dt >= 150, "parent lock: r=%d after %ld ms (should block ~200ms)", r, dt);
    cd_mutex_unlock(&p.hdr->mutex);
    waitpid(pid, NULL, 0);
    check(&p, "t4");
    cdipc_close(&p);
    cdipc_unlink(N);
}

static void t5_topic_recover_keeps_others(void)
{
    const char *N = "cdipc_test_5";
    cdipc_ch_t p, s0, s1;
    mk(N, CDIPC_TOPIC, 1, 2, 4);
    cfg(N, 0, 2, false);
    cfg(N, 1, 2, false);
    cdipc_open(&p, N, CDIPC_PUB, 0);
    cdipc_open(&s0, N, CDIPC_SUB, 0);
    cdipc_open(&s1, N, CDIPC_SUB, 1);
    struct timespec t = after_ms(50);
    cdipc_nd_t *nd = cdipc_pub_alloc(&p, &t);
    memcpy(nd->dat, "hello", 6);
    nd->len = 6;
    cdipc_pub_put(&p, nd, &t);
    cdipc_sub_get(&s0, &t); // taken, then "crash"
    EXPECT(cdipc_recover(&s0) == 1, "recover count");
    cdipc_nd_t *g = cdipc_sub_get(&s1, &t);
    EXPECT(g && !strcmp((char *)g->dat, "hello"), "sub1 lost the message");
    if (g)
        cdipc_sub_free(&s1, g);
    check(&p, "t5");
    cdipc_close(&p);
    cdipc_close(&s0);
    cdipc_close(&s1);
    cdipc_unlink(N);
}

static void t6_service_give_up(void)
{
    const char *N = "cdipc_test_6";
    cdipc_ch_t p, s;
    mk(N, CDIPC_SERVICE, 1, 1, 4);
    cfg(N, 0, 2, false);
    cdipc_open(&p, N, CDIPC_PUB, 0);
    cdipc_open(&s, N, CDIPC_SUB, 0);

    // a: replier already took it, requester gives up, replier replies later
    struct timespec t = after_ms(30);
    cdipc_nd_t *nd = cdipc_pub_alloc(&p, &t);
    cdipc_pub_put(&p, nd, &t);
    cdipc_nd_t *g = cdipc_sub_get(&s, &t);
    EXPECT(cdipc_pub_wait(&p, nd, &t) == ETIMEDOUT, "wait should time out");
    cdipc_pub_free(&p, nd);
    EXPECT(cdipc_sub_ret(&s, g) == 0, "late reply");
    EXPECT(p.hdr->free.len == 4, "a: leaked, free.len %u", p.hdr->free.len);

    // b: requester gives up before replier takes it: replier skips it
    t = after_ms(30);
    nd = cdipc_pub_alloc(&p, &t);
    cdipc_pub_put(&p, nd, &t);
    EXPECT(cdipc_pub_wait(&p, nd, &t) == ETIMEDOUT, "wait should time out");
    cdipc_pub_free(&p, nd);
    t = after_ms(30);
    EXPECT(cdipc_sub_get(&s, &t) == NULL, "cancelled request delivered");
    EXPECT(p.hdr->free.len == 4, "b: leaked, free.len %u", p.hdr->free.len);

    // c: normal round trip
    t = after_ms(100);
    nd = cdipc_pub_alloc(&p, &t);
    cdipc_pub_put(&p, nd, &t);
    g = cdipc_sub_get(&s, &t);
    memcpy(g->dat + p.hdr->max_len, "ok", 2);
    g->len_r = 2;
    cdipc_sub_ret(&s, g);
    EXPECT(cdipc_pub_wait(&p, nd, &t) == 0 && nd->len_r == 2, "round trip");
    cdipc_pub_free(&p, nd);
    check(&p, "t6");
    cdipc_close(&p);
    cdipc_close(&s);
    cdipc_unlink(N);
}

static void t7_service_logger(void)
{
    const char *N = "cdipc_test_7";
    cdipc_ch_t p, s0, s1;
    mk(N, CDIPC_SERVICE, 1, 2, 4);
    cfg(N, 0, 2, false);
    cfg(N, 1, 2, false);
    cdipc_open(&p, N, CDIPC_PUB, 0);
    cdipc_open(&s0, N, CDIPC_SUB, 0);
    cdipc_open(&s1, N, CDIPC_SUB, 1);
    struct timespec t = after_ms(100);
    cdipc_nd_t *nd = cdipc_pub_alloc(&p, &t);
    cdipc_pub_put(&p, nd, &t);
    cdipc_sub_ret(&s0, cdipc_sub_get(&s0, &t));
    EXPECT(cdipc_pub_wait(&p, nd, &t) == 0, "wait");
    cdipc_pub_free(&p, nd);
    cdipc_nd_t *g = cdipc_sub_get(&s1, &t);
    EXPECT(g && g->id == nd->id, "logger got the request");
    EXPECT(cdipc_sub_free(&s1, g) == 0, "logger release");
    EXPECT(p.hdr->free.len == 4, "free.len %u", p.hdr->free.len);
    check(&p, "t7");
    cdipc_close(&p);
    cdipc_close(&s0);
    cdipc_close(&s1);
    cdipc_unlink(N);
}

static void t8_bad_id(void)
{
    const char *N = "cdipc_test_8";
    cdipc_ch_t c;
    mk(N, CDIPC_TOPIC, 2, 2, 4);
    EXPECT(cdipc_open(&c, N, CDIPC_SUB, 2) == -1 && c.hdr == NULL && c.fd == -1, "sub id 2");
    EXPECT(cdipc_open(&c, N, CDIPC_PUB, -1) == -1, "pub id -1");
    EXPECT(cdipc_open(&c, N, CDIPC_SUB, 1) == 0, "sub id 1");
    check(&c, "t8");
    cdipc_close(&c);
    cdipc_unlink(N);
}

static cdipc_nd_t *t9_got;
static void *t9_waiter(void *arg)
{
    cdipc_ch_t *p = arg;
    struct timespec t = after_ms(2000);
    t9_got = cdipc_pub_alloc(p, &t);
    return NULL;
}

static void t9_cond_dead_waiter(void)
{
    const char *N = "cdipc_test_9";
    cdipc_ch_t p;
    pthread_t th;
    mk(N, CDIPC_TOPIC, 1, 1, 1);
    cdipc_open(&p, N, CDIPC_PUB, 0);
    struct timespec t = after_ms(50);
    cdipc_nd_t *nd = cdipc_pub_alloc(&p, &t); // the only node
    pid_t pid = fork();
    if (pid == 0)
        _exit(0);
    waitpid(pid, NULL, 0);
    p.hdr->cond.m = pid; // as if a woken waiter died holding it
    pthread_create(&th, NULL, t9_waiter, &p);
    usleep(100000);
    long t0 = now_ms();
    cdipc_pub_free(&p, nd); // wakes the waiter
    pthread_join(th, NULL);
    long dt = now_ms() - t0;
    EXPECT(t9_got && dt < 500, "waiter got=%p after %ld ms", (void *)t9_got, dt);
    if (t9_got)
        cdipc_pub_free(&p, t9_got);
    check(&p, "t9");
    cdipc_close(&p);
    cdipc_unlink(N);
}

static void t10_misuse_guards(void)
{
    const char *N = "cdipc_test_10";
    cdipc_ch_t p, s;
    mk(N, CDIPC_TOPIC, 1, 1, 4);
    cfg(N, 0, 2, false);
    cdipc_open(&p, N, CDIPC_PUB, 0);
    cdipc_open(&s, N, CDIPC_SUB, 0);
    struct timespec t = after_ms(50);
    cdipc_nd_t *nd = cdipc_pub_alloc(&p, &t);
    EXPECT(cdipc_pub_put(&p, nd, &t) == 0, "put");
    EXPECT(cdipc_pub_put(&p, nd, &t) == -1, "second put accepted");
    EXPECT(cdipc_pub_free(&p, nd) == -1, "free after put accepted");
    cdipc_nd_t *g = cdipc_sub_get(&s, &t);
    EXPECT(cdipc_sub_free(&s, g) == 0, "sub free");
    EXPECT(cdipc_sub_free(&s, g) == -1, "second sub free accepted");
    nd = cdipc_pub_alloc(&p, &t);
    EXPECT(cdipc_pub_free(&p, nd) == 0, "free unput topic node");
    EXPECT(cdipc_pub_free(&p, nd) == -1, "second pub free accepted");
    EXPECT(p.hdr->free.len == 4, "free.len %u", p.hdr->free.len);
    check(&p, "t10");
    cdipc_close(&p);
    cdipc_close(&s);
    cdipc_unlink(N);
}

static void t11_dropped_request(void)
{
    const char *N = "cdipc_test_11";
    cdipc_ch_t a, b;
    mk(N, CDIPC_SERVICE, 2, 1, 4);
    cfg(N, 0, 1, false);
    cdipc_open(&a, N, CDIPC_PUB, 0);
    cdipc_open(&b, N, CDIPC_PUB, 1);
    struct timespec t = after_ms(50);
    cdipc_nd_t *n1 = cdipc_pub_alloc(&a, &t);
    cdipc_pub_put(&a, n1, &t);
    cdipc_nd_t *n2 = cdipc_pub_alloc(&b, &t);
    cdipc_pub_put(&b, n2, &t); // replier queue full: drops n1
    EXPECT(cdipc_pub_wait(&a, n1, &t) == ECANCELED, "dropped request should be ECANCELED");
    cdipc_pub_free(&a, n1);
    cdipc_pub_free(&b, n2); // cancel the pending one
    cdipc_ch_t s;
    cdipc_open(&s, N, CDIPC_SUB, 0);
    t = after_ms(30);
    EXPECT(cdipc_sub_get(&s, &t) == NULL, "cancelled request delivered");
    EXPECT(a.hdr->free.len == 4, "free.len %u", a.hdr->free.len);
    check(&a, "t11");
    cdipc_close(&s);
    cdipc_close(&a);
    cdipc_close(&b);
    cdipc_unlink(N);
}

static int t12_r;
static void *t12_put(void *arg)
{
    cdipc_ch_t *p = arg;
    struct timespec t = after_ms(2000);
    cdipc_nd_t *nd = cdipc_pub_alloc(p, &t);
    t12_r = cdipc_pub_put(p, nd, &t);
    return NULL;
}

static void t12_sub_cfg_wakes_pub(void)
{
    const char *N = "cdipc_test_12";
    cdipc_ch_t p, s;
    pthread_t th;
    mk(N, CDIPC_TOPIC, 1, 1, 4);
    cfg(N, 0, 1, true);
    cdipc_open(&p, N, CDIPC_PUB, 0);
    cdipc_open(&s, N, CDIPC_SUB, 0);
    struct timespec t = after_ms(50);
    cdipc_pub_put(&p, cdipc_pub_alloc(&p, &t), &t); // queue full now
    t12_r = -2;
    pthread_create(&th, NULL, t12_put, &p);
    usleep(100000);
    EXPECT(t12_r == -2, "put did not block on need_wait");
    long t0 = now_ms();
    cdipc_sub_cfg(&s, 2, true);
    pthread_join(th, NULL);
    long dt = now_ms() - t0;
    EXPECT(t12_r == 0 && dt < 500, "put r=%d after %ld ms", t12_r, dt);
    EXPECT(s.sub->pend_head.len == 2, "pend %u", s.sub->pend_head.len);
    t = after_ms(50);
    cdipc_sub_free(&s, cdipc_sub_get(&s, &t));
    cdipc_sub_free(&s, cdipc_sub_get(&s, &t));
    check(&p, "t12");
    cdipc_close(&p);
    cdipc_close(&s);
    cdipc_unlink(N);
}

// fork a lock holder which leaves a half done update and dies inside the lock
static pid_t dying_holder(const char *N, void (*half_done)(cdipc_ch_t *))
{
    int pfd[2];
    char c;
    if (pipe(pfd))
        exit(1);
    pid_t pid = fork();
    if (pid == 0) {
        cdipc_ch_t ch;
        cdipc_open(&ch, N, -1, -1);
        cd_mutex_lock(&ch.hdr->mutex, NULL);
        ch.hdr->busy = true; // as ch_lock() of the library does
        half_done(&ch);
        if (write(pfd[1], "x", 1) < 0)
            _exit(1);
        usleep(150000);
        _exit(0);
    }
    if (read(pfd[0], &c, 1) < 0)
        exit(1);
    close(pfd[0]);
    close(pfd[1]);
    return pid; // still alive, holding the lock
}

static cdipc_nd_t *nd_by_id(cdipc_ch_t *ch, int id)
{
    return (void *)ch->nds + ch->nd_len * id;
}

// pub_alloc: node is off the free list, pub_id not set yet
static void half_alloc(cdipc_ch_t *ch)
{
    rlist_get(ch->hdr, &ch->hdr->free);
}

static void t13_holder_dies_in_lock(void)
{
    const char *N = "cdipc_test_13";
    cdipc_ch_t p;
    for (int queued = 0; queued < 2; queued++) {
        mk(N, CDIPC_TOPIC, 1, 1, 4);
        cdipc_open(&p, N, CDIPC_PUB, 0);
        pid_t pid = dying_holder(N, half_alloc);
        if (!queued)
            waitpid(pid, NULL, 0); // lock word keeps a dead tid: taken over by us
        struct timespec t = after_ms(2000);
        cdipc_nd_t *nd = cdipc_pub_alloc(&p, &t); // queued: blocks, kernel hands the lock over
        waitpid(pid, NULL, 0);
        EXPECT(nd && p.hdr->free.len == 3, "queued %d: nd %p, free.len %u", queued, (void *)nd, p.hdr->free.len);
        cdipc_pub_free(&p, nd);
        check(&p, queued ? "t13 handover" : "t13 takeover");
        cdipc_close(&p);
        cdipc_unlink(N);
    }
}

// pub_put of node 1: done for sub 0, linked without ref for sub 1; and a half pub_alloc
static void half_put(cdipc_ch_t *ch)
{
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_nd_t *nd = nd_by_id(ch, 1);
    rlist_put(hdr, &ch->subs[0].pend_head, &ch->wps[0 * hdr->max_nd + 1].node);
    nd->sub_ref |= 1;
    rlist_put(hdr, &ch->subs[1].pend_head, &ch->wps[1 * hdr->max_nd + 1].node);
    rlist_get(hdr, &hdr->free);
}

static void t14_half_put(void)
{
    const char *N = "cdipc_test_14";
    cdipc_ch_t p, s0, s1;
    mk(N, CDIPC_TOPIC, 1, 2, 4);
    cfg(N, 0, 2, false);
    cfg(N, 1, 2, false);
    cdipc_open(&p, N, CDIPC_PUB, 0);
    cdipc_open(&s0, N, CDIPC_SUB, 0);
    cdipc_open(&s1, N, CDIPC_SUB, 1);
    struct timespec t = after_ms(100);
    cdipc_nd_t *a = cdipc_pub_alloc(&p, &t);
    cdipc_pub_put(&p, a, &t);
    cdipc_nd_t *b = cdipc_pub_alloc(&p, &t); // the one "being put" by the dying holder
    EXPECT(a->id == 0 && b->id == 1, "node ids %d %d", a->id, b->id);
    waitpid(dying_holder(N, half_put), NULL, 0);

    for (int i = 0; i < 2; i++) {
        cdipc_ch_t *s = i ? &s1 : &s0;
        t = after_ms(100);
        cdipc_nd_t *g0 = cdipc_sub_get(s, &t), *g1 = cdipc_sub_get(s, &t);
        EXPECT(g0 && g1 && g0->id == 0 && g1->id == 1, "sub %d got %d %d", i, g0 ? g0->id : -1, g1 ? g1->id : -1);
        if (g0)
            cdipc_sub_free(s, g0);
        if (g1)
            EXPECT(cdipc_sub_free(s, g1) == 0, "sub %d free of repaired ref", i);
    }
    EXPECT(cdipc_recover(&p) == 1, "pub recover"); // node 1 was never released by its pub
    EXPECT(p.hdr->free.len == 4, "free.len %u", p.hdr->free.len);
    check(&p, "t14");
    cdipc_close(&p);
    cdipc_close(&s0);
    cdipc_close(&s1);
    cdipc_unlink(N);
}

// pub_put drops node 0: unreferenced and freed, not unlinked yet; then a half rlist_put
static void half_drop(cdipc_ch_t *ch)
{
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_nd_t *nd = nd_by_id(ch, 0);
    nd->sub_ref &= ~1ULL;
    rlist_put(hdr, &hdr->free, &nd->node);
    ch->subs[0].pend_head.len++;
}

static void t15_half_drop(void)
{
    const char *N = "cdipc_test_15";
    cdipc_ch_t p, s;
    mk(N, CDIPC_TOPIC, 1, 1, 4);
    cfg(N, 0, 2, false);
    cdipc_open(&p, N, CDIPC_PUB, 0);
    cdipc_open(&s, N, CDIPC_SUB, 0);
    struct timespec t = after_ms(100);
    cdipc_nd_t *a = cdipc_pub_alloc(&p, &t);
    memcpy(a->dat, "keep", 5);
    cdipc_pub_put(&p, a, &t);
    EXPECT(a->id == 0, "node id %d", a->id);
    waitpid(dying_holder(N, half_drop), NULL, 0);

    t = after_ms(100);
    cdipc_nd_t *n1 = cdipc_pub_alloc(&p, &t); // must not hand out the still pended node 0
    EXPECT(n1 && n1->id != 0, "alloc got node %d", n1 ? n1->id : -1);
    cdipc_nd_t *g = cdipc_sub_get(&s, &t);
    EXPECT(g && g->id == 0 && !strcmp((char *)g->dat, "keep"), "sub got %d", g ? g->id : -1);
    t = after_ms(30);
    EXPECT(cdipc_sub_get(&s, &t) == NULL, "phantom pend entry");
    if (g)
        cdipc_sub_free(&s, g);
    if (n1)
        cdipc_pub_free(&p, n1);
    EXPECT(p.hdr->free.len == 4, "free.len %u", p.hdr->free.len);
    check(&p, "t15");
    cdipc_close(&p);
    cdipc_close(&s);
    cdipc_unlink(N);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    void (*tests[])(void) = {
        t1_service_no_replier, t2_sub_id_above_31, t3_dead_owner, t4_fork_tid,
        t5_topic_recover_keeps_others, t6_service_give_up, t7_service_logger, t8_bad_id,
        t9_cond_dead_waiter, t10_misuse_guards, t11_dropped_request, t12_sub_cfg_wakes_pub,
        t13_holder_dies_in_lock, t14_half_put, t15_half_drop,
    };
    for (unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int f = fails;
        tests[i]();
        printf("t%-2u %s\n", i + 1, fails == f ? "ok" : "FAILED");
    }
    printf("%s: %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return !!fails;
}
