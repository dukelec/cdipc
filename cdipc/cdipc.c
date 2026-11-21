/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <d@d-l.io>
 */

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include "utils/cd_utils.h"
#include "utils/cd_debug.h"
#include "cdipc.h"

// 8 instead of sizeof(void *): keep uint64_t aligned on 32-bit targets
#define CDIPC_ALIGN(x)  (((x) + 7) & ~(size_t)7)


// set area pointers, return total size
static size_t cdipc_cal_addr(cdipc_ch_t *ch)
{
    cdipc_hdr_t *hdr = ch->hdr;
    ch->pubs = (void *)hdr + CDIPC_ALIGN(sizeof(cdipc_hdr_t));
    ch->subs = (void *)ch->pubs + CDIPC_ALIGN(sizeof(cdipc_pub_t) * hdr->max_pub);
    ch->wps = (void *)ch->subs + CDIPC_ALIGN(sizeof(cdipc_sub_t) * hdr->max_sub);
    ch->nds = (void *)ch->wps + CDIPC_ALIGN(sizeof(cdipc_wp_t) * hdr->max_nd * hdr->max_sub);
    ch->nd_len = CDIPC_ALIGN(sizeof(cdipc_nd_t) + hdr->max_len + hdr->max_len_r);
    return (void *)ch->nds + ch->nd_len * hdr->max_nd - (void *)hdr;
}

// last lock holder died inside the lock, any update may be half done:
// pend lists are the truth for sub refs, node states for the free list
static void ch_repair(cdipc_ch_t *ch)
{
    int i, n;
    cdipc_hdr_t *hdr = ch->hdr;

    dnf_warn(ch->name, "lock holder died, repair\n");
    for (i = 0; i < hdr->max_sub; i++) {
        cdipc_sub_t *sub = ch->subs + i;
        cdipc_wp_t *wps = ch->wps + i * hdr->max_nd; // the only ones allowed in this list
        rlist_node_t *rnode = sub->pend_head.rfirst, *last = NULL;

        for (n = 0; rnode && n < hdr->max_nd; n++) {
            cdipc_wp_t *wp = rlist_entry((void *)rnode + (ptrdiff_t)hdr, cdipc_wp_t);
            size_t ofs = (void *)wp - (void *)wps;
            if (ofs % sizeof(cdipc_wp_t) || ofs / sizeof(cdipc_wp_t) >= (size_t)hdr->max_nd)
                break;
            cdipc_wp2nd(ch, wp)->sub_ref |= 1ULL << i;
            last = &wp->node;
            rnode = last->rnext;
        }
        sub->pend_head.len = n;
        sub->pend_head.rlast = last ? (void *)last - (ptrdiff_t)hdr : NULL;
        if (last)
            last->rnext = NULL;
        else
            sub->pend_head.rfirst = NULL;
        if (n)
            cd_cond_broadcast(&sub->cond);
    }

    memset(&hdr->free, 0, sizeof(rlist_head_t));
    for (i = 0; i < hdr->max_nd; i++) {
        cdipc_nd_t *nd = (void *)ch->nds + ch->nd_len * i;
        if (!nd->sub_ref && nd->pub_id < 0)
            rlist_put(hdr, &hdr->free, &nd->node);
    }
    cd_cond_broadcast(&hdr->cond);
}

static int ch_lock(cdipc_ch_t *ch)
{
    cdipc_hdr_t *hdr = ch->hdr;
    int r = cd_mutex_lock(&hdr->mutex, NULL);

    if (r && r != EOWNERDEAD) {
        dnf_error(ch->name, "mutex_lock: %d\n", r);
        return r;
    }
    if (hdr->busy)
        ch_repair(ch);
    hdr->busy = true;
    return 0;
}

static void ch_unlock(cdipc_ch_t *ch)
{
    ch->hdr->busy = false;
    cd_mutex_unlock(&ch->hdr->mutex);
}

static int ch_wait(cdipc_ch_t *ch, cd_cond_t *c, const struct timespec *abstime)
{
    cdipc_hdr_t *hdr = ch->hdr;
    int r;

    hdr->busy = false;
    r = cd_cond_wait(c, &hdr->mutex, abstime);
    if (hdr->busy)
        ch_repair(ch);
    hdr->busy = true;
    if (r && r != ETIMEDOUT)
        dnf_error(ch->name, "cond_wait: %d\n", r);
    return r;
}

// the only way back to free list, besides ch_repair
static void nd_check_free(cdipc_hdr_t *hdr, cdipc_nd_t *nd)
{
    if (!nd->sub_ref && nd->pub_id < 0) {
        rlist_put(hdr, &hdr->free, &nd->node);
        cd_cond_broadcast(&hdr->cond);
    }
}

static void nd_pub_release(cdipc_hdr_t *hdr, cdipc_nd_t *nd)
{
    if (hdr->type == CDIPC_SERVICE && (nd->sub_ref & 1))
        nd->abort = true; // not replied yet, cancel it
    nd->pub_id = -1;
    nd_check_free(hdr, nd);
}

static void nd_sub_release(cdipc_hdr_t *hdr, cdipc_nd_t *nd, int sub_id)
{
    nd->sub_ref &= ~(1ULL << sub_id);
    if (hdr->type == CDIPC_SERVICE && sub_id == 0)
        cd_cond_broadcast(&hdr->cond); // requester waits for bit 0
    nd_check_free(hdr, nd);
}


int cdipc_create(const char *name, cdipc_type_t type, int max_pub, int max_sub,
        int max_nd, size_t max_len, size_t max_len_r)
{
    int i, r;
    cdipc_hdr_t hdr_tmp = {0};
    cdipc_ch_t _ch = {0};
    cdipc_ch_t *ch = &_ch;

    // max_sub is limited by the 64-bit sub_ref
    if (max_pub <= 0 || max_sub <= 0 || max_sub > 64 || max_nd <= 0 || !max_len ||
            (type == CDIPC_SERVICE && !max_len_r)) {
        dnf_error(name, "invalid arguments\n");
        return -1;
    }

    hdr_tmp.type = type;
    hdr_tmp.max_pub = max_pub;
    hdr_tmp.max_sub = max_sub;
    hdr_tmp.max_nd = max_nd;
    hdr_tmp.max_len = CDIPC_ALIGN(max_len);
    hdr_tmp.max_len_r = type == CDIPC_SERVICE ? CDIPC_ALIGN(max_len_r) : 0;
    ch->hdr = &hdr_tmp;
    ch->map_len = cdipc_cal_addr(ch); // only for map_len
    snprintf(ch->name, sizeof(ch->name), "%s", name);

    ch->fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG);
    if (ch->fd < 0) {
        dnf_error(ch->name, "shm_open: %s\n", strerror(errno));
        return ch->fd;
    }

    if (ftruncate(ch->fd, ch->map_len) == -1) {
        dnf_error(ch->name, "ftruncate to size %zu: %s\n", ch->map_len, strerror(errno));
        goto exit_free_fd;
    }

    ch->hdr = (cdipc_hdr_t*) mmap(NULL, ch->map_len,
            PROT_READ | PROT_WRITE, MAP_SHARED, ch->fd, 0);
    if (ch->hdr == MAP_FAILED) {
        dnf_error(ch->name, "mmap: %s\n", strerror(errno));
        goto exit_free_fd;
    }
    memcpy(ch->hdr, &hdr_tmp, sizeof(cdipc_hdr_t));
    cdipc_cal_addr(ch); // re-cal for pointers

    if ((r = cd_mutex_init(&ch->hdr->mutex, NULL))) {
        dnf_error(ch->name, "cd_mutex_init, ret: %d\n", r);
        goto exit_free_mmap;
    }

    if ((r = cd_cond_init(&ch->hdr->cond, NULL))) {
        dnf_error(ch->name, "cd_cond_init\n");
        goto exit_free_mmap;
    }

    for (i = 0; i < max_pub; i++) {
        cdipc_pub_t *pub = ch->pubs + i;
        memset(pub, 0, sizeof(cdipc_pub_t));
        pub->id = i;
    }
    for (i = 0; i < max_sub; i++) {
        cdipc_sub_t *sub = ch->subs + i;
        memset(sub, 0, sizeof(cdipc_sub_t));
        sub->id = i;
        cd_cond_init(&sub->cond, NULL);
    }
    for (i = 0; i < max_nd; i++) {
        cdipc_nd_t *nd = (void *)ch->nds + ch->nd_len * i;
        memset(nd, 0, sizeof(cdipc_nd_t));
        nd->id = i;
        nd->pub_id = -1;
        nd->pub_id_bk = -1;
        rlist_put(ch->hdr, &ch->hdr->free, &nd->node);
    }

    // set magic last, cdipc_open reads it with acquire
    __atomic_store_n(&ch->hdr->magic, CDIPC_MAGIC_NUM, __ATOMIC_RELEASE);
    return cdipc_close(ch);

exit_free_mmap:
    munmap(ch->hdr, ch->map_len);
exit_free_fd:
    close(ch->fd);
    cdipc_unlink(name);
    return -1;
}

int cdipc_unlink(const char *name)
{
    int r;

    if ((r = shm_unlink(name))) {
        dnf_error(name, "shm_unlink: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}


// normally: -1 for auto detect, 0 for reset to zero
static void cdipc_set_tid(cdipc_ch_t *ch, int tid)
{
    if (tid == -1)
        tid = syscall(SYS_gettid);

    if (ch->role == CDIPC_PUB && ch->pub)
        ch->pub->tid = tid;
    else if (ch->role == CDIPC_SUB && ch->sub)
        ch->sub->tid = tid;
}

int cdipc_open(cdipc_ch_t *ch, const char *name,
        cdipc_role_t role, int id)
{
    struct stat st;
    cdipc_hdr_t *hdr;

    memset(ch, 0, sizeof(cdipc_ch_t));
    snprintf(ch->name, sizeof(ch->name), "%s", name);

    ch->fd = shm_open(name, O_RDWR, S_IRWXU | S_IRWXG);
    if (ch->fd < 0) {
        dnf_error(ch->name, "shm_open: %s\n", strerror(errno));
        return ch->fd;
    }

    // size stays 0 until the creator's ftruncate, touching it would SIGBUS
    if (fstat(ch->fd, &st) || st.st_size < (off_t)sizeof(cdipc_hdr_t)) {
        dnf_error(ch->name, "not initialized\n");
        goto exit_close;
    }
    ch->map_len = st.st_size;
    hdr = ch->hdr = (cdipc_hdr_t*) mmap(NULL, ch->map_len,
            PROT_READ | PROT_WRITE, MAP_SHARED, ch->fd, 0);
    if (hdr == MAP_FAILED) {
        dnf_error(ch->name, "mmap: %s\n", strerror(errno));
        ch->hdr = NULL;
        goto exit_close;
    }
    if (__atomic_load_n(&hdr->magic, __ATOMIC_ACQUIRE) != CDIPC_MAGIC_NUM) {
        dnf_error(ch->name, "wrong magic num: %08x, expect: %08x\n",
                hdr->magic, CDIPC_MAGIC_NUM);
        goto exit_unmap;
    }
    if (cdipc_cal_addr(ch) > ch->map_len) {
        dnf_error(ch->name, "size mismatch\n");
        goto exit_unmap;
    }

    ch->role = role;
    if (role == CDIPC_PUB || role == CDIPC_SUB) {
        int max = role == CDIPC_PUB ? hdr->max_pub : hdr->max_sub;
        if (id < 0 || id >= max) {
            dnf_error(ch->name, "id %d out of range, max: %d\n", id, max);
            goto exit_unmap;
        }
        if (role == CDIPC_PUB)
            ch->pub = ch->pubs + id;
        else
            ch->sub = ch->subs + id;
        cdipc_set_tid(ch, -1);
    } else {
        dnf_debug(ch->name, "neither sub nor pub\n");
    }
    return 0;

exit_unmap:
    munmap(ch->hdr, ch->map_len);
    ch->hdr = NULL;
exit_close:
    close(ch->fd);
    ch->fd = -1;
    return -1;
}

int cdipc_recover(cdipc_ch_t *ch)
{
    int n = 0;
    int i;
    cdipc_hdr_t *hdr = ch->hdr;

    if (ch_lock(ch))
        return -1;

    if (ch->role == CDIPC_SUB) {
        cdipc_sub_t *sub = ch->sub;
        for (i = 0; i < hdr->max_nd; i++) {
            cdipc_nd_t *nd = (void *)ch->nds + ch->nd_len * i;
            if (nd->sub_ref & (1ULL << sub->id)) {
                bool found = false;
                rlist_node_t *rnode, *node;
                for (rnode = sub->pend_head.rfirst; rnode != NULL; rnode = node->rnext) {
                    node = (void *)rnode + (ptrdiff_t)hdr;
                    if (cdipc_wp2nd(ch, rlist_entry(node, cdipc_wp_t)) == nd) {
                        found = true;
                        break;
                    }
                }
                if (found)
                    continue;
                n++;
                if (hdr->type == CDIPC_SERVICE && sub->id == 0) {
                    nd->len_r = 0; // replier died before reply
                    nd->abort = true;
                }
                nd_sub_release(hdr, nd, sub->id);
            }
        }
    } else if (ch->role == CDIPC_PUB) {
        cdipc_pub_t *pub = ch->pub;
        for (i = 0; i < hdr->max_nd; i++) {
            cdipc_nd_t *nd = (void *)ch->nds + ch->nd_len * i;
            if (nd->pub_id == pub->id) {
                n++;
                nd_pub_release(hdr, nd);
            }
        }
    }

    ch_unlock(ch);
    return n;
}

int cdipc_close(cdipc_ch_t *ch)
{
    cdipc_set_tid(ch, 0);

    if (munmap(ch->hdr, ch->map_len)) {
        dnf_error(ch->name, "munmap\n");
        return -1;
    }
    ch->hdr = NULL;

    if (close(ch->fd)) {
        dnf_error(ch->name, "close fd\n");
        return -1;
    }
    ch->fd = -1;
    return 0;
}


// for pub:

cdipc_nd_t *cdipc_pub_alloc(cdipc_ch_t *ch, const struct timespec *abstime)
{
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_pub_t *pub = ch->pub;
    cdipc_nd_t *nd = NULL;
    assert(ch->role == CDIPC_PUB);

    if (ch_lock(ch))
        return NULL;

    while (!(nd = rlist_get_entry(hdr, &hdr->free, cdipc_nd_t))) {
        if (ch_wait(ch, &hdr->cond, abstime))
            break;
    }
    if (nd) {
        nd->abort = false;
        nd->pub_id = pub->id;
        nd->pub_id_bk = pub->id;
        nd->sub_ref = 0;
        nd->len = 0;
        nd->len_r = 0;
    }
    ch_unlock(ch);
    return nd;
}

static bool pub_need_wait(cdipc_ch_t *ch)
{
    int i;
    for (i = 0; i < ch->hdr->max_sub; i++) {
        cdipc_sub_t *sub = ch->subs + i;
        if (sub->need_wait && sub->max_len && sub->pend_head.len >= sub->max_len)
            return true;
    }
    return false;
}

int cdipc_pub_put(cdipc_ch_t *ch, cdipc_nd_t *nd,
        const struct timespec *abstime)
{
    int i, r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    assert(ch->role == CDIPC_PUB);

    if (ch_lock(ch))
        return -1;

    if (nd->pub_id != ch->pub->id || nd->sub_ref) {
        dnf_error(ch->name, "node %d not owned or still in use\n", nd->id);
        r = -1;
        goto out;
    }

    while (pub_need_wait(ch)) {
        if ((r = ch_wait(ch, &hdr->cond, abstime)))
            goto out;
    }

    if (hdr->type == CDIPC_SERVICE && !ch->subs[0].max_len) {
        dnf_error(ch->name, "no replier, sub 0 max_len is 0\n");
        r = -1;
        goto out;
    }

    nd->abort = false;
    nd->len_r = 0;
    for (i = 0; i < hdr->max_sub; i++) {
        cdipc_sub_t *sub = ch->subs + i;
        if (!sub->max_len)
            continue;

        while (sub->pend_head.len >= sub->max_len) { // drop the oldest
            cdipc_nd_t *old = cdipc_wp2nd(ch, rlist_entry(
                    (void *)sub->pend_head.rfirst + (ptrdiff_t)hdr, cdipc_wp_t));
            if (hdr->type == CDIPC_SERVICE && i == 0)
                old->abort = true; // request dropped before reply
            nd_sub_release(hdr, old, i);
            rlist_get(hdr, &sub->pend_head);
        }
        // unref before unlink above, link before ref here:
        // if we die in between, ch_repair gets the ref back from the pend list
        rlist_put(hdr, &sub->pend_head, &ch->wps[i * hdr->max_nd + nd->id].node);
        nd->sub_ref |= 1ULL << i;
        cd_cond_broadcast(&sub->cond);
    }
    if (hdr->type == CDIPC_TOPIC)
        nd_pub_release(hdr, nd); // freed at once if no sub takes it

out:
    ch_unlock(ch);
    return r;
}

int cdipc_pub_wait(cdipc_ch_t *ch, cdipc_nd_t *nd,
        const struct timespec *abstime)
{
    int r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    assert(ch->role == CDIPC_PUB);

    if (ch_lock(ch))
        return -1;

    while (!r && (nd->sub_ref & 1))
        r = ch_wait(ch, &hdr->cond, abstime);
    if (!r && nd->abort)
        r = ECANCELED;

    ch_unlock(ch);
    return r;
}

int cdipc_pub_free(cdipc_ch_t *ch, cdipc_nd_t *nd)
{
    int r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    assert(ch->role == CDIPC_PUB);

    if (ch_lock(ch))
        return -1;

    if (nd->pub_id == ch->pub->id) {
        nd_pub_release(hdr, nd);
    } else {
        dnf_error(ch->name, "node %d not owned\n", nd->id);
        r = -1;
    }

    ch_unlock(ch);
    return r;
}

// for sub:

cdipc_nd_t *cdipc_sub_get(cdipc_ch_t *ch, const struct timespec *abstime)
{
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_sub_t *sub = ch->sub;
    cdipc_wp_t *wp;
    cdipc_nd_t *nd = NULL;
    assert(ch->role == CDIPC_SUB);

    if (ch_lock(ch))
        return NULL;

    while (!nd) {
        if (!(wp = rlist_get_entry(hdr, &sub->pend_head, cdipc_wp_t))) {
            if (ch_wait(ch, &sub->cond, abstime))
                break;
            continue;
        }
        nd = cdipc_wp2nd(ch, wp);
        if (sub->need_wait)
            cd_cond_broadcast(&hdr->cond); // pend room for blocked pubs

        if (nd->abort) {
            df_debug("avoid abort node\n");
            nd_sub_release(hdr, nd, sub->id);
            nd = NULL;
        }
    }

    ch_unlock(ch);
    return nd;
}

int cdipc_sub_ret(cdipc_ch_t *ch, cdipc_nd_t *nd)
{
    assert(ch->role == CDIPC_SUB && ch->hdr->type == CDIPC_SERVICE);

    if (ch->sub->id != 0) {
        dnf_error(ch->name, "only allow sub id 0\n");
        return -1;
    }
    return cdipc_sub_free(ch, nd);
}

// also for service logging subs (id != 0)
int cdipc_sub_free(cdipc_ch_t *ch, cdipc_nd_t *nd)
{
    int r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_sub_t *sub = ch->sub;
    assert(ch->role == CDIPC_SUB);

    if (ch_lock(ch))
        return -1;

    if (nd->sub_ref & (1ULL << sub->id)) {
        nd_sub_release(hdr, nd, sub->id);
    } else {
        dnf_error(ch->name, "node %d not held\n", nd->id);
        r = -1;
    }

    ch_unlock(ch);
    return r;
}

int cdipc_sub_cfg(cdipc_ch_t *ch, int max_len, bool need_wait)
{
    cdipc_hdr_t *hdr = ch->hdr;
    assert(ch->role == CDIPC_SUB);

    if (max_len < 0)
        return -1;
    if (ch_lock(ch))
        return -1;

    ch->sub->max_len = max_len;
    ch->sub->need_wait = need_wait;
    cd_cond_broadcast(&hdr->cond); // pubs blocked by need_wait re-check

    ch_unlock(ch);
    return 0;
}
