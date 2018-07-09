/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

#ifndef __CDIPC_H__
#define __CDIPC_H__

#define CDIPC_MAGIC_NUM 0xcdcd0001


typedef enum {
    CDIPC_TOPIC = 0,
    CDIPC_SERVICE
} cdipc_type_t;

typedef enum {
    CDIPC_PUB = 0,
    CDIPC_SUB
} cdipc_role_t;


typedef struct {
    rlist_node_t    node;
    int             id;
    uint64_t        sub_ref;    // reference map
                                // TODO: add support for more than 64 bits
    int             pub_id;
    int             pub_id_bk;  // for logging
    bool            abort;
    size_t          len;
    size_t          ret_len;    // service only, ret data after origin data
    uint8_t         dat[];
} cdipc_nd_t;

typedef struct {
    rlist_node_t    node;
    cdipc_nd_t      *r_nd;
} cdipc_wp_t;                   // wrapper

typedef struct {
    int             id;
} cdipc_pub_t;                  // TODO: add process pid, also for sub_t

typedef struct {
    int             id;
    int             max_len;
    bool            need_wait;
    rlist_head_t    pend_head;
} cdipc_sub_t;

typedef struct {
    uint32_t        magic;
    cdipc_type_t    type;

    int             max_pub;
    int             max_sub;
    int             max_nd;
    size_t          max_len;

    pthread_mutex_t mutex;
    pthread_cond_t  cond;

    rlist_head_t    free_wp;
    rlist_head_t    free;
} cdipc_hdr_t;



typedef struct {
    int             fd;
    char            name[NAME_MAX];
    cdipc_hdr_t     *hdr;
    size_t          map_len;

    cdipc_pub_t     *pubs;  // beginning of pubs
    cdipc_sub_t     *subs;  // beginning of subs

    cdipc_role_t    role;
    cdipc_pub_t     *pub;   // owner self if owner is pub
    cdipc_sub_t     *sub;   // owner self if owner is sub
} cdipc_ch_t;



static cdipc_nd_t *cd_nd2r(const void *base, cdipc_nd_t *nd)
{
    if (nd == NULL)
        return NULL;
    return (void *)nd - (ptrdiff_t)base;
}
static cdipc_nd_t *cd_r2nd(const void *base, cdipc_nd_t *nd)
{
    if (nd == NULL)
        return NULL;
    return (void *)nd + (ptrdiff_t)base;
}
static cdipc_wp_t *cd_wp2r(const void *base, cdipc_wp_t *wp)
{
    if (wp == NULL)
        return NULL;
    return (void *)wp - (ptrdiff_t)base;
}
static cdipc_wp_t *cd_r2wp(const void *base, cdipc_wp_t *wp)
{
    if (wp == NULL)
        return NULL;
    return (void *)wp + (ptrdiff_t)base;
}

int cdipc_create(const char *name, cdipc_type_t type,
        int max_pub, int max_sub, int max_nd, size_t max_len);
int cdipc_unlink(const char *name);
int cdipc_open(cdipc_ch_t *ch, const char *name, cdipc_role_t role, int id);
int cdipc_close(cdipc_ch_t *ch);

cdipc_nd_t *cdipc_pub_alloc(cdipc_ch_t *ch, const struct timespec *abstime);
int cdipc_pub_put(cdipc_ch_t *ch, cdipc_nd_t *nd,
        const struct timespec *abstime);
int cdipc_pub_wait(cdipc_ch_t *ch, cdipc_nd_t *nd,
        const struct timespec *abstime);
int cdipc_pub_free(cdipc_ch_t *ch, cdipc_nd_t *nd);
cdipc_nd_t *cdipc_sub_get(cdipc_ch_t *ch, const struct timespec *abstime);
int cdipc_sub_ret(cdipc_ch_t *ch, cdipc_nd_t *nd);
int cdipc_sub_free(cdipc_ch_t *ch, cdipc_nd_t *nd);

#endif
