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

#include "cd_utils.h"

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
    list_node_t     node;
    int             id;
    int             ref;    // reference count
    int             owner;  // pub's id
    size_t          len;
    uint8_t         dat[];
} cdipc_nd_t;

typedef struct {
    int             id;
    cdipc_nd_t      *cur;
    cdipc_nd_t      *ans;
} cdipc_pub_t;

typedef struct {
    int             id;
    int             max_len;
    bool            need_wait;
    cdipc_nd_t      *cur;
    list_head_t     pend;
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

    list_head_t     free;
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


int cdipc_create(const char *name, cdipc_type_t type,
        int max_pub, int max_sub, int max_nd, size_t max_len);
int cdipc_unlink(const char *name);
int cdipc_open(cdipc_ch_t *ch, const char *name, cdipc_role_t role, int id);
int cdipc_close(cdipc_ch_t *ch);

#endif
