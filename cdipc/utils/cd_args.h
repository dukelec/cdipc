/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

#ifndef __CD_ARGS_H__
#define __CD_ARGS_H__

typedef struct {
    list_node_t node;
    const char  *key;
    const char  *val;
    bool        used;
} cd_args_entry_t;

typedef struct {
    list_head_t head;
} cd_args_t;


int cd_args_parse(cd_args_t *ca, int argc, char **argv);
int cd_args_free(cd_args_t *ca);

const char *cd_arg_get(cd_args_t *ca, const char *key);
const char *cd_arg_get2(cd_args_t *ca, const char *key1, const char *key2);
const char *cd_arg_get_left(cd_args_t *ca);

static inline const char *cd_arg_get_def(cd_args_t *ca,
        const char *key, const char *dft)
{
    const char *r = cd_arg_get(ca, key);
    return r ? r : dft;
}

static inline const char *cd_arg_get2_def(cd_args_t *ca,
        const char *key1, const char *key2, const char *dft)
{
    const char *r = cd_arg_get2(ca, key1, key2);
    return r ? r : dft;
}

#endif
