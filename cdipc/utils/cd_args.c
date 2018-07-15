/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

#include "cd_utils.h"
#include "cd_list.h"
#include "cd_args.h"


int cd_args_parse(cd_args_t *ca, int argc, char **argv)
{
    int i, r = 0;
    cd_args_entry_t *pre = NULL;
    list_head_init(&ca->head);

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            cd_args_entry_t *cur = calloc(1, sizeof(cd_args_entry_t));
            cur->key = argv[i];
            cur->val = "\0";
            list_put(&ca->head, &cur->node);
            pre = cur;
        } else {
            if (pre) {
                pre->val = argv[i];
                pre = NULL;
            } else {
                r = -1;
            }
        }
    }
    return r;
}

int cd_args_free(cd_args_t *ca)
{
    cd_args_entry_t *entry;
    while ((entry = list_get_entry(&ca->head, cd_args_entry_t)))
        free(entry);
}


const char *cd_arg_get(cd_args_t *ca, const char *key)
{
    list_node_t *pre, *pos;

    list_for_each(&ca->head, pre, pos){
        cd_args_entry_t *entry = list_entry(pos, cd_args_entry_t);
        if (key) {
            int r = strncmp(entry->key, key, strlen(key));
            if (r == 0) {
                if (strlen(entry->key) == strlen(key)) {
                    entry->used = true;
                    return entry->val;
                }
                if (strlen(entry->key) > strlen(key) &&
                        entry->key[strlen(key)] == '=') {
                    entry->used = true;
                    return entry->key + strlen(key) + 1;
                }
            }
        }
    }
    return NULL;
}

const char *cd_arg_get2(cd_args_t *ca, const char *key1, const char *key2)
{
    const char *r = cd_arg_get(ca, key1);
    if (!r)
        r = cd_arg_get(ca, key2);
    return r;
}

const char *cd_arg_get_left(cd_args_t *ca)
{
    list_node_t *pre, *pos;

    list_for_each(&ca->head, pre, pos){
        cd_args_entry_t *entry = list_entry(pos, cd_args_entry_t);
        if (!entry->used) {
            entry->used = true;
            return entry->key;
        }
    }
    return NULL;
}
