/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

/*
 * cd_args: an arguments parsing library
 *
 * example:
 *
 *  cd_args_t ca;
 *  cd_args_parse(&ca, argc, argv);
 *
 *  // if --id not found, use default value "0"
 *  // --id 3, --id=3 are the same
 *  int id = atol(cd_arg_get_def(&ca, "--id", "0"));
 *
 *  // -h is short version for --help, return not NULL if found of any
 *  // return NULL if arg not found, return empty string if arg has no value
 *  if (cd_arg_get2(&ca, "--help", "-h")) {
 *      printf("%s", usage_dump);
 *      exit(0);
 *  }
 *
 *  // we could call cd_arg_get_left in a loop to report all left args
 *  const char *left = cd_arg_get_left(&ca);
 *  if (left) {
 *      df_error("unknown arg: %s\n", left);
 *      printf("%s", usage_dump);
 *      exit(-1);
 *  }
 */

#ifndef __CD_ARGS_H__
#define __CD_ARGS_H__

#include "cd_utils.h"
#include "cd_list.h"

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
