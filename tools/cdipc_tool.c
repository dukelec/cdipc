/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

#include <getopt.h>
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>

#define DEBUG
#include "cdipc.h"


enum OPT_CREATE_IDX {
    OPT_CREATE_NAME = 1000,
    OPT_CREATE_TYPE,
    OPT_CREATE_MAX_PUB,
    OPT_CREATE_MAX_SUB,
    OPT_CREATE_MAX_ND,
    OPT_CREATE_MAX_LEN
};

static struct option opt_create[] = {
        { "name",       required_argument, NULL, OPT_CREATE_NAME },
        { "type",       required_argument, NULL, OPT_CREATE_TYPE },
        { "max-pub",    required_argument, NULL, OPT_CREATE_MAX_PUB },
        { "max-sub",    required_argument, NULL, OPT_CREATE_MAX_SUB },
        { "max-nd",     required_argument, NULL, OPT_CREATE_MAX_ND },
        { "max-len",    required_argument, NULL, OPT_CREATE_MAX_LEN },
        { 0, 0, 0, 0 }
};

int cmd_create(int argc, char **argv)
{
    char name[NAME_MAX] = { 0 };
    cdipc_type_t type = CDIPC_TOPIC;
    int max_pub = 2;
    int max_sub = 1;
    int max_nd = 1;
    size_t max_len = 256;

    while (true) {
        int option = getopt_long(argc, argv, "", opt_create, NULL);
        if (option == -1) {
            if (optind < argc) {
                printf ("non-option argv-elements: ");
                while (optind < argc)
                    printf ("%s ", argv[optind++]);
                putchar ('\n');
            }
            break;
        }
        switch (option) {
        case OPT_CREATE_NAME:
            strncpy(name, optarg, NAME_MAX);
            df_debug("set name: %s\n", name);
            break;
        case OPT_CREATE_TYPE:
            if (0 == strcasecmp(optarg, "service")) {
                type = CDIPC_SERVICE;
                df_debug("set type: service\n");
            } else if (0 != strcasecmp(optarg, "topic")) {
                df_error("wrong type, must be topic or service\n");
                exit(-1);
            }
            break;
        case OPT_CREATE_MAX_PUB:
            max_pub = atol(optarg);
            df_debug("set max_pub: %d\n", max_pub);
            break;
        case OPT_CREATE_MAX_SUB:
            max_sub = atol(optarg);
            df_debug("set max_sub: %d\n", max_sub);
            break;
        case OPT_CREATE_MAX_ND:
            max_nd = atol(optarg);
            df_debug("set max_nd: %d\n", max_nd);
            break;
        case OPT_CREATE_MAX_LEN:
            max_len = atol(optarg);
            df_debug("set max_len: %ld\n", max_len);
            break;
        case 0:
        case '?':
        default:
            break;
        }
    }

    if (!strlen(name)) {
        df_error("--name must specified\n");
        return -1;
    }
    df_debug("name: %s; type: %d, pub: %d, sub: %d, nd: %d, len: %ld\n",
            name, type, max_pub, max_sub, max_nd, max_len);
    return cdipc_create(name, type, max_pub, max_sub, max_nd, max_len);
}

int cmd_unlink(void)
{
    return 0;
}

int cmd_dump(void)
{
    return 0;
}

int main(int argc, char **argv)
{
    if (argc <= 1) {
        printf("Usage: cdipc [create|unlink|dump] ...\n");
        return -1;
    }

    if (0 == strcmp(argv[1], "create")) {
        return cmd_create(argc - 1, &argv[1]);
    }

    printf("Unknown command: %s\n", argv[1]);
    printf("Usage: cdipc [create|unlink|dump] ...\n");
    return -1;
}

