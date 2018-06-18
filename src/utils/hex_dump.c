/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2017, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author:
 *   Dominik Liebler
 *   Duke Fong <duke@dukelec.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cd_utils.h"


void hex_dump_small(char *pbuf, const void *addr, int len, int limit)
{
    int i;
    int dump_len = min(len, limit);
    int pos = 0;
    const uint8_t *pc = (const uint8_t *)addr;

    if (len == 0 || len < 0)
        pbuf[0] = '\0';
    for (i = 0; i < dump_len; i++)
        pos += sprintf(pbuf + pos, i ? " %02x" : "%02x", pc[i]);
    if (dump_len != len)
        sprintf(pbuf + pos, " ...");
}

void hex_dump(const void *addr, int len)
{
    int i;
    int pos = 0;
    char pbuf[75];
    char sbuf[17];
    const uint8_t *pc = (const uint8_t *)addr;

    if (len == 0 || len < 0)
        return;

    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0) {
                pos += sprintf(pbuf + pos, "  %s\n", sbuf);
                dputs(pbuf);
                pos = 0;
            }
            pos += sprintf(pbuf + pos, "  %04x ", i); // offset
        }
        pos += sprintf(pbuf + pos, " %02x", pc[i]);

        // printable ascii character
        if (pc[i] < 0x20 || pc[i] > 0x7e)
            sbuf[i % 16] = '.';
        else
            sbuf[i % 16] = pc[i];
        sbuf[(i % 16) + 1] = '\0';
    }

    // pad out last line
    while ((i % 16) != 0) {
        pos += sprintf(pbuf + pos, "   ");
        i++;
    }
    // print the final ascii field
    pos += sprintf(pbuf + pos, "  %s\n", sbuf);
    dputs(pbuf);
}
