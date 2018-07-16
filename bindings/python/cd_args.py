#!/usr/bin/env python
# Software License Agreement (MIT License)
#
# Copyright (c) 2018, UFactory, Inc.
# All rights reserved.
#
# Author: Duke Fong <duke@ufactory.cc>

""" cd_args: an arguments parsing library

example:

from cd_args import CdArgs

args = CdArgs() # or CdArgs(argv)

# if --id not found, use default value "0"
# --id 3, --id=3 are the same
id = int(args.get("--id", dft="0"))

# -h is short version for --help, return not None if found of any
# return None if arg not found, return empty string if arg has no value
if args.get("--help", "-h") != None:
    print("help message...")

# we could call cd_arg_get_left in a loop to report all left args
left = args.get_left()
if left != None:
    print("unknown arg:", left)
"""

import sys

class CdArgs():
    def __init__(self, argv=None):
        err_flag = False
        self.entries = []
        argv = argv[1:] if argv else sys.argv[1:]
        pre_entry = None
        for arg in argv:
            if arg.startswith("-"):
                pre_entry = {"key": arg, "val": "", "used": False}
                self.entries.append(pre_entry)
            else:
                if pre_entry:
                    pre_entry["val"] = arg
                    pre_entry = None
                else:
                    # save unwanted arg, report to user through get_left
                    self.entries.append({"key": arg, "val": "", "used": False})

    def _get(self, key):
        for entry in self.entries:
            if entry["key"].startswith(key):
                if len(entry["key"]) == len(key):
                    entry["used"] = True
                    return entry["val"]
                if entry["key"][len(key):len(key)+1] == "=":
                    entry["used"] = True
                    return entry["key"][len(key)+1:]
        return None

    def get(self, key1, key2=None, dft=None):
        val = self._get(key1)
        if val == None and key2:
            val = self._get(key2)
        if val == None:
            val = dft
        return val

    def get_left(self):
        for entry in self.entries:
            if not entry["used"]:
                entry["used"] = True
                return entry["key"]
        return None

