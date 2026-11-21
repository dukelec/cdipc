
## CDIPC

CDIPC is an Inter-Process Communication (IPC) mechanism and library. It is uniquely suited for coordinating perception, control drivers, and algorithms in real-time systems that sample data from physical processes.

CDIPC is similar to the ACH IPC library, but eliminates memory copy to improve efficiency. Other differences:

 - CDIPC support both Topic and Service similar to ROS;
 - Unlike the ACH and ROS Topic, if any of the subscriber's queue is full and the need_wait flag is true,
   the publisher will block.


### Channel Data Structure

Data is shared between processes through shared memory.

The data structure is same for Topic and Service, the gray part is service only.

The publisher (/requester) and subscriber (/replier) are initialled statictly,
we could support dynamic registration, but it is not implemented for the moment because it is not commonly used.

The max data size of each node in each channel are the same.

<img src="docs/img/cdipc-data-structure.svg" style="max-width:100%">

Each subscriber waits on its own condition variable, publishers (/requesters) share the one in the header,
so a wakeup only reaches the side which could make progress.


### Core Procedures

#### Topic

1. The publisher request a free node at begining, then fill data to the node at any time.
2. The publisher append the same node to all subscriber's node_head, and set the node reference map corresponding bits.
   If any subscriber's nodes amount equal to it's max_len before append new node to anyone:
     wait until not equal if need_wait is true;
     or clear the reference map bit of the oldest node, then free or drop it.
3. The subscriber pick up a node, then use it at any time (read only).
4. After use, clear the reference map bit and release the node if the map become zero (or drop if not zero).

#### Service

For use as service, only one replier is allowed.

1. The requester request a free node (as same as topic).
2. The requester append the node to replier's node_head (as same as topic, without clear pub reference).
3. The replier pick up a node.
4. The replier return data to requester (by simply clear reference map bit).
5. The requester free the node after read return data (free before reply cancels the request).

`cdipc_pub_put` fails if the replier (sub 0) is not enabled,
`cdipc_pub_wait` returns `ECANCELED` if the request is dropped or aborted.


### Other Consideration

 - We could traversal all nodes to recover lost nodes depend on pub and sub reference, e.g. process exist on error.
 - If a process dies while holding the channel lock, the next locker takes the lock over and repairs the lists.
 - All processes of a channel must be in the same PID namespace (e.g. docker `--pid=host`),
   because the PI-futex identifies the lock owner by its TID.
 - Because we use PI-futex instead of pthread mutex, so communication between user and kernel space is possible.
 - We could use different daemon application to export Topic and Service channel to different interface protocol, e.g. websocket (already support), TCP/UDP socket, unix socket.


#### Logging

We can simply add one or more subscriber to each topic and service dedicated for logging.

Note: The log subscriber in service never reply to requester, it releases the node by `cdipc_sub_free`.


### TODO

 - Wait on multiple channels by one call: add a plain event counter to each subscriber,
   wake it at publish and wait by `futex_waitv` (Linux >= 5.16).


### Install

`make && sudo make install`


### Test

`make test` runs the regression and stress tests under `tests/`,
`make test-ws` tests the websocket server (needs python websockets >= 14.2).


### Example

There is a command line tool for test purpose, type `cdipc --help` for more details,
or read the help message at the beginning of `tools/cli_tool/cdipc_tool.c`.

```
Example for topic (run put command in another terminal):
  cdipc create --name test   # create a topic with 2 pub and 2 sub
                             # 5 nodes of 256 bytes by default
  cdipc pend-cfg --name test # change max_len to 2 for first sub
                             # max_len is 0 and need_wait is false after create
  cdipc get --name test      # wait on sub id 0
  cdipc put --name test      # publish string "test msg" to the topic

Notes:
  default values can override by arguments
...
```

### License

The MIT License (MIT)  
https://rem.mit-license.org

