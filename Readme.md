
## CDIPC

CDIPC is an Inter-Process Communication (IPC) mechanism and library. It is uniquely suited for coordinating perception, control drivers, and algorithms in real-time systems that sample data from physical processes.

CDIPC is similar to the ACH IPC library, but eliminates memory copy to improve efficiency. Other differences:

 - CDIPC support both Topic and Service similar to ROS;
 - Unlike the ACH and ROS Topic, if any of the subscriber's queue is full and the need_wait flag is true,
   the publisher will block.


### Channel Data Structure

Data is shared between processes through mmap.

The data structure is same for Topic and Service, the gray part is service only.

The publisher (/requester) and subscriber (/replier) are initialled statictly,
we could support dynamic registration, but it is not implemented for the moment because it is not commonly used.

The max data size of each node in each channel are the same.

<img src="docs/img/cdipc-data-structure.svg" style="max-width:100%">

Currently we use a single conditional variable instead of all semaphores for simplification.


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
4. The replier return data to requester (by simply clear reference map bit) (append after original data).
5. The requester free the node after read return data.


### Other Consideration

 - We could implement the channel data structure inside a centra server application (instead of shared memory), for cross platform purpose.
 - We could use different daemon application to export Topic and Service channel to different interface protocol, e.g. websocket, TCP/UDP socket, unix socket.
 - We could traversal all nodes to retrieve lost nodes depend on pub and sub reference, e.g. process exist on error.

#### Logging

We can simply add one or more subscriber to each topic and service dedicated for logging.

Note: The log subscriber in service nerver replier to requester.


## License

The MIT License (MIT)  
https://rem.mit-license.org

