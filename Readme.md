
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
2. The publisher append the same node to all subscriber's node_head, and increase the reference count of the node each time.
   If any subscriber's nodes amount equal to it's max_len before append new node to anyone:
     wait until not equal if need_wait is true;
     or decrease the reference count of the oldest node, then free or drop it.
3. The subscriber pick up a node, then use it at any time (read only).
4. After use, decrease the reference count and release the node if the count become zero (or drop if not zero).

#### Service

For use as service, only one replier is allowed.

1. The requester request a free node.
2. The requester append the node to replier's node_head, and don't check replier's nodes amount.
3. The replier pick up a node.
4. The replier return the answer to requester (overwrite or append after original data). If the timeout flag in the node is set by requester, free it instead.
5. The requester free the node.


### Other Consideration

 - We could implement the channel data structure inside a centra server application, for cross platform purpose.
 - We could use different daemon application to export Topic and Service channel to different interface protocol, e.g. websocket, TCP/UDP socket, unix socket.

#### Logging

Use a stand alone topic for logging, when anyone call the library's API to put or get a node, the library use the node's index number as an id, write the id and topic path into log node, and copy part of data to log node, then send the log node to log topic.

To save full data for big data size topic, you can simply add a subscriber for debug in that topic.


## License
```
This Source Code Form is subject to the terms of the Mozilla
Public License, v. 2.0. If a copy of the MPL was not distributed
with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
```
