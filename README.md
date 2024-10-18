# BPF_TOOLS

Including some eBPF scripts to analyze performance.

### wakeup_latency.py
Sometimes, we want to know why our user thread has to wait a semaphore for a long time.
For example, user thread T0 waits for semaphore S1, and thread T1 does the first work and wakeups thread T2, T2 does the second work and then finally wakeups the S1 of user thread. To analyze the performance during the wakeup chains, we show the all broken wakeup latency, i.e., T0 (wait_start) -> T1 -> T2 -> T0 (wait_end).

This script uses ebp-usdt to trace the waiting process of one random user thread, and also the notify position of all wakeup threads.

#### usage:
First, we should include the header of folly tracing files and insert 'FOLLY_SDT' tracepoint to our source code.

1. wait_position
```c++
#include "folly/tracing/StaticTracepoint.h"

FOLLY_SDT(usdt, wait_start, threshold);
pthread_cond_wait(S1)
FOLLY_SDT(usdt, wait_end);
```

2. notify position
```c++
// thread T1
FOLLY_SDT(usdt, 1, notify_val);
wakeup_T2()

// thread T2
FOLLY_SDT(usdt, 2, notify_val);
pthread_cond_notify(S1)
```
Only the threshold exceeds the notify_val, the next thread will be notified.

then run our program, and use eBPF script to print the following similar result.
#### example:
```shell
$ sudo python wakeup_latency.py -p 36780 -d 1 -u
[ Attaching probes to pid 36780 for 5 seconds ]
[ 4 wakeup point are set ]
================================================================================
Graph of wakeup latency:
        [ wait_start ]
              | 298 usecs, 1447 counts
              V
        [ wakeup 1 ]
              | 44 usecs, 1309 counts
              V
        [ wakeup 2 ]
              | 948 usecs, 1369 counts
              V
        [ wakeup 3 ]
              | 451 usecs, 1054 counts
              V
        [ wakeup 4 ]
              | 1131 usecs, 1089 counts
              V
        [ wait end ]
average wait latency: 2656 usecs, cnt: 1453

================================================================================
Histogram of each wakeup:

Historgram = The Whole Wait latency
     usecs               : count     distribution
         0 -> 1          : 4        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 27       |**                                      |
       128 -> 255        : 43       |****                                    |
       256 -> 511        : 85       |********                                |
       512 -> 1023       : 366      |**************************************  |
      1024 -> 2047       : 203      |*********************                   |
      2048 -> 4095       : 384      |****************************************|
      4096 -> 8191       : 292      |******************************          |
      8192 -> 16383      : 39       |****                                    |

Historgram =  from [ wait start ] to [ wakeup 1 ]

     usecs               : count     distribution
         0 -> 1          : 141      |***********************                 |
         2 -> 3          : 145      |************************                |
         4 -> 7          : 239      |****************************************|
         8 -> 15         : 239      |****************************************|
        16 -> 31         : 77       |************                            |
        32 -> 63         : 68       |***********                             |
        64 -> 127        : 93       |***************                         |
       128 -> 255        : 102      |*****************                       |
       256 -> 511        : 120      |********************                    |
       512 -> 1023       : 80       |*************                           |
      1024 -> 2047       : 104      |*****************                       |
      2048 -> 4095       : 34       |*****                                   |
...
```

### latch_latency.py
Sometimes, we want to know who holds the target latch, and cause user thread to wait for a long time.

This scripts uses ebp-usdt to trace the waiting process of one random user thread, and shows all holding threads and its stacks, average latency and hold counts.

#### usage:
1. wait_position
```c++
#include "folly/tracing/StaticTracepoint.h"

FOLLY_SDT(usdt, wait_start, mutex_addr);
mutex_enter(mutex_addr);
FOLLY_SDT(usdt, wait_end);
```

2. mutex_exit position
```c++
__attribute__((noinline)) void latch_exit(void *mutex) {
  FOLLY_SDT(usdt, latch_exit, mutex);
}

void mutex_exit(void *mutex) {
  latch_exit(mutex);
}
```

#### example:
```shell
[ Attaching probes to pid 37509 for 5 seconds ]
================================================================================
Latch wait latency:

avg : 736 usecs, cnt: 2214

================================================================================
Latency that other threads hold this latch when we are waiting:

| 65 usecs, 74 counts | mysqld | latch_exit();ReadView::clone_oldest();PrivateReadView::open_purge();trx_purge();srv_purge_coordinator_thread();start_thread()

| 5 usecs, 37760 counts | mysqld | latch_exit();trx_commit_low();trx_commit();trx_commit_for_mysql();innobase_commit();ha_commit_low();TC_LOG_DUMMY::commit();ha_commit_trans();trans_commit_stmt();mysql_execute_command();Prepared_statement::execute();Prepared_statement::execute_loop();mysqld_stmt_execute();dispatch_command();do_handle_one_connection();handle_one_connection();start_thread()

| 12 usecs, 37901 counts | mysqld | latch_exit();trx_commit_low();trx_commit();trx_commit_for_mysql();innobase_commit();ha_commit_low();TC_LOG_DUMMY::commit();ha_commit_trans();trans_commit_stmt();mysql_execute_command();Prepared_statement::execute();Prepared_statement::execute_loop();mysqld_stmt_execute();dispatch_command();do_handle_one_connection();handle_one_connection();start_thread()

| 22 usecs, 38439 counts | mysqld | latch_exit();trx_start_low();row_search_for_mysql();ha_innobase::index_read();handler::read_range_first();handler::multi_range_read_next();QUICK_RANGE_SELECT::get_next();rr_quick();mysql_update();mysql_execute_command();Prepared_statement::execute();Prepared_statement::execute_loop();mysqld_stmt_execute();dispatch_command();do_handle_one_connection();handle_one_connection();start_thread()
```
