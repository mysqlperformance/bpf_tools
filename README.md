# BPF_TOOLS

Including many eBPF scripts to analyze performance.

### wakeup_latency
Using USDT, to answer why our user thread has to wait for a long time. By tracing the wakup latency from other threads, which wakeup us to not to wait.

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

