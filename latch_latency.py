#!/usr/bin/python2
from __future__ import print_function
from bcc import BPF, USDT
from time import sleep, strftime
import argparse
import signal
import ctypes as ct

parser = argparse.ArgumentParser(description="Trace the latch latency from one user thread.",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", type=int, help="The id of the process to trace.")
parser.add_argument("-u", "--microseconds", action="store_true",
    help="microsecond histogram")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-i", "--interval", type=int,
    help="summary interval, in seconds")
parser.add_argument("-d", "--duration", type=int,
    help="total duration of trace, in seconds")

parser.set_defaults(verbose=False)
args = parser.parse_args()
if args.duration and not args.interval:
  args.interval = args.duration
if not args.interval:
  args.interval = 99999999
if not args.pid:
  print("ERROR: pid is empty")
  exit(1)

print("[ Attaching probes to pid %d for %d seconds ]" % (args.pid, args.duration))
def signal_ignore(signal, frame):
    print()

bpf_text="""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>
struct key_t {
  u32 pid;
  int stack_id;
  char name[TASK_COMM_LEN];
};

struct val_t {
  u64 total;
  u32 count;
};

struct thd_t {
  u64 latch;
  u64 wait_ts;
  u64 last_latch_exit_ts;
};

BPF_ARRAY(user_tid, u64, 1);
BPF_HASH(thds, u64, struct thd_t);

BPF_ARRAY(avgs, u64, 2);
BPF_HASH(latencys, struct key_t, struct val_t, 40960);
BPF_STACK_TRACE(stack_traces, 16384);

/* get and set one thread to trace */
static u64 get_user_tid() {
  int key = 0;
  u64 *tid = user_tid.lookup(&key);
  if (tid == 0)
    return 0;
  return *tid;
}
static void set_user_tid(u64 val) {
  int key = 0;
  u64 *tid = user_tid.lookup(&key);
  if (tid == 0)
    return;
  if (*tid == 0)
    // no user thread, choose one
    *tid = val;
}

int wait_start(struct pt_regs *ctx) {
  u64 tid = bpf_get_current_pid_tgid();
  u64 ts = bpf_ktime_get_ns();

  if (get_user_tid() == 0) {
    set_user_tid(tid);
  }

  if (tid != get_user_tid()) {
    return 0;
  }

  //bpf_trace_printk("latch: %llu\\n", tid);
  struct thd_t thd = {0};
  bpf_usdt_readarg(1, ctx, &thd.latch);
  thd.wait_ts = ts;
  thd.last_latch_exit_ts = ts;
  thds.update(&tid, &thd);
  return 0;
}

int latch_exit(struct pt_regs *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
  u64 latch;
  bpf_usdt_readarg(1, ctx, &latch);
  bpf_trace_printk("latch: %llu\\n", latch);
  u64 user_tid = get_user_tid();
  struct thd_t *thd = thds.lookup(&user_tid);
  if (thd == 0 || latch != thd->latch) {
      return 0;
  }
  struct key_t key = {.pid = tgid};
  key.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
  bpf_get_current_comm(&key.name, sizeof(key.name));
  u64 ts = bpf_ktime_get_ns();
  u64 delta = ts - thd->last_latch_exit_ts;
  if (ts < thd->last_latch_exit_ts)
    delta = 0;
  thd->last_latch_exit_ts = ts;
  FACTOR
  struct val_t *valp, zero = {};
  valp = latencys.lookup_or_try_init(&key, &zero);
  if (valp) {
    valp->total += delta;
    valp->count += 1;
  }
  return 0;
}

int wait_end(struct pt_regs *ctx) {
  u64 tid = bpf_get_current_pid_tgid();
  struct thd_t *thd = thds.lookup(&tid);
  if (thd == 0) {
     return 0;
  }
  /* calculate the whole wait time */
  u64 ts = bpf_ktime_get_ns();
  u64 delta = ts - thd->wait_ts;
  FACTOR
  avgs.increment(0, delta);
  avgs.increment(1, 1);

  thds.delete(&tid);
  return 0;
}
"""

usdt_ctx = USDT(pid=args.pid)
usdt_ctx.enable_probe(probe="usdt:wait_start", fn_name="wait_start")
usdt_ctx.enable_probe(probe="usdt:wait_end", fn_name="wait_end")
usdt_ctx.enable_probe(probe="usdt:latch_exit", fn_name="latch_exit")

if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
elif args.microseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"
else:
    bpf_text = bpf_text.replace('FACTOR', '')
    label = "nsecs"

b = BPF(text=bpf_text, usdt_contexts=[usdt_ctx], debug=0)

def print_cross_line(c):
  str = ""
  for i in range(80):
    str += c
  print("\033[33m%s\033[0m" % (str))
def print_title(str):
  print("\033[32m%s\033[0m\n" % (str))

# print distribution of latch_latency
def print_latch_latency(avgs, latencys, stack_traces):
  print_cross_line('=')
  print_title("Latch wait latency: ")
  avg = avgs[0].value / (avgs[1].value + 1)
  print("avg : %ld %s, cnt: %ld\n" %(avg, label, avgs[1].value)) 
  print_cross_line('=')
  print_title("Latency that other threads hold this latch when we are waiting: ")
  for k, v in sorted(latencys.items(), key=lambda kv: kv[1].total):
    user_stack = [] if k.stack_id < 0 else \
        stack_traces.walk(k.stack_id)
    user_stack = list(user_stack)
    line = []
    line.extend([b.sym(addr, k.pid).decode('utf-8', 'replace').split('(')[0] + "()" for addr in user_stack])
    name = k.name.decode('utf-8', 'replace')
    avg = (v.total) / (v.count + 1)
    print("| %d %s, %d counts | %s | %s\n" % (avg, label, v.count, name, ";".join(line)))

exiting = 0 if args.interval else 1
seconds = 0
while 1:
    try:
        sleep(args.interval)
        seconds += args.interval
    except KeyboardInterrupt:
        exiting = 1
        # as cleanup can take many seconds, trap Ctrl-C:
        signal.signal(signal.SIGINT, signal_ignore)
    if args.duration and seconds >= args.duration:
        exiting = 1

    print_latch_latency(b['avgs'], b['latencys'], b['stack_traces'])
    b['avgs'].clear()
    if exiting:
        print("Detaching...")
        exit()
