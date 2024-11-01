#!/usr/bin/python2
from __future__ import print_function
from bcc import BPF, USDT
from time import sleep, strftime
import argparse
import signal
import ctypes as ct

parser = argparse.ArgumentParser(description="show distribution of variables.",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", type=int, help="The id of the process to trace.")
parser.add_argument("-i", "--interval", type=int,
    help="summary interval, in seconds")
parser.add_argument("-d", "--duration", type=int,
    help="total duration of trace, in seconds")
parser.add_argument("-n", "--name", type=str, help="The name of traced variables.")

parser.set_defaults(verbose=False)
args = parser.parse_args()
if args.duration and not args.interval:
  args.interval = args.duration
if not args.interval:
  args.interval = 99999999
if not args.duration:
  args.duration = 99999999
if not args.pid:
  print("ERROR: pid is empty")
  exit(1)
if not args.name:
  print("ERROR: variable name is empty")
  exit(1)

print("[ Attaching probes to pid %d for %d seconds ]" % (args.pid, args.duration))
def signal_ignore(signal, frame):
    print()

bpf_text="""

typedef struct hist_key {
    u64 tid;
    u64 slot;
} hist_key_t;

// for wakeup latency
BPF_ARRAY(avgs, u64, 2);
BPF_HISTOGRAM(thread_dist, hist_key_t);
BPF_HISTOGRAM(dist);

int got_variable(struct pt_regs *ctx) {
  u64 tid = bpf_get_current_pid_tgid();
  u64 var;
  bpf_usdt_readarg(1, ctx, &var);
  //bpf_trace_printk("var: %llu\\n", var);
  avgs.increment(0, var);
  avgs.increment(1, 1);
  dist.increment(bpf_log2l(var));
  return 0;
}

"""

usdt_ctx = USDT(pid=args.pid)
usdt_ctx.enable_probe(probe="vardist:" + args.name, fn_name="got_variable")

b = BPF(text=bpf_text, usdt_contexts=[usdt_ctx], debug=0)

def print_cross_line(c):
  str = ""
  for i in range(80):
    str += c
  print("\033[33m%s\033[0m" % (str))
def print_title(str):
  print("\033[32m%s\033[0m" % (str))

# print distribution of wakeup
def print_variable_dist(dist, avgs):
  print_cross_line('=')
  print_title("Distribution of varables [%s]: " % (args.name))
  dist.print_log2_hist(args.name)
  avg = avgs[0].value / (avgs[1].value + 1)
  print("variable avg: %ld, cnt: %ld\n" %(avg, avgs[1].value))

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

    print_variable_dist(b['dist'], b['avgs'])
    b['avgs'].clear()
    b['dist'].clear()
    if exiting:
        print("Detaching...")
        exit()
