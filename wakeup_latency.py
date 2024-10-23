#!/usr/bin/python2
from __future__ import print_function
from bcc import BPF, USDT
from time import sleep, strftime
import argparse
import signal
import ctypes as ct

parser = argparse.ArgumentParser(description="Trace the wakup latency from one user thread.",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", type=int, help="The id of the process to trace.")
parser.add_argument("-t", "--user_tid", type=int, help="the user thread id we care about.")
parser.add_argument("-u", "--microseconds", action="store_true",
    help="microsecond histogram")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-i", "--interval", type=int,
    help="summary interval, in seconds")
parser.add_argument("-d", "--duration", type=int,
    help="total duration of trace, in seconds")
parser.add_argument("-M", "--max_wakeup_count", type=int,
    help="max wakeup count to analyze, 16 by defalut")

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
if not args.max_wakeup_count:
  args.max_wakeup_count = 16

print("[ Attaching probes to pid %d for %d seconds ]" % (args.pid, args.duration))
def signal_ignore(signal, frame):
    print()

bpf_text="""
struct thd_t {
  u64 threshold;
  bool is_wakeup[MAX_WAKEUP_COUNT+1];
};

typedef struct hist_key {
    u32 wakeup_id;
    u64 slot;
} hist_key_t;

BPF_ARRAY(user_tid, u64, 1);
BPF_HASH(thds, u64, struct thd_t);

// for wakeup latency
BPF_ARRAY(wakeup_ts, u64, MAX_WAKEUP_COUNT + 1); // include wait start
BPF_ARRAY(wakeup_totals, u64, MAX_WAKEUP_COUNT + 1);
BPF_ARRAY(wakeup_counts, u64, MAX_WAKEUP_COUNT + 1);
BPF_HISTOGRAM(wakeup_dist, hist_key_t);

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
  if (USER_THREAD != -1) {
    val = USER_THREAD;
  }
  if (*tid == 0)
    // no user thread, choose one
    *tid = val;
}

/* set timestamp of each wakeup */
static void set_wakeup_ts(u32 i, u64 val) {
  u64 *ts = wakeup_ts.lookup(&i);
  if (ts == 0)
    return;
  *ts = val;
}

static u64 get_wakeup_ts(u32 i) {
  u64 *ts = wakeup_ts.lookup(&i);
  if (ts == 0)
    return 0;
  return *ts;
}

static void store_wakeup_time(struct thd_t *thd, u32 wid, u64 ts) {
  if (thd->is_wakeup[wid] != 0) {
    // already wake up
    return;
  }

  thd->is_wakeup[wid] = true;
  set_wakeup_ts(wid, ts);

  /* large wakeup comes, and we enable all small
   * uncoming wakeups and set their latency to 1ns */
  u32 i = wid - 1;
  for (; i > 0 && !thd->is_wakeup[i]; i--) {
    thd->is_wakeup[i] = true;
    hist_key_t key = {};

    key.wakeup_id = i;
    u64 delta = 1;
    key.slot = bpf_log2l(delta);
    wakeup_dist.increment(key);
    wakeup_totals.increment(i, delta);
    wakeup_counts.increment(i, 1);
  }
  /* calculate the time after previous wakeup */
  u64 prev_ts = get_wakeup_ts(i);
  if (ts > prev_ts) {
    hist_key_t key = {};
    u64 delta = ts - prev_ts;
    FACTOR
    key.wakeup_id = wid;
    key.slot = bpf_log2l(delta);
    wakeup_dist.increment(key);
    wakeup_totals.increment(wid, delta);
    wakeup_counts.increment(wid, 1);
  }
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

  //bpf_trace_printk("threshold: %llu\\n", tid);
  struct thd_t thd = {0};
  thd.is_wakeup[0] = true;
  set_wakeup_ts(0, ts);
  bpf_usdt_readarg(1, ctx, &thd.threshold);
  thds.update(&tid, &thd);
  return 0;
}

WAKEUP_FUNC

int wait_end(struct pt_regs *ctx) {
  u64 tid = bpf_get_current_pid_tgid();
  struct thd_t *thd = thds.lookup(&tid);
  if (thd == 0) {
     return 0;
  }
  /* calculate the whole wait time */
  u64 start_ts = get_wakeup_ts(0);
  u64 ts = bpf_ktime_get_ns();
  u64 delta = ts - start_ts;
  hist_key_t key = {};
  FACTOR
  key.wakeup_id = 0;
  key.slot = bpf_log2l(delta);
  wakeup_dist.increment(key);
  wakeup_totals.increment(0, delta);
  wakeup_counts.increment(0, 1);

  /* wait_end is also the last wakeup */
  store_wakeup_time(thd, MAX_WAKEUP_COUNT, ts);

  thds.delete(&tid);
  return 0;
}
"""

usdt_ctx = USDT(pid=args.pid)
usdt_ctx.enable_probe(probe="wakeup:wait_start", fn_name="wait_start")
usdt_ctx.enable_probe(probe="wakeup:wait_end", fn_name="wait_end")

wakeup_text = ""
for i in range(1, args.max_wakeup_count):
  try:
    usdt_ctx.enable_probe(probe="wakeup:%d" % (i), fn_name="wakeup_%d" % (i))
    fn_text = """
      int wakeup_""" + str(i) + """(struct pt_regs *ctx) {
        u32 wid = """ + str(i) + """;
        u64 notify_val;
        bpf_usdt_readarg(1, ctx, &notify_val);
        //bpf_trace_printk("norify_val %llu\\n", notify_val);
        u64 tid = get_user_tid();
        struct thd_t *thd = thds.lookup(&tid);

        if (thd == 0 || notify_val < thd->threshold) {
          // notify_val doesn't reach the threshold,
          return 0;
        }

        u64 ts = bpf_ktime_get_ns();
        store_wakeup_time(thd, wid, ts);
        return 0;
      }
    """
    wakeup_text += fn_text
  except:
    break;

print("[ %d wakeup points are set ]" % (i-1))
bpf_text = bpf_text.replace("WAKEUP_FUNC", wakeup_text);
bpf_text = bpf_text.replace("MAX_WAKEUP_COUNT", str(i));
args.max_wakeup_count = i
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
elif args.microseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"
else:
    bpf_text = bpf_text.replace('FACTOR', '')
    label = "nsecs"

if args.user_tid:
  bpf_text = bpf_text.replace('USER_THREAD', str(args.user_tid))
else:
  bpf_text = bpf_text.replace('USER_THREAD', '-1')

b = BPF(text=bpf_text, usdt_contexts=[usdt_ctx], debug=0)

def print_cross_line(c):
  str = ""
  for i in range(80):
    str += c
  print("\033[33m%s\033[0m" % (str))
def print_title(str):
  print("\033[32m%s\033[0m" % (str))
def print_arrow(middle, tail):
  print("\t      | %s\n\t      V\n\t\033[33m%s\033[0m" % (middle, tail))

def get_avg(totals, counts, i):
  return totals[i].value / (counts[i].value + 1)

# print distribution of wakeup
def print_wakeup_graph(totals, counts):
  print_cross_line('=')
  print_title("Graph of wakeup latency: ")
  print("\t\033[33m[ wait_start ]\033[0m")
  for i in range(1, args.max_wakeup_count):
    cnt = counts[i].value
    if cnt == 0:
      continue
    avg = get_avg(totals, counts, i)
    print_arrow("%d %s, %d counts" % (avg, label, cnt), "[ wakeup %d ]" % (i))
  cnt = counts[args.max_wakeup_count].value
  avg = get_avg(totals, counts, args.max_wakeup_count)
  print_arrow("%d %s, %d counts" % (avg, label, cnt), "[ wait end ]")
  avg = get_avg(totals, counts, 0)
  print("average wait latency: %ld %s, cnt: %ld\n" %(avg, label, counts[0].value))

def print_section(key):
  if key == 0:
    return "The Whole Wait latency"
  start = ("wakeup " + str(key - 1)) if key > 1 else "wait start"
  end = ("wakeup " + str(key)) if key < args.max_wakeup_count else "wait end"
  return " from [ %s ] to [ %s ]\n" % (start, end)

def print_wakeup_dist(wakeup_dist):
  print_cross_line('=')
  print_title("Histogram of each wakeup: ")
  wakeup_dist.print_log2_hist(label, "Historgram", section_print_fn=print_section,
      bucket_fn=lambda k: k)

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

    print("[ user thread %d is selected ]" % (ct.c_int32(b['user_tid'][0].value).value))
    print_wakeup_dist(b['wakeup_dist'])
    print_wakeup_graph(b['wakeup_totals'], b['wakeup_counts'])
    b['wakeup_totals'].clear()
    b['wakeup_counts'].clear()
    b['wakeup_dist'].clear()
    if exiting:
        print("Detaching...")
        exit()
