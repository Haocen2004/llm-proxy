#!/bin/sh
# cpu-watch.sh —— 排查脚本：CPU / load / 磁盘 IO 任一超阈值时，落盘一份系统快照。
#
# 目标环境：amd64 Linux 服务器（x86_64），POSIX sh 可运行；全部走 /proc + ps，
#   不依赖 top / iostat / sysstat / bash。临时文件优先放 tmpfs(/dev/shm)，
#   避免在 IO 瓶颈机上让监控自身产生磁盘写。
#
# 每次快照记录：
#   * 触发原因（CPU% / load1 / PSI io 压力）
#   * CPU 时间细分（iowait 单列，不再和 idle 混算）
#   * load average、runqueue 线程数、uptime
#   * PSI 压力（cpu / io / memory 的 some+full avg10）—— 定位 load 来源的关键
#   * 内存明细（含 Dirty / Writeback，脏页堆积是 IO 阻塞的直接信号）
#   * D 状态（不可中断睡眠）进程 + wchan + 命令行 —— load 被谁撑起来
#   * 瞬时写盘速率 TOP N（write_bytes 差分）
#   * 瞬时 CPU TOP N（含 pid / 完整命令行 / RSS）
#   * ps 生命期平均视图（互补参考）
#
# 用法（在服务器上）：
#   后台跑：nohup sh /usr/local/bin/cpu-watch.sh >/dev/null 2>&1 &
#   看日志：tail -f /var/log/cpu-watch.log
#   停脚本：pkill -f cpu-watch.sh
#
# 触发条件（任一命中即记录，默认值）：
#   * CPU 整机使用率 > TH（默认 75%，0=关闭）
#   * load1 > LOAD_TH（默认 = NCPU * LOAD_RATIO = 2 * 0.7 = 1.40，0=关闭）
#   * PSI io full avg10 > IO_TH（默认 40%，0=关闭）—— 磁盘阻塞触发
#   * 任一核使用率 > PERCORE_TH（默认关闭）
#
# 可调环境变量：
#   TH=75          整机 CPU 使用率阈值 %
#   LOAD_TH=        load1 绝对阈值；留空则按 NCPU*LOAD_RATIO 计算（0=关闭）
#   LOAD_RATIO=0.7  load1 相对核数的触发比例
#   IO_TH=40       PSI io full avg10 阈值 %（0=关闭）
#   PERCORE_TH=    单核 CPU 阈值 %（默认关闭）
#   INT=2          采样间隔秒
#   COOLDOWN=60    两次落盘最小间隔秒
#   TOPN=5         各类 TOP 条数
#   LOG=/var/log/cpu-watch.log
#   MAX_Kb=2048    日志轮转阈值 KB（超出转存 $LOG.1）
#   PS_EXTRA=1     是否附 ps 视图
#   CLK_TCK=100    内核 jiffies 频率
#   PAGESIZE=4096  页大小
#
# 退出码：0 正常；1 无法创建临时目录。

set -u

TH=${TH:-75}
PERCORE_TH=${PERCORE_TH:-}
LOAD_TH=${LOAD_TH:-}
LOAD_RATIO=${LOAD_RATIO:-0.7}
IO_TH=${IO_TH:-40}
COOLDOWN=${COOLDOWN:-60}
INT=${INT:-2}
TOPN=${TOPN:-5}
LOG=${LOG:-/var/log/cpu-watch.log}
MAX_Kb=${MAX_Kb:-2048}
PS_EXTRA=${PS_EXTRA:-1}
HZ=${CLK_TCK:-100}
PAGE=${PAGESIZE:-4096}

# 临时文件优先 tmpfs，避免监控自身写盘
TMPD=""
for base in /dev/shm /run /tmp; do
    if [ -d "$base" ] && [ -w "$base" ]; then
        TMPD=$(mktemp -d "$base/cpu-watch.XXXXXX" 2>/dev/null) || TMPD=""
        [ -n "$TMPD" ] && break
    fi
done
if [ -z "$TMPD" ] || [ ! -d "$TMPD" ]; then
    TMPD=/tmp/cpu-watch.$$
    mkdir -p "$TMPD" 2>/dev/null || exit 1
fi
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT
trap 'cleanup; exit 0' INT TERM HUP

C1=$TMPD/cpu.prev;  C2=$TMPD/cpu.cur
P1=$TMPD/proc.prev; P2=$TMPD/proc.cur
I1=$TMPD/io.prev;   I2=$TMPD/io.cur
U1=$TMPD/up.prev;   U2=$TMPD/up.cur

NCPU=$(awk '/^cpu[0-9]+ /{n++} END{print n+0}' /proc/stat 2>/dev/null)
case "$NCPU" in ''|*[!0-9]*) NCPU=1 ;; esac
[ "$NCPU" -lt 1 ] 2>/dev/null && NCPU=1

if [ -z "$LOAD_TH" ]; then
    LOAD_TH=$(awk -v n="$NCPU" -v r="$LOAD_RATIO" 'BEGIN{printf "%.2f", n*r}')
fi

# ---- 采样 ---------------------------------------------------------------
# /proc/stat cpu 行 -> "<cpu> <total> <idle+iowait> <user> <nice> <sys> <idle> <iowait> <irq+softirq> <steal>"
cpu_snap() {
    awk '/^cpu / || /^cpu[0-9]+ /{
             u=$2; n=$3; s=$4; i=$5; w=$6; q=$7; f=$8; st=$9;
             t=u+n+s+i+w+q+f+st;
             printf "%s %d %d %d %d %d %d %d %d %d\n", $1, t, i+w, u, n, s, i, w, q+f, st
         }' /proc/stat > "$1" 2>/dev/null
}

# /proc/<pid>/stat -> "<pid> <ppid> <cpu-jiffies>"（sed 贪婪匹配，进程名含 ")" 也正确）
proc_snap() {
    cat /proc/[0-9]*/stat 2>/dev/null \
        | sed 's/^\([0-9]*\) (.*) /\1 /' \
        | awk '{print $1, $3, $12+$13}' > "$1"
}

# /proc/<pid>/io -> "<pid> <write_bytes>"（一次 awk 读全部进程，开销极小）
io_snap() {
    awk '/^write_bytes:/{n=FILENAME; sub("/proc/","",n); sub("/io","",n); print n, $2}' \
        /proc/[0-9]*/io 2>/dev/null | sort -k1,1n > "$1"
}

up_snap() {
    awk '{printf "%.6f", $1; exit}' /proc/uptime > "$1" 2>/dev/null
}

# 两个 uptime 快照的秒差
wall_dt() {
    awk 'NR==FNR{a=$1; next} {d=$1-a; if(d<=0) d=1; printf "%.6f", d; exit}' "$1" "$2"
}

# 整机使用率（整数百分比）
cpu_usage() {
    awk 'NR==FNR{p[$1]=$2; pi[$1]=$3; next}
         $1=="cpu"{dt=$2-p[$1]; di=$3-pi[$1];
                  if(dt>0) printf "%d", (dt-di)*100/dt; else printf "0"; exit}' "$1" "$2"
}

# 每核使用率 "cpu0:99 cpu1:88 ..."
percpu_str() {
    awk 'NR==FNR{p[$1]=$2; pi[$1]=$3; next}
         /^cpu[0-9]+ /{dt=$2-p[$1]; di=$3-pi[$1];
                       u=(dt>0)?(dt-di)*100/dt:0; printf "%s:%d ", $1, u}' "$1" "$2"
}

# PSI 单行："io[s/f=77.3/66.6]"
psi_one() {
    if [ ! -r "/proc/pressure/$1" ]; then printf '%s[n/a]' "$1"; return; fi
    awk -v n="$1" '/^some/{split($0,a,"avg10="); split(a[2],b," "); s=b[1]}
                    /^full/{split($0,a,"avg10="); split(a[2],b," "); f=b[1]}
                    END{printf "%s[s/f=%s/%s]", n, s, f}' "/proc/pressure/$1" 2>/dev/null
}

# PSI io full avg10（浮点字符串）
psi_io_full() {
    [ -r /proc/pressure/io ] || { echo 0; return; }
    awk '/^full/{split($0,a,"avg10="); split(a[2],b," "); print b[1]; exit}' /proc/pressure/io 2>/dev/null
}

# 浮点比较：$1 > $2 时返回 0(真)
gt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 > b+0)}'; }

# ---- 日志轮转 -----------------------------------------------------------
rotate() {
    [ -f "$LOG" ] || return 0
    sz=$(wc -c < "$LOG" 2>/dev/null)
    case "$sz" in ''|*[!0-9]*) return 0 ;; esac
    if [ "$sz" -gt $((MAX_Kb * 1024)) ]; then
        mv -f "$LOG" "$LOG.1" 2>/dev/null
        echo "### 日志超过 ${MAX_Kb}KB，已转存为 $LOG.1 并重新开始" >> "$LOG"
    fi
}

# ---- 落盘快照（读取全局：usage / pc / wall / load1 / io_full / reason）----
dump_snapshot() {
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    up=$(awk '{u=$1; d=int(u/86400); h=int((u%86400)/3600); m=int((u%3600)/60); s=int(u%60);
               if(d>0) printf "%dd%dh%dm", d,h,m; else if(h>0) printf "%dh%dm%ds", h,m,s;
               else printf "%dm%ds", m,s; exit}' /proc/uptime 2>/dev/null)
    thr=$(awk '{print $4; exit}' /proc/loadavg 2>/dev/null)
    mem=$(awk '/^MemTotal:/{t=$2} /^MemFree:/{f=$2} /^MemAvailable:/{a=$2} /^Buffers:/{b=$2}
               /^Cached:/{c=$2} /^SwapTotal:/{st=$2} /^SwapFree:/{sf=$2}
               /^Dirty:/{d=$2} /^Writeback:/{w=$2}
               END{printf "total=%dM free=%dM avail=%dM buffcache=%dM swap=%dM/%dM dirty=%dM writeback=%dM",
                          t/1024, f/1024, a/1024, (b+c)/1024, (st-sf)/1024, st/1024, d/1024, w/1024}' \
          /proc/meminfo 2>/dev/null)
    np_now=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l | tr -d ' ')
    case "$np_now" in ''|*[!0-9]*) np_now=0 ;; esac
    detail=$(paste "$C1" "$C2" | awk '$1=="cpu"{dt=$12-$2; if(dt<=0) dt=1;
        printf "user=%.1f%% nice=%.1f%% sys=%.1f%% idle=%.1f%% IOWAIT=%.1f%% irq+softirq=%.1f%% steal=%.1f%%",
        ($14-$4)*100/dt, ($15-$5)*100/dt, ($16-$6)*100/dt, ($17-$7)*100/dt,
        ($18-$8)*100/dt, ($19-$9)*100/dt, ($20-$10)*100/dt; exit}' 2>/dev/null)
    psi="$(psi_one cpu) $(psi_one io) $(psi_one memory)"
    wall_s=$(awk -v a="$wall" 'BEGIN{printf "%.2f", a}')

    {
        echo ""
        echo "===== $ts | 触发: $reason | load $load1 $load5 $load15 | 线程(run/total) $thr | uptime $up ====="
        echo "cpu(整机 ${usage}%): $detail"
        echo "percore: $pc"
        echo "PSI(avg10, some/full): $psi"
        echo "mem: $mem | 进程数: $np_now"
    } >> "$LOG"

    # D 状态进程：load 被谁撑起来
    dlist=$(ps -eo pid,stat,wchan:20,args 2>/dev/null | awk '$2 ~ /^D/' | head -n 10 | cut -c1-170)
    if [ -n "$dlist" ]; then
        {
            echo "D 状态(不可中断睡眠, 直接贡献 load):"
            printf '  %-9s %-6s %-20s %s\n' PID STAT WCHAN CMD
            printf '%s\n' "$dlist" | sed 's/^/  /'
        } >> "$LOG"
    else
        echo "D 状态: 本轮未捕获（ps 为瞬时快照，短促 D 状态可能漏掉）" >> "$LOG"
    fi

    # 瞬时写盘 TOP
    {
        echo "瞬时写盘 TOP${TOPN} (采样 ${wall_s}s):"
        printf '  %-9s %-10s %s\n' PID RATE CMD
    } >> "$LOG"
    wtop=$(awk -v dt="$wall" 'NR==FNR{w[$1]=$2; next}
         {d=($2-w[$1])/dt; if(d>1) printf "%.0f %s\n", d, $1}' "$I1" "$I2" 2>/dev/null \
        | sort -rn | head -n "$TOPN")
    if [ -n "$wtop" ]; then
        printf '%s\n' "$wtop" | while read -r b pid; do
            [ -n "${pid:-}" ] || continue
            rate=$(awk -v b="$b" 'BEGIN{if(b>=1048576) printf "%.2fMB/s", b/1048576;
                                  else if(b>=1024) printf "%.1fKB/s", b/1024;
                                  else printf "%dB/s", b}')
            cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-90)
            [ -n "$cmd" ] || cmd="[$(cat "/proc/$pid/comm" 2>/dev/null)]"
            printf '  %-9s %-10s %s\n' "$pid" "$rate" "$cmd" >> "$LOG"
        done
    else
        echo "  (本轮无显著写入)" >> "$LOG"
    fi

    # 瞬时 CPU TOP（排除监控脚本自身）
    {
        echo "瞬时 CPU TOP${TOPN} (CPU% 单核口径):"
        printf '  %-9s %-9s %-8s %-9s %s\n' PID PPID CPU% RSS CMD
    } >> "$LOG"
    awk -v me="$$" 'NR==FNR{c[$1]=$3; next}
         {if($1 in c && $1+0 != me+0){d=$3-c[$1]; if(d>0) printf "%d %s %s\n", d, $1, $2}}' \
        "$P1" "$P2" | sort -rn | head -n "$TOPN" | while read -r d pid ppid; do
            [ -n "${pid:-}" ] || continue
            pct=$(awk -v d="$d" -v hz="$HZ" -v dt="$wall" 'BEGIN{printf "%.1f", d*100/(hz*dt)}')
            rss_p=$(awk '{print $2; exit}' "/proc/$pid/statm" 2>/dev/null)
            rss=$(awk -v p="${rss_p:-0}" -v pg="$PAGE" 'BEGIN{printf "%.1fM", p*pg/1048576}')
            cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-300)
            [ -n "$cmd" ] || cmd="[$(cat "/proc/$pid/comm" 2>/dev/null)]"
            printf '  %-9s %-9s %-8s %-9s %s\n' "$pid" "$ppid" "$pct" "$rss" "$cmd" >> "$LOG"
        done

    if [ "$PS_EXTRA" = 1 ]; then
        psout=$(ps -eo pid,ppid,stat,pcpu,pmem,rss,etime,args --sort=-pcpu 2>/dev/null \
                | sed '/ps -eo pid,ppid,stat,pcpu/d' | head -n $((TOPN + 1)))
        if [ -n "${psout:-}" ]; then
            {
                echo "ps 视图（进程生命期平均 CPU，互补参考）:"
                printf '%s\n' "$psout" | sed 's/^/  /'
            } >> "$LOG"
        fi
    fi
}

# ---- 主循环 -------------------------------------------------------------
cpu_snap "$C1"; proc_snap "$P1"; io_snap "$I1"; up_snap "$U1"
last_hit=0

echo "### cpu-watch 启动 $(date '+%Y-%m-%d %H:%M:%S') pid=$$ ncpu=$NCPU tmp=$TMPD th=${TH}% load_th=${LOAD_TH} io_th=${IO_TH}% percpu_th=${PERCORE_TH:-off} int=${INT}s cooldown=${COOLDOWN}s topn=${TOPN} log=$LOG" >> "$LOG"

while :; do
    sleep "$INT"

    if [ ! -r /proc/stat ]; then
        echo "### $(date '+%Y-%m-%d %H:%M:%S') 读不到 /proc/stat，退出" >> "$LOG"
        break
    fi

    cpu_snap "$C2"; proc_snap "$P2"; io_snap "$I2"; up_snap "$U2"

    wall=$(wall_dt "$U1" "$U2")
    case "$wall" in ''|*[!0-9.]*) wall="$INT" ;; esac

    usage=$(cpu_usage "$C1" "$C2")
    case "$usage" in ''|*[!0-9]*) usage=0 ;; esac
    pc=$(percpu_str "$C1" "$C2")
    read -r load1 load5 load15 _ < /proc/loadavg 2>/dev/null || { load1=0; load5=0; load15=0; }
    io_full=$(psi_io_full)

    reason=""
    if [ "$TH" != 0 ] && [ "$usage" -ge "$TH" ]; then
        reason="cpu=${usage}%>=${TH}%"
    fi
    if [ -z "$reason" ] && [ "$LOAD_TH" != 0 ] && gt "$load1" "$LOAD_TH"; then
        reason="load1=${load1}>${LOAD_TH}"
    fi
    if [ -z "$reason" ] && [ "$IO_TH" != 0 ] && gt "$io_full" "$IO_TH"; then
        reason="io_full_avg10=${io_full}%>${IO_TH}%"
    fi
    if [ -z "$reason" ] && [ -n "$PERCORE_TH" ]; then
        for u in $pc; do
            v=${u#*:}
            case "$v" in ''|*[!0-9]*) continue ;; esac
            if [ "$v" -ge "$PERCORE_TH" ]; then reason="percpu_${u%:*}=${v}%>=${PERCORE_TH}%"; break; fi
        done
    fi

    if [ -n "$reason" ]; then
        now=$(date +%s)
        if [ $((now - last_hit)) -ge "$COOLDOWN" ]; then
            last_hit=$now
            rotate
            dump_snapshot
        fi
    fi

    mv -f "$C2" "$C1" 2>/dev/null || cp -f "$C2" "$C1"
    mv -f "$P2" "$P1" 2>/dev/null || cp -f "$P2" "$P1"
    mv -f "$I2" "$I1" 2>/dev/null || cp -f "$I2" "$I1"
    mv -f "$U2" "$U1" 2>/dev/null || cp -f "$U2" "$U1"
done
