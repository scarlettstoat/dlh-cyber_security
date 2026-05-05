#!/bin/bash
ps -u $1 -o user,pid,pcpu,pmem,vsz,rss,tty,stat,start,start,time,cmd --no-headers | grep -v "^\S* *\S* *\S* *\S* *0 *0"
