#!/bin/bash
ps aux | grep -v "^\S* *\S* *\S* *\S* *0 *0" | grep "^$1"
