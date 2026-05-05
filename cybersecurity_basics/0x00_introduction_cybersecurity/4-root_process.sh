#!/bin/bash
ps aux | grep $1 | grep -v "^\S* *\S* *\S* *\S* *0 *0"
