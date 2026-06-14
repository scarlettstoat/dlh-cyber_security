#!/bin/bash
sudo iptables -A INPUT -p tcp --dport ssh -j ACCEPT
sudo iptables -P INPUT DROP
