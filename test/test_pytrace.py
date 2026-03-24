#!/usr/bin/env python3
"""Simple test program for pytrace tracing. Has a known call tree."""
import time
import os
import threading

def inner():
    total = 0
    for i in range(100):
        total += i
    return total

def middle():
    result = 0
    for _ in range(10):
        result += inner()
    return result

def outer():
    for _ in range(5):
        middle()
        time.sleep(0.05)

def worker_inner():
    total = 0
    for i in range(100):
        total += i
    return total

def worker_task(name):
    while True:
        for _ in range(10):
            worker_inner()
        time.sleep(0.05)

if __name__ == "__main__":
    for i in range(3):
        t = threading.Thread(target=worker_task, args=(f"worker-{i}",), daemon=True)
        t.start()
    print(f"PID: {os.getpid()}", flush=True)
    while True:
        outer()
