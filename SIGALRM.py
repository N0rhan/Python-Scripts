# CODE
import os
import signal
import time

def send_signal(pid):
    os.kill(pid, signal.SIGABRT)

print("Program started count down")
counter = 20

while counter > 0:
    counter -= 1
    time.sleep(1)
send_signal(pid)
print("Time out! Application terminated.")
