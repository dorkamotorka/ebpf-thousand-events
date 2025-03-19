import os
import time
import argparse
import threading

def generate_syscalls(rate):
    """
    Generate syscalls at the specified rate (calls per second) in a loop.
    """
    interval = 1.0 / rate  # Time interval between syscalls
    syscall_count = 0

    try:
        while True:
            os.getpid()  # Example syscall: Get process ID
            syscall_count += 1

            time.sleep(interval)  # Control execution rate
    except KeyboardInterrupt:
        print(f"\nThread {threading.current_thread().name} stopped after executing {syscall_count} syscalls.")

def spawn_threads(rate, num_threads):
    """
    Spawn multiple threads, each generating syscalls at the specified rate.
    """
    threads = []

    print(f"Spawning {num_threads} threads, each generating {rate} syscalls/sec.")
    
    for i in range(num_threads):
        thread = threading.Thread(target=generate_syscalls, args=(rate,), name=f"Thread-{i+1}")
        thread.daemon = True
        thread.start()
        threads.append(thread)

    try:
        while True:
            time.sleep(1)  # Keep the main thread alive
    except KeyboardInterrupt:
        print("\nStopping all threads...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a high rate of syscalls using multiple threads.")
    parser.add_argument("rate", type=int, help="Number of syscalls per second per thread")
    parser.add_argument("threads", type=int, help="Number of threads")
    args = parser.parse_args()

    spawn_threads(args.rate, args.threads)
