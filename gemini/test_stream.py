import time
import os

pipe_path = "/sys/kernel/debug/vma_tracker/data"

print(f"{'EVENT':<5} | {'PID':<6} | {'START_ADDR':<14} | {'END_ADDR':<14} | {'PERM':<4} | {'FILE'}")
print("-" * 80)

try:
    while True:
        if os.path.exists(pipe_path):
            with open(pipe_path, "r") as f:
                # 循环读取所有可用的行
                for line in f:
                    clean_line = line.strip()
                    if clean_line:
                        print(f"Captured: {clean_line}")
        time.sleep(0.01) # 极高频率扫描，确保实时感
except KeyboardInterrupt:
    print("\nStop.")