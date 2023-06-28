# Folder text reports

import sys

hmap = {}

for line in sys.stdin:
    line = line.rstrip()
    prefix, cycles = line.rsplit(' ', 1)
    cycles = int(cycles)
    if prefix not in hmap:
        hmap[prefix] = 0
    hmap[prefix] += cycles

hmap_summary = {}
total = 0
for k, v in hmap.items():
    _, func_name = k.rsplit(':', 1)
    total += v
    if func_name not in hmap_summary:
        hmap_summary[func_name] = 0
    else:
        hmap_summary[func_name] += v

print("total cycles: %.1f M " % (float(total)/1024/1024))

index = 0
for (k,v) in sorted(hmap_summary.items(), key=lambda x: x[1], reverse=True):
    percent = int(v*100/total)
    print("%s: %d %%" % (k, percent))
    index += 1
    if index > 9:
        break
