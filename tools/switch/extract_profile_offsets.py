#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0+
"""Pull the module offsets out of a Switch profiler report.

usage: extract_profile_offsets.py profile-....txt > profile-offsets.txt

The output feeds symbolize_profile.py, which needs an ELF of the same build.
"""

import re
import sys


def main():
    path = sys.argv[1]
    out, names = [], {}
    thread = mode = None
    total = 0
    build = "?"
    for line in open(path, errors="replace"):
        line = line.rstrip("\n")
        m = re.match(r"build \S+ \((\w+)\)", line)
        if m:
            build = m.group(1)
        m = re.match(r"== Thread T(\d+): (.*) ==", line)
        if m:
            thread, mode = int(m.group(1)), None
            names[thread] = m.group(2)
            continue
        m = re.match(r"Where it was \((\d+) samples\)", line)
        if m:
            total = int(m.group(1))
        if line.startswith("Self PCs while running"):
            mode = "S"
            continue
        if line.startswith("Stacks ("):
            mode = "K"
            continue
        if line and not line.startswith(" "):
            mode = None
        if thread is None or mode is None:
            continue
        if mode == "S":
            m = re.match(r"\s+[\d.]+%\s+(\d+)\s+m:([0-9a-f]+)$", line)
            if m:
                out.append(f"S {thread} {m.group(1)} {m.group(2)}")
        else:
            m = re.match(r"\s+(\d+) (run|svc:[0-9a-f]+) m:([0-9a-f]+)(?: Lm:([0-9a-f]+))?", line)
            if m:
                out.append(f"K {thread} {m.group(1)} {m.group(3)} {m.group(4) or '-'} {m.group(2)}")
    print(f"# Module offsets from {path.rsplit('/', 1)[-1]} (build {build}).")
    print(f"# total {total}")
    for index, name in names.items():
        print(f"# thread {index} {name}")
    print("\n".join(out))


if __name__ == "__main__":
    main()
