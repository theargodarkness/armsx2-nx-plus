#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0+
"""Turn the module offsets of a Switch profile report into function names.

The Switch profiler reports C++ samples as bare module offsets (m:4aaf60). An NRO
is linked at address 0, so those offsets are ELF addresses of the build that
produced the report. This reads the offsets file made from a report, an `nm -nC`
listing and a flat binary image of the same build, and prints per-thread totals.

usage: symbolize_profile.py offsets.txt nm.txt image.bin
"""

import bisect
import collections
import struct
import sys


def load_symbols(path):
    addrs, names = [], []
    for line in open(path, errors="replace"):
        parts = line.rstrip("\n").split(" ", 2)
        if len(parts) < 3 or parts[1] not in "tTwW":
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        if addrs and addrs[-1] == addr:
            continue
        addrs.append(addr)
        names.append(parts[2])
    return addrs, names


def main():
    offsets_path, nm_path, image_path = sys.argv[1:4]
    addrs, names = load_symbols(nm_path)
    image = open(image_path, "rb").read()

    def lookup(off):
        i = bisect.bisect_right(addrs, off) - 1
        if i < 0:
            return "?"
        name = names[i]
        return name if len(name) <= 150 else name[:147] + "..."

    total = 1
    thread_names = {}
    self_counts = collections.defaultdict(collections.Counter)
    pair_counts = collections.defaultdict(collections.Counter)
    blocked = collections.defaultdict(collections.Counter)
    link_offsets = set()

    for line in open(offsets_path):
        f = line.split()
        if not f:
            continue
        if f[0] == "#":
            if len(f) >= 3 and f[1] == "total":
                total = int(f[2])
            elif len(f) >= 4 and f[1] == "thread":
                thread_names[int(f[2])] = " ".join(f[3:])
            continue
        thread, count, pc = int(f[1]), int(f[2]), int(f[3], 16)
        if f[0] == "S":
            self_counts[thread][lookup(pc)] += count
        elif f[0] == "K":
            lr = None if f[4] == "-" else int(f[4], 16)
            if lr is not None:
                link_offsets.add(lr)
            caller = lookup(lr) if lr is not None else "-"
            if f[5] == "run":
                pair_counts[thread][(lookup(pc), caller)] += count
            else:
                blocked[thread][(f[5], caller)] += count

    # A link register value should follow a BL or BLR. If most do not, this ELF is
    # not laid out like the build the report came from and the names are wrong.
    good = checked = 0
    for lr in sorted(link_offsets):
        if lr < 4 or lr > len(image):
            continue
        (insn,) = struct.unpack_from("<I", image, lr - 4)
        checked += 1
        if (insn & 0xFC000000) == 0x94000000 or (insn & 0xFFFFFC1F) == 0xD63F0000:
            good += 1
    print(f"layout check: {good} of {checked} link-register offsets follow a call instruction")
    print(f"symbols: {len(addrs)}, image bytes: {len(image):#x}")

    for thread in sorted(self_counts):
        name = thread_names.get(thread, str(thread))
        counts = self_counts[thread]
        running = sum(counts.values())
        print(f"\n=== {name}: self time by function ({running} C++ samples of {total}) ===")
        for fn, count in counts.most_common(70):
            print(f"{100.0 * count / total:6.2f}%  {count:6d}  {fn}")
        if pair_counts[thread]:
            print(f"\n--- {name}: leaf <- link register, top stacks only ---")
            for (fn, caller), count in pair_counts[thread].most_common(45):
                print(f"{100.0 * count / total:6.2f}%  {count:6d}  {fn}  <-  {caller}")
        if blocked[thread]:
            print(f"\n--- {name}: blocked in the kernel, by caller ---")
            for (svc, caller), count in blocked[thread].most_common(12):
                print(f"{100.0 * count / total:6.2f}%  {count:6d}  {svc}  <-  {caller}")


if __name__ == "__main__":
    main()
