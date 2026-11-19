#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0+
"""Turn the module offsets of a Switch profile report into function names.

The Switch profiler reports C++ samples as bare module offsets (m:4aaf60). An NRO
is linked at address 0, so those offsets are ELF addresses of the build that
produced the report. This reads the offsets file made from a report, an `nm -nC`
listing and a flat binary image of the same build, and prints per-thread totals.

usage: symbolize_profile.py offsets.txt nm.txt image.bin [elf addr2line]

With an ELF that carries debug info (same code, built with -g) and the toolchain's
addr2line, the hottest addresses are also resolved to source lines, inlining included.
"""

import bisect
import collections
import struct
import subprocess
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


def resolve_lines(elf, addr2line, pcs):
    """Map each pc to its inline chain, innermost first: [(function, file:line), ...]."""
    if not pcs:
        return {}
    out = subprocess.run([addr2line, "-e", elf, "-a", "-f", "-i", "-C"] + [f"{pc:#x}" for pc in pcs],
        capture_output=True, text=True, check=True).stdout.splitlines()
    chains, current, i = {}, None, 0
    while i < len(out):
        line = out[i]
        if line.startswith("0x"):
            current = int(line, 16)
            chains[current] = []
            i += 1
            continue
        if current is not None and i + 1 < len(out):
            where = out[i + 1].split(" (discriminator")[0]
            parts = where.rsplit("/", 2)
            chains[current].append((line, "/".join(parts[-2:]) if len(parts) > 2 else where))
        i += 2
    return chains


def short(name, limit=90):
    return name if len(name) <= limit else name[: limit - 3] + "..."


def main():
    offsets_path, nm_path, image_path = sys.argv[1:4]
    elf, addr2line = (sys.argv[4], sys.argv[5]) if len(sys.argv) >= 6 else (None, None)
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
    pc_counts = collections.defaultdict(collections.Counter)
    pair_counts = collections.defaultdict(collections.Counter)
    blocked = collections.defaultdict(collections.Counter)
    link_offsets = set()
    extra = []  # X <label> <offset>: single addresses to resolve, such as a crash pc

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
        if f[0] == "X":
            extra.append((f[1], int(f[2], 16)))
            continue
        thread, count, pc = int(f[1]), int(f[2]), int(f[3], 16)
        if f[0] == "S":
            self_counts[thread][lookup(pc)] += count
            pc_counts[thread][pc] += count
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

    if extra:
        chains = resolve_lines(elf, addr2line, [pc for _, pc in extra]) if elf else {}
        print("\n=== Single addresses ===")
        for label, pc in extra:
            print(f"{label} m:{pc:x}  {lookup(pc)}")
            for fn, at in chains.get(pc, []):
                print(f"      {at}  {short(fn, 110)}")

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
        if elf and running >= total // 20:
            top = [pc for pc, _ in pc_counts[thread].most_common(1500)]
            chains = resolve_lines(elf, addr2line, top)
            by_line = collections.Counter()
            by_inline = collections.Counter()
            covered = 0
            for pc in top:
                chain = chains.get(pc) or []
                if not chain:
                    continue
                count = pc_counts[thread][pc]
                covered += count
                inner_fn, inner_at = chain[0]
                outer_fn = chain[-1][0]
                by_line[(inner_at, inner_fn)] += count
                by_inline[(outer_fn, inner_fn)] += count
            print(f"\n--- {name}: self time by inlined function, as outer <= inner ({covered} samples resolved) ---")
            for (outer_fn, inner_fn), count in by_inline.most_common(60):
                inner = "(own code)" if inner_fn == outer_fn else short(inner_fn)
                print(f"{100.0 * count / total:6.2f}%  {count:6d}  {short(outer_fn, 60)}  <=  {inner}")
            print(f"\n--- {name}: self time by source line ---")
            for (at, fn), count in by_line.most_common(70):
                print(f"{100.0 * count / total:6.2f}%  {count:6d}  {at}  {short(fn, 70)}")


if __name__ == "__main__":
    main()
