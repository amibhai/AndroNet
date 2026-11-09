#!/usr/bin/env python3
"""Draws the data figures from evaluation/results/. Grayscale with hatching: the printed volume is
black and white, so a series must stay identifiable without colour."""
import json
import pathlib
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
RESULTS = HERE.parent / "evaluation" / "results"

matplotlib.rcParams.update({
    "pdf.fonttype": 42,  # embed real outlines so the typesetter's checks pass
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 8.5,
    "axes.linewidth": 0.6,
    "hatch.linewidth": 0.5,
})

STAGES = [("Record building", "parse"), ("Statistics", "stats"), ("Dissection", "dpi")]


def layers(result):
    s = result["stages"]
    l1 = s["noRulesNoSigs.detect"]["meanUs"]
    l2 = max(s["noRules.detect"]["meanUs"] - l1, 0)
    l3 = max(s["full.detect"]["meanUs"] - s["noRules.detect"]["meanUs"], 0)
    return l1, l2, l3


def series(path):
    r = json.loads(pathlib.Path(path).read_text())
    s = r["stages"]
    l1, l2, l3 = layers(r)
    values = [s[f"full.{k}"]["meanUs"] for _, k in STAGES] + [l1, l2, l3, s["full.total"]["meanUs"]]
    return values


def fig_cost(baseline, current, out):
    labels = [name for name, _ in STAGES] + ["Layer 1", "Layer 2", "Layer 3", "Total"]
    old = series(baseline)
    new = series(current)
    fig, ax = plt.subplots(figsize=(4.8, 2.1))
    y = list(range(len(labels)))
    h = 0.36
    ax.barh([i - h / 2 for i in y], old, height=h, color="0.25", label="v1.3.0 (first implementation)", zorder=2)
    ax.barh([i + h / 2 for i in y], new, height=h, facecolor="white", edgecolor="0.15", hatch="/////", linewidth=0.6,
            label="v1.4.0 (corrected)", zorder=2)
    ax.set_xscale("log")
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlabel("Mean cost per packet (µs, log scale)")
    ax.grid(axis="x", which="major", color="0.85", linewidth=0.5, zorder=0)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)

    def fmt(v):
        return f"{v:,.0f}" if v >= 100 else f"{v:.0f}" if v >= 10 else f"{v:.1f}"

    for i, (a, b) in enumerate(zip(old, new)):
        ax.text(a * 1.12, i - h / 2, fmt(a), va="center", fontsize=7)
        ax.text(b * 1.12, i + h / 2, fmt(b), va="center", fontsize=7)
    ax.set_xlim(left=1, right=max(old) * 3.2)
    # Top right is the one area no bar reaches: the first two stages cost only a few microseconds
    ax.legend(frameon=False, loc="upper right", fontsize=7.5, handlelength=1.6)
    fig.tight_layout(pad=0.3)
    fig.savefig(out)
    plt.close(fig)
    print("wrote", out, "old", [round(x, 1) for x in old], "new", [round(x, 1) for x in new])


if __name__ == "__main__":
    fig_cost(sys.argv[1], sys.argv[2], HERE / "fig_cost.pdf")
