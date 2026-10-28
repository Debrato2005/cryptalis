# /// script
# requires-python = ">=3.12"
# dependencies = ["matplotlib>=3.6,<4"]
# ///
"""Render recorded performance evidence, without running a new benchmark.

Usage: uv run scripts/render_performance.py
Matplotlib is a script-only dependency; the runtime package does not need it.
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
from matplotlib import pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
RECEIPTS = (
    "performance-current-20261023.json",
    "performance-100k-20261023.json",
    "performance-million-prepared-20261023.json",
)
COLORS = ("#52677D", "#087F8C")


def load():
    records = [json.loads((ROOT / "docs/_reset" / name).read_text()) for name in RECEIPTS]
    for record in records:
        if (not record["data"]["native_and_attached_results_equal"]
                or not record["source_stability"]["unchanged"]):
            raise ValueError("Performance evidence lacks equal results or stable source.")
        for workload in ("point", "equality", "in20"):
            result = record["whole_path"][workload]
            if min(result["native_p95_ms"], result["attached_p95_ms"]) < 0:
                raise ValueError("Latency must be nonnegative.")
            if abs(result["attached_p95_ms"] - result["native_p95_ms"]
                   - result["added_p95_ms"]) > 0.0002:
                raise ValueError("Recorded added p95 disagrees with the measured paths.")
        if any(part["isolated_column_and_index_bytes"] <= 0
               for part in record["storage_native_attached"]):
            raise ValueError("Storage evidence must contain a positive baseline.")
    return records


def save(figure, destination):
    figure.savefig(destination, metadata={"Date": None}, bbox_inches="tight")
    plt.close(figure)


def main():
    records = load()
    output = ROOT / "docs/images"
    output.mkdir(exist_ok=True)
    plt.rcParams.update({"font.size": 11, "svg.fonttype": "none", "svg.hashsalt": "cryptalis",
                         "axes.spines.top": False, "axes.spines.right": False})
    labels = [f'{record["data"]["rows_each"]:,}' for record in records]
    figure, axes = plt.subplots(1, 3, figsize=(12, 4.2), layout="constrained", sharey=True)
    for axis, workload, title in zip(axes, ("point", "equality", "in20"),
                                     ("Point read", "Equality", "IN with 20 values")):
        for offset, key, color, label in (
                (-0.19, "native_p95_ms", COLORS[0], "Native"),
                (0.19, "attached_p95_ms", COLORS[1], "Protected")):
            values = [record["whole_path"][workload][key] for record in records]
            bars = axis.bar([x + offset for x in range(3)], values, width=0.36,
                            color=color, label=label)
            axis.bar_label(bars, fmt="%.2f", padding=3, fontsize=9)
        axis.set(title=title, xticks=range(3), xticklabels=labels, xlabel="Rows per application")
        axis.grid(axis="y", alpha=0.18)
        axis.set_axisbelow(True)
        axis.set_ylim(0, 7.5)
    axes[0].set_ylabel("P95 latency in milliseconds; lower is better")
    axes[0].legend(frameon=False)
    figure.suptitle("Recorded warm TEXT reads: native and protected", fontsize=15)
    save(figure, output / "read-latency.svg")

    figure, axis = plt.subplots(figsize=(9, 4), layout="constrained")
    ratios = [record["storage_native_attached"][1]["isolated_column_and_index_bytes"]
              / record["storage_native_attached"][0]["isolated_column_and_index_bytes"]
              for record in records]
    bars = axis.bar(labels, ratios, color=COLORS[1], width=0.5)
    axis.bar_label(bars, labels=[f"{value:.3f}×" for value in ratios], padding=5)
    axis.axhline(1, color=COLORS[0], label="Native baseline: 1×")
    axis.axhline(2, color="#9B4C22", linestyle="--", label="Local storage target: at most 2×")
    axis.set(title="Recorded protected column + equality index storage",
             xlabel="Rows per application", ylabel="Protected bytes / native bytes", ylim=(0, 2.5))
    axis.legend(frameon=False, loc="upper right")
    axis.grid(axis="y", alpha=0.18)
    axis.set_axisbelow(True)
    save(figure, output / "indexed-storage.svg")


if __name__ == "__main__":
    main()
