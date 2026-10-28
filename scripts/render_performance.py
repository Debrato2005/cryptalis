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
    destination.write_text("".join(line.rstrip() + "\n" for line in destination.read_text().splitlines()))
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

    comparison = json.loads((ROOT / "docs/_reset/admission-lineage-20261028.json").read_text())
    figure, axes = plt.subplots(1, 2, figsize=(11, 4), layout="constrained")
    for axis, workload, title in zip(axes, ("public_projection", "first_protected"),
                                     ("Wide public projection", "Early protected match")):
        for offset, name, color, label in (
                (-0.19, "baseline", COLORS[0], "Target branch"),
                (0.19, "candidate", COLORS[1], "Candidate")):
            values = [comparison["cases"][str(count)][workload][name]["median_us"]
                      for count in (1, 8, 32)]
            bars = axis.bar([x + offset for x in range(3)], values, width=0.36,
                            color=color, label=label)
            axis.bar_label(bars, fmt="%.2f", padding=3, fontsize=9)
        axis.set(title=title, xticks=range(3), xticklabels=("1", "8", "32"),
                 xlabel="Protected fields in the mapping", ylabel="Median microseconds per inspection")
        axis.margins(y=0.22)
        axis.grid(axis="y", alpha=0.18)
        axis.set_axisbelow(True)
    axes[0].legend(frameon=False)
    figure.suptitle("Local query-inspection microbenchmark: speedup and trade-off", fontsize=14)
    save(figure, output / "lineage-inspection.svg")

    counts = json.loads((ROOT / "docs/_reset/count-performance-20261028.json").read_text())
    figure, axes = plt.subplots(1, 2, figsize=(10, 4), layout="constrained", sharey=True)
    for axis, workload, title in zip(axes, ("nonnull", "distinct"),
                                     ("COUNT of non-NULL names", "COUNT of distinct names")):
        results = [entry for entry in counts["observations"] if entry["workload"] == workload]
        for offset, name, color in ((-0.19, "native", COLORS[0]), (0.19, "protected", COLORS[1])):
            values = [entry["paths"][name]["p95_ms"] for entry in results]
            bars = axis.bar([x + offset for x in range(len(results))], values, width=0.36,
                            color=color, label=name.capitalize())
            axis.bar_label(bars, fmt="%.2f", padding=3, fontsize=9)
        axis.set(title=title, xticks=range(len(results)),
                 xticklabels=[f'{entry["rows"]:,}' for entry in results], xlabel="Rows per application")
        axis.grid(axis="y", alpha=0.18)
        axis.set_axisbelow(True)
        axis.margins(y=0.2)
    axes[0].set_ylabel("P95 milliseconds; lower is better")
    axes[0].legend(frameon=False)
    figure.suptitle("Local count queries: 31 alternating warm samples per path", fontsize=14)
    save(figure, output / "count-latency.svg")

    scalars = [json.loads((ROOT / f'docs/_reset/scalar-cost-{name}-20261028.json').read_text())
               for name in ('int16', 'int32', 'int64', 'date')]
    figure, axes = plt.subplots(1, 2, figsize=(12, 4.4), layout="constrained")
    labels = ('int2', 'int4', 'int8', 'Date')
    for offset, workload, color, label in ((-.19, 'point_scalar', COLORS[0], 'Scalar result'),
                                          (.19, 'point_entities', COLORS[1], 'Full entity')):
        bars = axes[0].bar([x + offset for x in range(4)],
                          [record['whole_path'][workload]['added_p95_ms'] for record in scalars],
                          width=.36, color=color, label=label)
        axes[0].bar_label(bars, fmt='%.2f', padding=3, fontsize=9)
    axes[0].axhline(3, linestyle='--', color='#9B4C22', label='Local added-p95 target')
    axes[0].set(title='Point-read cost above native', ylabel='Added p95 milliseconds', ylim=(0, 3.6))
    axes[0].legend(frameon=True, facecolor='white', edgecolor='none', framealpha=1, fontsize=9)
    bars = axes[1].bar(range(4), [record['isolated_column_ratio'] for record in scalars], color=COLORS[1])
    axes[1].bar_label(bars, fmt='%.2f×', padding=3)
    axes[1].axhline(1, color=COLORS[0], label='Native column: 1×')
    axes[1].set(title='Storage-only column cost', ylabel='Protected / native column bytes', ylim=(0, 26))
    axes[1].legend(frameon=False)
    for axis in axes:
        axis.set(xticks=range(4), xticklabels=labels)
        axis.grid(axis='y', alpha=.18)
        axis.set_axisbelow(True)
    figure.suptitle('Local scalar costs: 10,000 rows and 100 alternating warm pairs', fontsize=14)
    figure.text(.02, -.04, 'One Date scalar sample reached 65.41 ms. Raw samples retain every observation. '
                'These columns have no equality index.', fontsize=9)
    save(figure, output / 'scalar-costs.svg')


if __name__ == "__main__":
    main()
