"""Render the two benchmark graphs from saved measurements, plus a case-level CSV."""
import argparse
import csv
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

NAMES = {
    "action_substitution": "Action substitution",
    "scope_manipulation": "Scope manipulation",
    "input_integrity": "Input integrity",
    "policy_gates": "Existing policy gates",
    "evidence_freshness": "Evidence freshness*",
    "approval_authenticity": "Approval authenticity*",
    "evidence_authenticity": "Evidence authenticity*",
}
COLORS = {"baseline": "#98614D", "repaired": "#24665C"}


def load_comparison(directory):
    results = {name: json.loads((directory / f"{name}.json").read_text()) for name in COLORS}
    before, after = results.values()
    for result in results.values():
        if result["summary"]["measurement_errors"] or not result["complete_corpus"]:
            raise ValueError("cannot render headline rates from incomplete or erroneous measurements")
    for key in ("corpus_sha256", "runner_sha256", "clock"):
        if before[key] != after[key]:
            raise ValueError(f"comparison mismatch: {key}")
    if before["target"]["policy_sha256"] != after["target"]["policy_sha256"]:
        raise ValueError("comparison uses different policies")
    if [(x["id"], x["input_sha256"]) for x in before["cases"]] != [(x["id"], x["input_sha256"]) for x in after["cases"]]:
        raise ValueError("comparison uses different inputs")
    return results


def render(directory, png_dir=None):
    results = load_comparison(directory)
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9,
                         "text.color": "#172A3A", "axes.labelcolor": "#44545E",
                         "svg.hashsalt": "cerberus-guardian-benchmark-v1"})
    names = list(NAMES)
    families = {name: {row["family"]: row for row in result["summary"]["families"] if row["kind"] == "unsafe"}
                for name, result in results.items()}
    fig = plt.figure(figsize=(6.5, 3.9), facecolor="white")
    ax = fig.add_axes([.34, .19, .54, .66])
    for series, offset, marker in [("baseline", -.19, "s"), ("repaired", .19, "o")]:
        for y, family in enumerate(names):
            row = families[series][family]
            value = 100 * row["violations"] / row["cases"]
            ax.scatter(value, y + offset, color=COLORS[series], marker=marker, s=38, zorder=3)
            ax.annotate(f"{row['violations']}/{row['cases']}", (value, y + offset),
                        xytext=(7 if value < 90 else -7, 0), textcoords="offset points",
                        ha="left" if value < 90 else "right", va="center", color=COLORS[series], fontsize=8)
    for y, family in enumerate(names):
        values = [100 * families[series][family]["violations"] / families[series][family]["cases"] for series in COLORS]
        ax.plot(values, [y-.19, y+.19], color="#BFC9CD", linewidth=1, zorder=1)
    ax.axhline(3.5, color="#CCD4D8", linewidth=.8)
    ax.set_yticks(range(len(names)), [NAMES[name] for name in names])
    ax.set_ylim(len(names)-.5, -.5)
    ax.set_xlim(-3, 103)
    ax.set_xticks([0,25,50,75,100], ["0%","25%","50%","75%","100%"])
    ax.set_xlabel("Unsafe requests receiving a valid token\nLower is better", fontsize=9, labelpad=9)
    ax.grid(axis="x", color="#E5EAED", linewidth=.7)
    ax.tick_params(length=0, pad=6)
    for spine in ax.spines.values(): spine.set_visible(False)
    handles = [Line2D([],[],marker=marker,linestyle="",color=COLORS[name],label=label)
               for name,marker,label in [("baseline","s","Baseline ac22a922"),("repaired","o","Repaired 651bd4a4")]]
    fig.legend(handles=handles, loc="upper left", bbox_to_anchor=(.32,1.0), ncol=2, frameon=False, fontsize=8.5)
    fig.text(.02,.012,"* Additional assurance requirements; raw-envelope boundary, no trusted upstream authenticator.",fontsize=7.5,color="#55636D")
    save(fig, directory, png_dir, "unauthorized-approvals")

    fig = plt.figure(figsize=(6.5,3.6), facecolor="white")
    ax = fig.add_axes([.13,.23,.81,.66])
    points = {}
    for series, result in results.items():
        unsafe = result["summary"]["unsafe_authorization"]
        eligible = result["summary"]["eligible_response_success"]
        x,y = 100*unsafe["rate"],100*eligible["rate"]
        points[series] = (x,y)
        ax.scatter(x,y,color=COLORS[series],s=80,marker="s" if series=="baseline" else "o",zorder=3)
        label = ("Baseline" if series=="baseline" else "Repaired") + f"\n{unsafe['numerator']}/{unsafe['denominator']} unsafe approvals\n{eligible['numerator']}/{eligible['denominator']} eligible responses"
        ax.annotate(label,(x,y),xytext=(0,-18),textcoords="offset points",ha="center",va="top",fontsize=8.5,color=COLORS[series])
    before,after = points["baseline"],points["repaired"]
    ax.annotate("",xy=(after[0]+3,after[1]),xytext=(before[0]-3,before[1]),
                arrowprops={"arrowstyle":"->","color":"#7A8B92","linewidth":1})
    ax.set_xlim(0,100);ax.set_ylim(0,110)
    ax.set_xticks([0,25,50,75,100],["0%","25%","50%","75%","100%"])
    ax.set_yticks([0,25,50,75,100],["0%","25%","50%","75%","100%"])
    ax.set_xlabel("Unsafe authorization rate on the 33 selected requests\nLower is better",fontsize=9,labelpad=9)
    ax.set_ylabel("Eligible signed-response success\nHigher is better",fontsize=9,labelpad=8)
    ax.grid(color="#E5EAED",linewidth=.7);ax.set_axisbelow(True)
    ax.spines[["top","right"]].set_visible(False)
    for side in ["left","bottom"]: ax.spines[side].set_color("#CBD4D8")
    ax.tick_params(length=0,pad=6)
    fig.text(.13,.012,"Exact corpus fractions, not real-world probabilities. Eight eligible controls per version.",fontsize=8,color="#55636D")
    save(fig, directory, png_dir, "utility-vs-unsafe-authorization")

    columns=["version","target_commit","id","family","kind","basis","expected","outcome","token_valid",
             "unauthorized_approval","unauthorized_receipt","simulated_receipts","expected_met","measurement_valid","description"]
    with (directory/"case-results.csv").open("w",newline="",encoding="utf-8") as stream:
        writer=csv.DictWriter(stream,fieldnames=columns,lineterminator="\n");writer.writeheader()
        for name,result in results.items():
            for case in result["cases"]:
                row={key:case.get(key) for key in columns}
                row.update(version=name,target_commit=result["target"]["commit"])
                writer.writerow(row)


def save(fig, directory, png_dir, name):
    svg_path = directory/f"{name}.svg"
    fig.savefig(svg_path,metadata={"Date":None})
    svg_path.write_text("\n".join(line.rstrip() for line in svg_path.read_text().splitlines())+"\n")
    if png_dir:
        png_dir.mkdir(parents=True,exist_ok=True)
        fig.savefig(png_dir/f"{name}.png",dpi=300)
    plt.close(fig)


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results",type=Path,required=True)
    parser.add_argument("--png-dir",type=Path)
    args=parser.parse_args()
    render(args.results,args.png_dir)
    print("Rendered two graphs and case-results.csv from matching verified inputs.")
