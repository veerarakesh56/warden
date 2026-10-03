"""Train WARDEN's decision component (src/warden/decide.py) on the published benchmark runs.

    python scripts/train_decider.py            # writes src/warden/data/decider.json

Data: every gradable run in docs/bench (the published bundles, so anyone can re-train and get the same file).
Label: the rubric's grade of the action against the INJECTED fault - CORRECT or not - an independent ground truth
(register E2); WARDEN's own verdicts are features, never labels. Model: logistic regression with an L2 penalty,
fitted by plain gradient descent (deterministic, no dependency). Evaluation: every fault class is held out in turn
and predicted by a model that never saw it, and the held-out predictions are scored - Brier, expected calibration
error and AUC - beside the same scores for the model's own self-reported confidence.
"""

from __future__ import annotations

import json
import math
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "src" / "warden" / "data" / "decider.json"
GRADABLE = {"CORRECT", "WRONG", "HARMFUL", "SAFE-BUT-UNHELPFUL"}
L2, STEPS, RATE = 1.0, 3000, 0.1


def examples(bundles: list[pathlib.Path]) -> list[tuple[list[float], int, str]]:
    sys.path.insert(0, str(ROOT))
    from scenarios.score import score_run_dir

    from warden.decide import FEATURES, features
    from warden.models import Alert, ContextBundle, RemediationProposal, RootCause, Verdict

    out = []
    for bundle in bundles:
        scored = score_run_dir(bundle, rubric_path=bundle / "grading" / "scoring.yaml")
        for row in scored["rows"]:
            if row["diagnosis"] not in GRADABLE:
                continue
            d = json.loads((bundle / "reports" / f"{row['scenario_id']}.{row['index']}.json").read_text(encoding="utf-8"))
            f = features(Alert(**d["alert"]), ContextBundle(**d["context"]), RootCause(**d["root_cause"]),
                         RemediationProposal(**d["proposal"]), Verdict(**d["verdict"]))
            out.append(([f[k] for k in FEATURES], int(row["diagnosis"] == "CORRECT"), row["fault_class"]))
    return out


def _standardise(xs: list[list[float]]) -> tuple[list[float], list[float]]:
    n, k = len(xs), len(xs[0])
    mean = [sum(x[j] for x in xs) / n for j in range(k)]
    scale = [math.sqrt(sum((x[j] - mean[j]) ** 2 for x in xs) / n) or 1.0 for j in range(k)]
    return mean, scale


def _sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, z))))


def fit(xs: list[list[float]], ys: list[int]) -> dict:
    mean, scale = _standardise(xs)
    zs = [[(x[j] - mean[j]) / scale[j] for j in range(len(x))] for x in xs]
    w, b, n = [0.0] * len(zs[0]), 0.0, len(zs)
    for _ in range(STEPS):
        gw, gb = [L2 * wj / n for wj in w], 0.0
        for z, y in zip(zs, ys, strict=True):
            err = _sigmoid(b + sum(wj * zj for wj, zj in zip(w, z, strict=True))) - y
            gb += err / n
            for j, zj in enumerate(z):
                gw[j] += err * zj / n
        w = [wj - RATE * g for wj, g in zip(w, gw, strict=True)]
        b -= RATE * gb
    return {"mean": mean, "scale": scale, "weights": w, "bias": b}


def _p(model: dict, x: list[float]) -> float:
    return _sigmoid(model["bias"] + sum(w * (v - m) / s for v, m, s, w in
                                        zip(x, model["mean"], model["scale"], model["weights"], strict=True)))


def brier(ps: list[float], ys: list[int]) -> float:
    return sum((p - y) ** 2 for p, y in zip(ps, ys, strict=True)) / len(ys)


def ece(ps: list[float], ys: list[int], bins: int = 10) -> float:
    total = 0.0
    for i in range(bins):
        idx = [k for k, p in enumerate(ps) if i / bins <= p < (i + 1) / bins or (i == bins - 1 and p == 1.0)]
        if idx:
            total += len(idx) / len(ps) * abs(sum(ps[k] for k in idx) / len(idx) - sum(ys[k] for k in idx) / len(idx))
    return total


def auc(ps: list[float], ys: list[int]) -> float | None:
    pos = [p for p, y in zip(ps, ys, strict=True) if y]
    neg = [p for p, y in zip(ps, ys, strict=True) if not y]
    if not pos or not neg:
        return None
    wins = sum(1.0 if a > b else 0.5 if a == b else 0.0 for a in pos for b in neg)
    return wins / (len(pos) * len(neg))


def held_out(data: list[tuple[list[float], int, str]]) -> tuple[list[float], list[int], list[float]]:
    """Each fault class predicted by a model trained without it; also the self-reported confidence beside it."""
    ps, ys, conf = [], [], []
    for group in sorted({g for _, _, g in data}):
        train = [(x, y) for x, y, g in data if g != group]
        test = [(x, y) for x, y, g in data if g == group]
        if len({y for _, y in train}) < 2:
            continue
        model = fit([x for x, _ in train], [y for _, y in train])
        for x, y in test:
            ps.append(_p(model, x))
            ys.append(y)
            conf.append(x[0])  # FEATURES[0] is the model's own confidence
    return ps, ys, conf


def render(bundles: list[pathlib.Path] | None = None) -> dict:
    from warden.decide import FEATURES

    bundles = bundles or sorted(p for p in (ROOT / "docs" / "bench").glob("wave*") if (p / "manifest.json").exists())
    data = examples(bundles)
    ys = [y for _, y, _ in data]
    ps, hys, conf = held_out(data)
    model = fit([x for x, _, _ in data], ys)
    r = 6
    return {
        "features": list(FEATURES),
        "mean": [round(v, r) for v in model["mean"]], "scale": [round(v, r) for v in model["scale"]],
        "weights": [round(v, r) for v in model["weights"]], "bias": round(model["bias"], r),
        "label_source": "rubric",
        "trained_on": {"bundles": [b.name for b in bundles], "runs": len(data), "correct": sum(ys)},
        "held_out_by_fault_class": {
            "runs": len(hys),
            "brier": round(brier(ps, hys), 4), "ece": round(ece(ps, hys), 4), "auc": round(auc(ps, hys) or 0, 4),
            "self_reported_confidence": {"brier": round(brier(conf, hys), 4), "ece": round(ece(conf, hys), 4),
                                         "auc": round(auc(conf, hys) or 0, 4)},
            "base_rate_brier": round(brier([sum(hys) / len(hys)] * len(hys), hys), 4),
        },
    }


def main() -> None:
    sys.path.insert(0, str(ROOT / "src"))
    doc = render()
    OUT.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({k: doc[k] for k in ("trained_on", "held_out_by_fault_class")}, indent=2))


if __name__ == "__main__":
    main()
