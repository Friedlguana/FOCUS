"""``focus models`` - inspect, evaluate and retrain the traffic models."""

from __future__ import annotations

import argparse
import json
import time
import warnings
from pathlib import Path

from rich.text import Text

from focus import theme
from focus.core.paths import INBOUND_MODEL, OUTBOUND_MODEL, TRAFFIC_CSV

from .base import Command

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")


def _joblib():
    import joblib

    return joblib


def _heavy():
    """Import the model stack lazily.

    Every CLI invocation used to pay ~2.5 s for scikit-learn and ~1 s for
    pandas just to print ``focus --help``. Those imports now happen only when
    a model command actually needs them.
    """
    import joblib
    import pandas as pd
    from sklearn.ensemble import RandomForestRegressor
    from sklearn.metrics import mean_absolute_error, r2_score

    return joblib, pd, RandomForestRegressor, mean_absolute_error, r2_score


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--train", action="store_true", help="retrain both models from the CSV")
    parser.add_argument("--predict", type=int, metavar="N", help="predict the sample at elapsed N")
    parser.add_argument("--csv", type=Path, default=TRAFFIC_CSV, help="training data")
    parser.add_argument("--json", action="store_true", help="machine-readable output")


def _load(path: Path):
    joblib = _joblib()
    try:
        return joblib.load(path)
    except Exception as error:  # noqa: BLE001 - corrupt/missing artifacts are expected
        return error


def _describe(name: str, path: Path, model) -> dict:
    info = {
        "name": name,
        "file": path.name,
        "present": path.exists(),
        "size": path.stat().st_size if path.exists() else 0,
        "loaded": not isinstance(model, Exception),
        "error": "",
        "type": "—",
        "trees": 0,
        "features": "—",
        "mae": None,
        "r2": None,
    }
    if isinstance(model, Exception):
        info["error"] = str(model)
        return info

    info["type"] = type(model).__name__
    if info["type"] == "RandomForestRegressor":
        info["type"] = "random forest"
    info["trees"] = getattr(model, "n_estimators", 0)
    features = getattr(model, "feature_names_in_", None)
    if features is not None:
        info["features"] = ", ".join(str(feature) for feature in features)
    return info


def _evaluate(model, frame, target) -> tuple[float, float]:
    _, _, _, mean_absolute_error, r2_score = _heavy()
    predictions = model.predict(frame)
    return float(mean_absolute_error(target, predictions)), float(r2_score(target, predictions))


def _train(csv_path: Path) -> tuple[list[dict], float]:
    joblib, pd, RandomForestRegressor, _, _ = _heavy()
    data = pd.read_csv(csv_path)
    missing = {"elapsed_time", "inbound_data", "outbound_data"} - set(data.columns)
    if missing:
        raise ValueError(f"missing columns: {', '.join(sorted(missing))}")
    if len(data) < 10:
        raise ValueError("need at least 10 samples to train")

    frame = data[["elapsed_time"]]
    split = max(1, int(len(data) * 0.8))
    started = time.perf_counter()
    results = []

    for name, target_column, path in (
        ("inbound", "inbound_data", INBOUND_MODEL),
        ("outbound", "outbound_data", OUTBOUND_MODEL),
    ):
        target = data[target_column]
        holdout = RandomForestRegressor(random_state=42, n_jobs=-1)
        holdout.fit(frame.iloc[:split], target.iloc[:split])
        mae, r2 = _evaluate(holdout, frame.iloc[split:], target.iloc[split:])

        final = RandomForestRegressor(random_state=42, n_jobs=-1)
        final.fit(frame, target)
        joblib.dump(final, path)

        results.append({
            "name": name,
            "file": path.name,
            "samples": len(data),
            "train": split,
            "test": len(data) - split,
            "mae": round(mae, 4),
            "r2": round(r2, 4),
            "saved": str(path),
        })

    return results, time.perf_counter() - started


def run(args: argparse.Namespace) -> int:
    theme.set_json_mode(args.json)
    if args.train:
        try:
            results, elapsed = _train(args.csv)
        except (OSError, ValueError) as error:
            theme.error(f"training failed: {error}")
            return 1

        if args.json:
            print(json.dumps({"trained": results, "elapsed": round(elapsed, 3)}, indent=2))
            return 0

        theme.section("train", f"{results[0]['samples']} samples · {elapsed:.2f}s")

        table = theme.new_table()
        table.add_column("model", style=theme.TEXT)
        table.add_column("holdout", justify="right", style=theme.MUTED)
        table.add_column("mae", justify="right", style=theme.TEXT)
        table.add_column("r²", justify="right", style=theme.TEXT)
        table.add_column("saved", style=theme.MUTED)

        for result in results:
            table.add_row(
                result["name"],
                f"{result['test']} samples",
                f"{result['mae']:.3f}",
                f"{result['r2']:.3f}",
                result["file"],
            )
        theme.show_table(table)
        theme.blank()
        theme.ok("models retrained on the full log and saved")
        theme.hint("the holdout rows are a chronological split, not a shuffled split")
        return 0

    inbound = _load(INBOUND_MODEL)
    outbound = _load(OUTBOUND_MODEL)

    if args.predict is not None:
        if args.predict < 1:
            theme.error("--predict expects a positive second")
            return 2
        _, pd, _, _, _ = _heavy()
        frame = pd.DataFrame([[args.predict]], columns=["elapsed_time"])
        payload = {}
        for name, model in (("inbound", inbound), ("outbound", outbound)):
            if isinstance(model, Exception):
                payload[name] = None
                continue
            payload[name] = round(float(model.predict(frame)[0]), 4)

        if args.json:
            print(json.dumps({"elapsed": args.predict, "prediction": payload}, indent=2))
        else:
            theme.section("predict", f"elapsed {args.predict}s")
            theme.kv(
                [
                    ("inbound", f"{payload['inbound']} Mbps" if payload["inbound"] is not None else "unavailable"),
                    ("outbound", f"{payload['outbound']} Mbps" if payload["outbound"] is not None else "unavailable"),
                ]
            )
            theme.blank()
            theme.hint("the shipped models are keyed on elapsed time and are kept for compatibility")
        return 0

    info_in = _describe("inbound", INBOUND_MODEL, inbound)
    info_out = _describe("outbound", OUTBOUND_MODEL, outbound)
    rows = [info_in, info_out]

    if not args.json and not isinstance(inbound, Exception) and TRAFFIC_CSV.exists():
        try:
            pd = _heavy()[1]
            data = pd.read_csv(TRAFFIC_CSV)
            frame = data[["elapsed_time"]]
            info_in["mae"], info_in["r2"] = _evaluate(inbound, frame, data["inbound_data"])
            info_out["mae"], info_out["r2"] = _evaluate(outbound, frame, data["outbound_data"])
        except (OSError, KeyError, ValueError):
            pass

    if args.json:
        print(json.dumps(rows, indent=2))
        return 0

    theme.section("models", f"{sum(1 for row in rows if row['loaded'])} loaded")

    table = theme.new_table()
    table.add_column("model", style=theme.TEXT)
    table.add_column("type", style=theme.MUTED)
    table.add_column("trees", justify="right", style=theme.MUTED)
    table.add_column("features", style=theme.MUTED)
    table.add_column("size", justify="right", style=theme.MUTED)
    table.add_column("fit", justify="right")

    for row in rows:
        if not row["loaded"]:
            table.add_row(row["name"], Text("unavailable", style=theme.ERR), "—", "—", "—", "—")
            continue
        fit = "—"
        if row["r2"] is not None:
            style = theme.OK if row["r2"] >= 0.25 else theme.WARN
            fit = Text(f"r² {row['r2']:.2f}", style=style)
        table.add_row(
            row["name"],
            row["type"],
            str(row["trees"]),
            row["features"],
            theme.fmt_bytes(row["size"]),
            fit,
        )

    theme.show_table(table)
    theme.blank()
    theme.hint("r² is in-sample fit · --train reports a chronological holdout")
    theme.hint("predict with: focus models --predict 120")
    return 0


COMMAND = Command(
    name="models",
    summary="Inspect and retrain the traffic models",
    usage="models [--train] [--predict N]",
    configure=configure,
    run=run,
)
