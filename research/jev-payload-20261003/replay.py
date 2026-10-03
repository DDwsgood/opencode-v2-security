#!/usr/bin/env python3
"""Small-batch Jev replay. Never execute corpus command/script contents."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--reviewer", type=Path, default=(
        Path(__file__).resolve().parents[2] / "src/security/jev-reviewer.py"))
    parser.add_argument("--endpoint", default=os.environ.get("JEV_ENDPOINT"))
    parser.add_argument("--model", default=os.environ.get("JEV_MODEL"))
    parser.add_argument("--api-key-env", default="JEV_API_KEY")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args()
    corpus = json.loads(args.corpus.read_text())
    if not isinstance(corpus, list) or not 0 < len(corpus) < 50:
        parser.error("Each batch must contain 1–49 cases")
    if not args.endpoint or not args.model:
        parser.error("Supply --endpoint/--model or JEV_ENDPOINT/JEV_MODEL")
    key = os.environ.get(args.api_key_env)
    if not key:
        parser.error("The configured API-key environment variable is empty")
    if args.output.exists():
        parser.error("Refusing to overwrite an earlier result")
    if not 1 <= args.workers <= 8 or args.timeout <= 0:
        parser.error("Workers must be 1–8 and timeout must be positive")
    spec = importlib.util.spec_from_file_location("jev_replay", args.reviewer)
    reviewer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reviewer)
    reviewer.ENDPOINT = args.endpoint

    def review(case):
        started = time.monotonic()
        result = {"id": case["id"], "expected": case["expected"]}
        try:
            response = reviewer.review_request(
                case["request"], args.model, args.timeout, key,
                dict(reviewer.DEFAULT_THRESHOLDS))
            result.update(response)
            result["pred"] = "DENY" if response["deny"] else "ALLOW"
        except Exception as error:
            # Request bodies and HTTP responses may contain sensitive data.
            result["pred"] = "ERROR"
            result["error_type"] = type(error).__name__
        result["elapsed_s"] = round(time.monotonic() - started, 2)
        return result

    results = []
    with args.output.open("x") as output:
        args.output.chmod(0o600)
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for result in pool.map(review, corpus):
                results.append(result)
                output.write(json.dumps(result, ensure_ascii=False) + "\n")
                output.flush()
                print(result["id"], result["expected"], result["pred"], flush=True)
    print(json.dumps({
        "cases": len(results),
        "false_deny": sum(r["expected"] == "ALLOW" and r["pred"] == "DENY" for r in results),
        "false_allow": sum(r["expected"] == "DENY" and r["pred"] == "ALLOW" for r in results),
        "errors": sum(r["pred"] == "ERROR" for r in results),
    }))


if __name__ == "__main__":
    main()
