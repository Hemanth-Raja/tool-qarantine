"""Command-line entry: `python -m tq.cli run samples 'python /tool/json_formatter.py'`."""
import argparse
import json
import sys

from . import runner, store

COLORS = {"trusted": "\033[32m", "review": "\033[33m", "suspicious": "\033[33m",
          "dangerous": "\033[31m"}
RESET = "\033[0m"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tq", description="Tool Quarantine")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="quarantine and exercise a tool")
    r.add_argument("tool_dir")
    r.add_argument("entry", help="e.g. 'python /tool/server.py' (docker) or 'python server.py'")
    r.add_argument("--name", default="")
    r.add_argument("--mode", default="auto", choices=["auto", "docker", "trace"])
    r.add_argument("--json", action="store_true")
    r.add_argument("--save", action="store_true", help="store the report for the web UI")

    h = sub.add_parser("hash", help="print a tool's code fingerprint (sha256)")
    h.add_argument("tool_dir")
    h.add_argument("entry", help="the entry command it was quarantined with")

    k = sub.add_parser("check", help="ask a Tool Quarantine server whether this code may run; "
                                     "exit 0 if approved, 1 otherwise (for gateways and CI)")
    k.add_argument("tool_dir")
    k.add_argument("entry")
    k.add_argument("--server", default="http://localhost:8000")

    args = ap.parse_args(argv)
    if args.cmd in ("hash", "check"):
        from .fingerprint import tool_hash
        digest = tool_hash(args.tool_dir, args.entry, "upload")
        if args.cmd == "hash":
            print(digest)
            return 0
        import urllib.request
        with urllib.request.urlopen(f"{args.server.rstrip('/')}/api/registry/check?hash={digest}",
                                    timeout=15) as resp:
            res = json.load(resp)
        print(json.dumps(res, indent=2))
        return 0 if res.get("allowed") else 1
    if args.cmd == "run":
        rep = runner.run(args.tool_dir, args.entry, tool_name=args.name or None, mode=args.mode)
        if args.save:
            rep["id"] = store.save_run(rep)
        if args.json:
            print(json.dumps(rep, indent=2))
            return 0
        v = rep["verdict"]
        c = COLORS.get(v["label"], "")
        print(f"\n  Tool:    {rep['tool']}  ({rep['mode']} mode, agent: {rep['agent']})")
        print(f"  Verdict: {c}{v['label'].upper()}{RESET}  score {v['score']}/100 — {v['summary']}")
        print(f"  Calls:   {', '.join(c['name'] for c in rep['calls_made']) or '(none)'}")
        if rep["findings"]:
            print("  Findings:")
            for f in rep["findings"]:
                print(f"    [{f['severity'].upper()}] {f['title']}")
                print(f"        {f['detail']}")
                for e in f["evidence"][:6]:
                    print(f"          · {e}")
        else:
            print("  Findings: none")
        if rep.get("id"):
            print(f"  Saved as run {rep['id']}")
        print()
        return 0


if __name__ == "__main__":
    sys.exit(main())
