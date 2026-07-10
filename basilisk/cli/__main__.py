from __future__ import annotations

import argparse
import json
import sys

from basilisk.config import get_settings
from basilisk.hkp.handlers import get_blob_store, get_store, ingest_keytext, lookup_stats
from basilisk.openpgp.approve import approve_cert


def cmd_doctor(_: argparse.Namespace) -> int:
    settings = get_settings()
    ok = True
    try:
        import pysequoia  # noqa: F401
        print("pysequoia: ok")
    except ImportError:
        print("pysequoia: MISSING")
        ok = False
    store = get_store(settings)
    print(f"storage: ok ({settings.db_path})")
    print(f"blob path: {settings.blob_path}")
    print(f"dev_approve: {settings.dev_approve}")
    return 0 if ok else 1


def cmd_approve(args: argparse.Namespace) -> int:
    store = get_store()
    uids = args.uids.split(",") if args.uids else None
    approve_cert(store, args.fingerprint, uids or [])
    print(f"Approved {args.fingerprint.upper()}")
    return 0


def cmd_migrate(args: argparse.Namespace) -> int:
    from pathlib import Path

    from basilisk.config import get_settings
    from basilisk.db.sqlite_store import SqliteCertStore

    settings = get_settings()
    store = SqliteCertStore(settings.db_path)
    migrations = sorted(Path(__file__).resolve().parents[1] / "db" / "migrations").glob("*.sql")
    for mig in migrations:
        sql = mig.read_text(encoding="utf-8").strip()
        if sql:
            store._conn.executescript(sql)  # noqa: SLF001
            store._conn.commit()
        print(f"Applied {mig.name}")
    return 0


def cmd_smoke(_: argparse.Namespace) -> int:
    stats = lookup_stats()
    print(json.dumps(json.loads(stats.body if isinstance(stats.body, str) else stats.body.decode())))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="basilisk")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("doctor")
    p.set_defaults(func=cmd_doctor)
    p = sub.add_parser("approve")
    p.add_argument("fingerprint")
    p.add_argument("--uids", default="")
    p.set_defaults(func=cmd_approve)
    p = sub.add_parser("migrate")
    p.set_defaults(func=cmd_migrate)
    p = sub.add_parser("smoke")
    p.set_defaults(func=cmd_smoke)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
