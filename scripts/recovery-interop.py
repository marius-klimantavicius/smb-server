#!/usr/bin/env python3
"""Opt-in bounded native Samba probes; no download or ordinary-test dependency.

Supply a built test host, native Samba tools, an existing disposable share root,
and a password file outside that root. All host access must use this one server.
Each dialect is pinned, signing is required, and skips remain skips in results.
The output directory must be new. Ctrl-C stops the host and removes the generated
Samba authentication file; share contents and evidence are retained for inspection.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time


DEFAULT_SUITES = (
    "smb2.multichannel.generic.interface_info",
    "smb2.multichannel.oplocks.test1",
    "smb2.durable-open.reopen2",
    "smb2.durable-open.file-position",
    "smb2.durable-v2-open.reopen2",
)


def run_client(command, log, env, timeout):
    started = time.monotonic()
    timed_out = False
    with log.open("w", encoding="utf-8") as stream:
        try:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                                    env=env, timeout=timeout)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code, timed_out = None, True
    contents = log.read_text(encoding="utf-8", errors="replace")
    counts = {kind: len(re.findall(r"^" + kind + r":", contents, re.MULTILINE))
              for kind in ("success", "failure", "error", "skip")}
    outcome = ("timeout" if timed_out else "fail" if code != 0 or counts["failure"] or counts["error"]
               else "skip" if counts["skip"] else "pass")
    return {"command": command, "exit": code, "outcome": outcome,
            "subunit": counts, "seconds": round(time.monotonic() - started, 3),
            "log": str(log)}


def stop_host(host):
    if host.poll() is None:
        host.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGINT)
        try:
            host.wait(timeout=12)
        except subprocess.TimeoutExpired:
            host.kill()
            host.wait(timeout=5)
            return {"exit": host.returncode, "forced": True}
    return {"exit": host.returncode, "forced": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, type=Path, help="Smb.TestHost.dll or native executable")
    parser.add_argument("--root", required=True, type=Path, help="existing disposable share directory")
    parser.add_argument("--listen-address", required=True, type=ipaddress.ip_address)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password-file", required=True, type=Path)
    parser.add_argument("--exclusive-server-access", required=True, action="store_true")
    parser.add_argument("--smbtorture", required=True, type=Path)
    parser.add_argument("--smbclient", type=Path, help="also check signed upload/download bytes")
    parser.add_argument("--protection", choices=("sign", "encrypt"), default="sign")
    parser.add_argument("--library-path", action="append", default=[], type=Path,
                        help="optional native tool library directory; repeat as needed")
    parser.add_argument("--output", required=True, type=Path, help="new evidence directory")
    parser.add_argument("--dialect", action="append", choices=("300", "302", "311"))
    parser.add_argument("--suite", action="append", help="repeat to override bounded default suites")
    parser.add_argument("--timeout", type=int, default=45, help="seconds per client process")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or args.timeout < 1:
        parser.error("port must be 1..65535 and timeout must be positive")
    for field in ("host", "root", "password_file", "smbtorture", "output", "smbclient"):
        value = getattr(args, field)
        if value is not None:
            setattr(args, field, value.resolve())
    if not args.root.is_dir() or args.root == Path(args.root.anchor):
        parser.error("root must be an existing disposable directory below a filesystem root")
    if args.password_file.is_relative_to(args.root):
        parser.error("password file must be outside the shared root")
    if args.output.is_relative_to(args.root):
        parser.error("evidence and temporary authentication files must be outside the shared root")
    for tool in (args.host, args.smbtorture, args.smbclient):
        if tool is not None and not tool.is_file():
            parser.error("host and client paths must be existing files")
    password = args.password_file.read_text(encoding="utf-8").rstrip("\r\n")
    if any(not value or any(c in value for c in "\r\n\x00")
           for value in (args.domain, args.user, password)):
        parser.error("domain, user and password must be nonempty single-line values")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    auth_fd, auth_name = tempfile.mkstemp(prefix="samba-auth-", dir=args.output)
    with os.fdopen(auth_fd, "w", encoding="utf-8") as auth:
        auth.write(f"domain = {args.domain}\nusername = {args.user}\npassword = {password}\n")
    env = os.environ.copy()
    if args.library_path:
        key = "PATH" if os.name == "nt" else "LD_LIBRARY_PATH"
        env[key] = os.pathsep.join([*(str(p.resolve()) for p in args.library_path), env.get(key, "")])
    env["TMP" if os.name == "nt" else "TMPDIR"] = str(args.output)
    prefix = ["dotnet", str(args.host)] if args.host.suffix.lower() == ".dll" else [str(args.host)]
    command = prefix + ["serve-recovery", str(args.root), str(args.listen_address), str(args.port),
                        args.domain, args.user, str(args.password_file), "--exclusive-server-access"]
    report = {"server": command, "clients": [], "shutdown": None}
    host = None
    try:
        with (args.output / "host.log").open("w", encoding="utf-8") as host_log:
            host = subprocess.Popen(command, stdout=host_log, stderr=subprocess.STDOUT,
                                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
                                    start_new_session=os.name != "nt", env=env)
            deadline = time.monotonic() + 15
            while "share=P0 endpoint=" not in (args.output / "host.log").read_text(encoding="utf-8", errors="replace"):
                if host.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("test host did not become ready; inspect host.log")
                time.sleep(0.05)
            for dialect in args.dialect or ("300", "302", "311"):
                common = [f"//{args.listen_address}/P0", "-p", str(args.port), "-A", auth_name,
                          f"--client-protection={args.protection}", f"--option=client min protocol=SMB3_{dialect[1:]}",
                          f"--option=client max protocol=SMB3_{dialect[1:]}"]
                if args.smbclient:
                    source, target = args.output / f"input-{dialect}.txt", args.output / f"output-{dialect}.txt"
                    source.write_bytes(b"independent signed native Samba roundtrip\n")
                    operations = f'put "{source}" interop-{dialect}.txt; get interop-{dialect}.txt "{target}"; del interop-{dialect}.txt'
                    row = run_client([str(args.smbclient), *common, "-c", operations],
                                     args.output / f"smbclient-{dialect}.log", env, args.timeout)
                    row.update(dialect=dialect, suite=f"{args.protection}-roundtrip",
                               bytes_equal=target.exists() and source.read_bytes() == target.read_bytes())
                    if not row["bytes_equal"]:
                        row["outcome"] = "fail"
                    report["clients"].append(row)
                for index, suite in enumerate(args.suite or DEFAULT_SUITES):
                    row = run_client([str(args.smbtorture), *common, "--format=subunit", "--fullname",
                                      f"--maximum-runtime={args.timeout}", suite],
                                     args.output / f"smbtorture-{dialect}-{index}.log", env, args.timeout + 5)
                    row.update(dialect=dialect, suite=suite)
                    # Exit zero without an actual successful subunit test is not a pass.
                    if row["outcome"] == "pass" and row["subunit"]["success"] == 0:
                        row["outcome"] = "no-tests"
                    report["clients"].append(row)
                    print(json.dumps({key: row[key] for key in ("dialect", "suite", "outcome", "exit")}), flush=True)
    finally:
        try:
            if host is not None:
                report["shutdown"] = stop_host(host)
        finally:
            Path(auth_name).unlink(missing_ok=True)
            (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if (all(row["outcome"] == "pass" for row in report["clients"])
                 and report["shutdown"] == {"exit": 0, "forced": False}) else 1


if __name__ == "__main__":
    raise SystemExit(main())
