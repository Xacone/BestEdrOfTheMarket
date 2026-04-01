#!/usr/bin/env python3
import argparse
import os
import pathlib
import shutil
import subprocess
import sys


def resolve_msbuild(explicit_path: str | None) -> str:
    if explicit_path:
        p = pathlib.Path(explicit_path)
        if p.exists():
            return str(p)
        raise FileNotFoundError(f"MSBuild not found at: {explicit_path}")

    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    candidates = [
        pathlib.Path(pf86) / "Microsoft Visual Studio" / "2022" / "BuildTools" / "MSBuild" / "Current" / "Bin" / "MSBuild.exe",
        pathlib.Path(pf86) / "Microsoft Visual Studio" / "2022" / "Community" / "MSBuild" / "Current" / "Bin" / "MSBuild.exe",
        pathlib.Path(pf86) / "Microsoft Visual Studio" / "2022" / "Professional" / "MSBuild" / "Current" / "Bin" / "MSBuild.exe",
        pathlib.Path(pf86) / "Microsoft Visual Studio" / "2022" / "Enterprise" / "MSBuild" / "Current" / "Bin" / "MSBuild.exe",
    ]

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    via_path = shutil.which("msbuild")
    if via_path:
        return via_path

    raise FileNotFoundError("Unable to locate MSBuild.exe")


def build_clean_environment() -> dict[str, str]:
    normalized: dict[str, tuple[str, str]] = {}
    for key, value in os.environ.items():
        normalized[key.lower()] = (key, value)

    path_value = ""
    if "path" in normalized:
        path_value = normalized["path"][1]

    clean_env: dict[str, str] = {}
    for lower_key, (key, value) in normalized.items():
        if lower_key == "path":
            continue
        clean_env[key] = value

    if path_value:
        clean_env["Path"] = path_value

    return clean_env


def main() -> int:
    parser = argparse.ArgumentParser(description="Run MSBuild with a normalized Windows environment.")
    parser.add_argument("--solution", default="BestEdrOfTheMarket.sln", help="Path to .sln file")
    parser.add_argument("--configuration", default="Release", help="Build configuration")
    parser.add_argument("--platform", default="x64", help="Build platform")
    parser.add_argument("--msbuild", default=None, help="Explicit path to MSBuild.exe")
    parser.add_argument("--cwd", default=".", help="Working directory")
    parser.add_argument("--extra", nargs="*", default=[], help="Extra msbuild arguments")
    args = parser.parse_args()

    solution = pathlib.Path(args.solution).resolve()
    if not solution.exists():
        print(f"[!] Solution file not found: {solution}", file=sys.stderr)
        return 2

    cwd = pathlib.Path(args.cwd).resolve()
    msbuild = resolve_msbuild(args.msbuild)
    clean_env = build_clean_environment()

    cmd = [
        msbuild,
        str(solution),
        "/m",
        f"/p:Configuration={args.configuration}",
        f"/p:Platform={args.platform}",
    ] + list(args.extra)

    print("[*] Running:", " ".join(cmd))
    print("[*] CWD:", str(cwd))
    print("[*] Using normalized environment key for path: Path")

    completed = subprocess.run(cmd, cwd=str(cwd), env=clean_env)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
