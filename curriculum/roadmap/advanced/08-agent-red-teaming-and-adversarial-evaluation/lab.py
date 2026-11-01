"""Runnable entry point and public API for the Advanced 08 campaign lab."""

from campaign import *  # noqa: F403 - intentional notebook-friendly re-export


if __name__ == "__main__":
    import json

    for label, report in zip(("hardened", "unsafe-baseline", "broken-observer"), demo()):  # noqa: F405
        print(label, json.dumps(report_summary(report), sort_keys=True))  # noqa: F405
