"""Copy likely-download rows to a separate CSV, preserving all columns."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "out" / "download_urls.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "data.csv")
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error("Input and output must be different files.")

    count = 0
    try:
        with args.input.open(encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            if not reader.fieldnames or "status" not in reader.fieldnames:
                parser.error("Input CSV must contain a 'status' column.")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("w", encoding="utf-8", newline="") as destination:
                writer = csv.DictWriter(destination, fieldnames=reader.fieldnames)
                writer.writeheader()
                for row in reader:
                    if row["status"] == "probed_likely_download":
                        writer.writerow(row)
                        count += 1
    except (OSError, UnicodeError, csv.Error, ValueError) as exc:
        parser.exit(1, f"Error: {exc}\n")
    print(f"Saved {count:,} likely-download rows to {args.output}")


if __name__ == "__main__":
    main()
