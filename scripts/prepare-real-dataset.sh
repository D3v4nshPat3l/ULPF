#!/usr/bin/env sh
set -eu

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
dataset_root="${1:-../realdata}"
output="${2:-testdata/real/all-perimeter.log}"
mkdir -p "$(dirname "$output")"

for source in \
  "$dataset_root/SotM30-anton.log" \
  "$dataset_root/SotM34/iptables/iptablesyslog" \
  "$dataset_root/SotM34/snort/snortsyslog"
do
  test -f "$source" || { echo "Missing real dataset file: $source. See docs/DATASETS.md." >&2; exit 1; }
done

cat "$dataset_root/SotM30-anton.log" "$dataset_root/SotM34/iptables/iptablesyslog" "$dataset_root/SotM34/snort/snortsyslog" > "$output"

printf 'Prepared %s\nRecords: %s\nSHA-256: %s\n' \
  "$output" "$(wc -l < "$output" | tr -d ' ')" "$(sha256sum "$output" | cut -d' ' -f1)"
