#!/usr/bin/env bash
# check-licenses.sh: every module linked into the connector binary has a
# license file of an allowed kind. Permissive licenses (Apache-2.0, MIT, BSD,
# ISC, MPL-2.0) are allowed for anyone; GPL-3.0 only for openctemio modules
# (this project's own license). Anything else, or no license file, fails.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
while IFS='|' read -r mod dir; do
  [ -n "$mod" ] || continue
  file="$(find "$dir" -maxdepth 1 -type f \( -iname 'LICEN[CS]E*' -o -iname 'COPYING*' \) | sort | head -1)"
  if [ -z "$file" ]; then
    echo "::error::$mod has no license file"; fail=1; continue
  fi
  text="$(head -c 4000 "$file")"
  kind=""
  case "$text" in
    *"GNU AFFERO GENERAL PUBLIC LICENSE"*|*"Server Side Public License"*|*"Business Source License"*) kind="" ;;
    *"Apache License"*) kind="Apache-2.0" ;;
    *"Mozilla Public License"*) kind="MPL-2.0" ;;
    *"Permission is hereby granted, free of charge"*) kind="MIT" ;;
    *"Redistribution and use in source and binary forms"*) kind="BSD" ;;
    *"Permission to use, copy, modify, and/or distribute"*) kind="ISC" ;;
    *"GNU GENERAL PUBLIC LICENSE"*)
      case "$mod" in github.com/openctemio/*) kind="GPL-3.0 (openctemio)" ;; esac ;;
  esac
  if [ -z "$kind" ]; then
    echo "::error::$mod: license not allowed or not recognised ($file)"; fail=1
  else
    printf '%-45s %s\n' "$mod" "$kind"
  fi
done < <(GOWORK=off GOFLAGS=-mod=mod go list -deps -f '{{with .Module}}{{.Path}}|{{.Dir}}{{end}}' ./... | sort -u)
exit "$fail"
