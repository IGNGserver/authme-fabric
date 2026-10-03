#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
cd "$repo_root"

active_modules=(
  authme-core
  authme-fabric
  authme-fabric-mid
  authme-fabric-legacy
)

optional_modules=(
  authme-fabric-old
  authme-fabric-pre
  authme-fabric-older
)

for module in "${optional_modules[@]}"; do
  if [[ -d "$module" ]]; then
    active_modules+=("$module")
  fi
done

expected_includes="$(printf "include '%s'\n" "${active_modules[@]}" | sort)"
actual_includes="$(grep -E "^include '[^' ]+'" settings.gradle | sort)"
if [[ "$actual_includes" != "$expected_includes" ]]; then
  printf '%s\n' 'Fabric scope check failed: settings.gradle includes unexpected projects.' >&2
  printf '%s\n' "$actual_includes" >&2
  exit 1
fi

for module in "${active_modules[@]}"; do
  if [[ ! -d "$module/src" ]]; then
    printf 'Fabric scope check failed: missing active source directory: %s/src\n' "$module" >&2
    exit 1
  fi
done

java_api_pattern='^[[:space:]]*import[[:space:]]+(org\.bukkit|io\.papermc|dev\.folia|com\.velocitypowered|net\.md-5)'
gradle_api_pattern='org\.spigotmc|org\.bukkit|io\.papermc|dev\.folia|com\.velocitypowered|bungeecord-api|paper-api'
package_pattern='^[[:space:]]*package[[:space:]]+io\.github\.authme\.(platform|proxy)\.'

for pattern in "$java_api_pattern" "$gradle_api_pattern" "$package_pattern"; do
  if matches="$(grep -RInE --include='*.java' --include='*.gradle' "$pattern" "${active_modules[@]}" 2>/dev/null || true)"; then
    if [[ -n "$matches" ]]; then
      printf '%s\n' 'Fabric scope check failed: non-Fabric API/package found in active modules.' >&2
      printf '%s\n' "$matches" >&2
      exit 1
    fi
  fi
done

active_descriptors="$(find "${active_modules[@]}" -type f \( -name 'plugin.yml' -o -name 'bungee.yml' \) -print)"
if [[ -n "$active_descriptors" ]]; then
  printf '%s\n' 'Fabric scope check failed: native plugin descriptor found in active modules.' >&2
  printf '%s\n' "$active_descriptors" >&2
  exit 1
fi

printf '%s\n' 'Fabric scope check passed.'
