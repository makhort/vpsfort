#!/bin/bash
# Builds the documentation site from the READMEs and COMPARISON.md with mdBook, for GitHub
# Pages next to the package repository (.github/workflows/repository.yml runs it; by hand:
# ./scripts/docs-site.sh OUT). The pages are the files as they are, with the private sections
# (between the HTML comments "private" + ":begin" and "private" + ":end") left out and the
# links between the READMEs pointed at each other's pages.
#
# Needs mdbook (https://rust-lang.github.io/mdBook/; `cargo install mdbook --locked`, or the
# release binary CI downloads). Without it, only the book's sources are written (--sources).
set -euo pipefail
cd "$(dirname "$0")/.."

out=${1:-}
[ -n "$out" ] || { echo "usage: $0 OUT_DIR [--sources]" >&2; exit 2; }
sources_only=${2:-}

book=$(mktemp -d "${TMPDIR:-/tmp}/vpsfort-docs.XXXXXX")
trap 'rm -rf "$book"' EXIT
mkdir -p "$book/src"

# page name -> source file
pages=(
    "index:README.md"
    "comparison:COMPARISON.md"
    "vpsfort:vpsfort/README.md"
    "vpsfort-web:vpsfort-web/README.md"
    "vpsfort-sim:vpsfort-sim/README.md"
    "vpsfort-xmpp-bot:vpsfort-xmpp-bot/README.md"
    "vpsfort-tg-bot:vpsfort-tg-bot/README.md"
    "vpsfort-mail-bot:vpsfort-mail-bot/README.md"
    "vpsfort-signal-bot:vpsfort-signal-bot/README.md"
    "vpsfort-matrix-bot:vpsfort-matrix-bot/README.md"
    "vpsfort-push-bot:vpsfort-push-bot/README.md"
    "testing-fedora:vpsfort/TESTING-fedora.md"
)
# links as the READMEs write them (from their own directory) -> the page
links=(
    's#\]\(\.\./README\.md#](index.md#g'
    's#\]\(README\.md#](index.md#g'
    's#\]\((\.\./)?COMPARISON\.md#](comparison.md#g'
    's#\]\((\.\./)?vpsfort/README\.md#](vpsfort.md#g'
    's#\]\((\.\./)?vpsfort-web/README\.md#](vpsfort-web.md#g'
    's#\]\((\.\./)?vpsfort-sim/README\.md#](vpsfort-sim.md#g'
    's#\]\((\.\./)?vpsfort-xmpp-bot/README\.md#](vpsfort-xmpp-bot.md#g'
    's#\]\((\.\./)?vpsfort-tg-bot/README\.md#](vpsfort-tg-bot.md#g'
    's#\]\((\.\./)?vpsfort-mail-bot/README\.md#](vpsfort-mail-bot.md#g'
    's#\]\((\.\./)?vpsfort-signal-bot/README\.md#](vpsfort-signal-bot.md#g'
    's#\]\((\.\./)?vpsfort-matrix-bot/README\.md#](vpsfort-matrix-bot.md#g'
    's#\]\((\.\./)?vpsfort-push-bot/README\.md#](vpsfort-push-bot.md#g'
    's#\]\((\.\./)?vpsfort/TESTING-fedora\.md#](testing-fedora.md#g'
    's#\]\(TESTING-fedora\.md#](testing-fedora.md#g'
)
sed_links=()
for l in "${links[@]}"; do sed_links+=(-e "$l"); done

for entry in "${pages[@]}"; do
    page=${entry%%:*}
    file=${entry#*:}
    [ -f "$file" ] || { echo "no $file" >&2; exit 1; }
    # the private sections go; then the links (the markers are spelled in two parts, so this
    # script holds none itself)
    awk -v from="<!-- private"":begin -->" -v to="<!-- private"":end -->" \
        'index($0, from) { skip = 1; next } index($0, to) { skip = 0; next } !skip' "$file" \
        | sed -E "${sed_links[@]}" > "$book/src/$page.md"
done

cat > "$book/src/SUMMARY.md" <<'SUM'
# Summary

- [vpsfort](index.md)
- [Compared with the alternatives](comparison.md)
- [vpsfort: the daemon](vpsfort.md)
- [vpsfort-web: the console](vpsfort-web.md)
- [vpsfort-sim: the simulator](vpsfort-sim.md)
- [The bots]()
  - [XMPP (vpsfort-xmpp-bot)](vpsfort-xmpp-bot.md)
  - [Telegram (vpsfort-tg-bot)](vpsfort-tg-bot.md)
  - [Mail (vpsfort-mail-bot)](vpsfort-mail-bot.md)
  - [Signal (vpsfort-signal-bot)](vpsfort-signal-bot.md)
  - [Matrix (vpsfort-matrix-bot)](vpsfort-matrix-bot.md)
  - [ntfy, Gotify, a webhook (vpsfort-push-bot)](vpsfort-push-bot.md)
- [Tried on Fedora](testing-fedora.md)
SUM
cat > "$book/book.toml" <<'TOML'
[book]
title = "vpsfort"
description = "Behaviour-based intrusion prevention for a small self-hosted server family"
language = "en"

[output.html]
default-theme = "light"
preferred-dark-theme = "navy"
git-repository-url = "https://github.com/makhort/vpsfort"
no-section-label = true

[output.html.fold]
enable = true
level = 0

[output.html.search]
limit-results = 20
TOML

if [ "$sources_only" = --sources ] || ! command -v "${MDBOOK:-mdbook}" > /dev/null; then
    mkdir -p "$out"
    cp -R "$book/src" "$book/book.toml" "$out/"
    echo "book sources written to $out (mdbook not run$([ "$sources_only" = --sources ] || echo ': mdbook is not installed'))"
    exit 0
fi
"${MDBOOK:-mdbook}" build "$book" --dest-dir "$(cd "$(dirname "$out")" && pwd)/$(basename "$out")" > /dev/null
echo "docs built in $out ($(find "$out" -name '*.html' | wc -l | tr -d ' ') pages)"
