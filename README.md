# 🗣 sing-box_Route-rules

Auto-generated [sing-box](https://sing-box.sagernet.org) rule-sets, rebuilt daily by GitHub Actions.

## Usage

The built rule-sets live in two directories:

- `rule_srs/` — compiled `.srs` binaries (recommended; faster to load)
- `rule_json/` — the `.json` sources they were compiled from

Reference any file by its raw URL in your sing-box config:

```jsonc
{
  "type": "remote",
  "tag": "skk-cdn",
  "format": "binary",
  "url": "https://raw.githubusercontent.com/KdeInit/sing-box_Route-rules/main/rule_srs/ruleset.skk.moe-domainset-cdn.srs"
}
```

Use `"format": "binary"` for `.srs` and `"format": "source"` for `.json`. The `.srs`
files are format version 3, which needs sing-box 1.11.0+ (the daily build uses 1.13.3).

## How it works

- `source.yml` — upstream rule-set sources (`file_name` + `url`). Add an entry here to mirror a new list.
- `convert.py` — downloads each source, converts it to a sing-box rule-set, and compiles it to `.srs`.
- `tencent.py` — builds a Tencent IP-CIDR rule-set from ASN announced prefixes (via RIPEstat).
- `.github/workflows/main.yml` — runs the scripts daily (also on push to `main` and manual dispatch), then commits the results to `rule_json/` and `rule_srs/`.

## License

[GPL](./LICENSE). Mirrored upstream lists keep their own licenses (e.g. [Sukka's Ruleset](https://ruleset.skk.moe) is AGPL 3.0).
