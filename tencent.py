import requests
import json
import os
import subprocess


def fetch_prefixes(asn):
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
    try:
        response = requests.get(url, timeout=15)
        data = response.json()
        return [item["prefix"] for item in data.get("data", {}).get("prefixes", [])]
    except Exception as e:
        print(f"Error ({asn}): {e}")
        return []


def main():
    target_asns = ["AS45090", "AS132203", "AS139341"]

    all_prefixes = []
    for asn in target_asns:
        all_prefixes.extend(fetch_prefixes(asn))

    all_prefixes = sorted(set(all_prefixes))

    config = {"version": 3, "rules": [{"ip_cidr": all_prefixes}]}

    json_filename = "my-tencent-ipcidr.json"
    output_dir = "./output"
    srs_filename = os.path.join(output_dir, "my-tencent-ipcidr.srs")
    with open(json_filename, "w") as f:
        json.dump(config, f, indent=2)
    os.makedirs(output_dir, exist_ok=True)
    compile_cmd = [
        "sing-box",
        "rule-set",
        "compile",
        json_filename,
        "--output",
        srs_filename,
    ]
    subprocess.run(compile_cmd, check=True, capture_output=True, text=True)


if __name__ == "__main__":
    main()
