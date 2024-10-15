import pandas as pd
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress


def read_yaml_from_url(url):
    response = requests.get(url)  # Send a GET request to the URL
    response.raise_for_status()
    return yaml.safe_load(response.text)  # Parse the YAML content from the response


def read_list_from_url(url):
    return pd.read_csv(
        url, header=None, names=["pattern", "address", "other"], on_bad_lines="warn"
    )  # Read CSV from URL, handle bad lines with a warning


def is_ipv4_or_ipv6(address):
    try:
        ipaddress.IPv4Network(address)
        return "ipv4"
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return "ipv6"
        except ValueError:
            return None


def parse_yaml_items(yaml_data):
    rows = []
    if not isinstance(yaml_data, str):
        items = yaml_data.get("payload", [])  # Get the payload items from the YAML data
    else:
        lines = yaml_data.splitlines()  # Split the string into lines
        line_content = lines[0]  # Get the first line content
        items = line_content.split()  # Split the line content into items

    for item in items:
        address = item.strip("'")  # Remove surrounding single quotes
        if "," not in item:
            if is_ipv4_or_ipv6(item):  # Determine if the item is an IP address
                pattern = "IP-CIDR"
            else:
                if address.startswith("+") or address.startswith("."):
                    pattern = "DOMAIN-SUFFIX"
                    address = address[1:]  # Remove the leading '+' or '.'
                    if address.startswith("."):
                        address = address[1:]  # Remove the leading '.' again if present
                else:
                    pattern = "DOMAIN"
        else:
            pattern, address = item.split(
                ",", 1
            )  # Split the item into pattern and address

        rows.append(
            {"pattern": pattern.strip(), "address": address.strip(), "other": None}
        )  # Append the parsed item to rows

    return pd.DataFrame(
        rows, columns=["pattern", "address", "other"]
    )  # Convert rows to DataFrame


def parse_and_convert_to_dataframe(link):
    if link.endswith(".yaml") or link.endswith(".txt"):
        try:
            yaml_data = read_yaml_from_url(link)  # Read YAML data from URL
            df = parse_yaml_items(yaml_data)  # Parse YAML items into DataFrame
        except:
            df = read_list_from_url(
                link
            )  # Fallback to reading CSV if YAML parsing fails
    else:
        df = read_list_from_url(link)  # Read CSV data from URL
    return df


def sort_dict(obj):
    if isinstance(obj, dict):
        return {
            k: sort_dict(obj[k]) for k in sorted(obj)
        }  # Recursively sort dictionary by keys
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted(
            [sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0]
        )  # Sort list of dictionaries
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj


def process_json_file(link, output_directory, base_file_name):
    os.makedirs(output_directory, exist_ok=True)
    file_name = os.path.join(
        output_directory, f"{base_file_name}.json"
    )  # Construct the output file path
    response = requests.get(link)  # Send a GET request to the URL
    response.raise_for_status()  # Raise an error if the request was unsuccessful
    json_data = response.json()  # Parse the sing-box's JSON content from the response

    # sing-box rule-set format version 2 is already supported in latest release.
    # Upgrade rule-set version to 2.
    if json_data.get("version") == 1:
        json_data["version"] = 2

    with open(file_name, "w", encoding="utf-8") as output_file:
        json.dump(
            json_data, output_file, ensure_ascii=False, indent=2
        )  # Write JSON data to file

    return file_name


def process_other_files(link, output_directory, base_file_name):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(
            executor.map(parse_and_convert_to_dataframe, [link])
        )  # Parse and convert data to DataFrame
        df = pd.concat(
            results, ignore_index=True
        )  # Concatenate results into a single DataFrame

    df = df[~df["pattern"].str.contains("#")].reset_index(
        drop=True
    )  # Remove rows with patterns containing '#'
    map_dict = {
        "DOMAIN-SUFFIX": "domain_suffix",
        "HOST-SUFFIX": "domain_suffix",
        "DOMAIN": "domain",
        "HOST": "domain",
        "host": "domain",
        "DOMAIN-KEYWORD": "domain_keyword",
        "HOST-KEYWORD": "domain_keyword",
        "host-keyword": "domain_keyword",
        "IP-CIDR": "ip_cidr",
        "ip-cidr": "ip_cidr",
        "IP-CIDR6": "ip_cidr",
        "IP6-CIDR": "ip_cidr",
        "SRC-IP-CIDR": "source_ip_cidr",
        "GEOIP": "geoip",
        "DST-PORT": "port",
        "SRC-PORT": "source_port",
        "URL-REGEX": "domain_regex",
    }
    df = df[df["pattern"].isin(map_dict.keys())].reset_index(
        drop=True
    )  # Filter rows based on pattern keys
    df = df.drop_duplicates().reset_index(drop=True)  # Remove duplicate rows
    df["pattern"] = df["pattern"].replace(
        map_dict
    )  # Replace pattern values based on map_dict
    os.makedirs(
        output_directory, exist_ok=True
    )  # Create output directory if it doesn't exist

    result_rules = {"version": 1, "rules": []}
    domain_entries = []
    for pattern, addresses in (
        df.groupby("pattern")["address"].apply(list).to_dict().items()
    ):  # Group addresses by pattern
        if pattern == "domain_suffix":
            rule_entry = {
                pattern: ["." + address.strip() for address in addresses]
            }  # Add leading '.' to addresses
            result_rules["rules"].append(rule_entry)
            domain_entries.extend([address.strip() for address in addresses])
        elif pattern == "domain":
            domain_entries.extend([address.strip() for address in addresses])
        else:
            rule_entry = {pattern: [address.strip() for address in addresses]}
            result_rules["rules"].append(rule_entry)

    domain_entries = list(set(domain_entries))  # Remove duplicate domain entries
    if domain_entries:
        result_rules["rules"].insert(
            0, {"domain": domain_entries}
        )  # Insert domain entries at the beginning

    file_name = os.path.join(
        output_directory, f"{base_file_name}.json"
    )  # Construct the output file path
    with open(file_name, "w", encoding="utf-8") as output_file:
        json.dump(
            sort_dict(result_rules), output_file, ensure_ascii=False, indent=2
        )  # Write sorted JSON data to file

    return file_name


def compile_to_binary(file_name):
    srs_path = file_name.replace(".json", ".srs")  # Replace .json extension with .srs
    os.system(
        f"sing-box rule-set compile --output {srs_path} {file_name}"
    )  # Compile sing-box's JSON file to binary
    return srs_path


def parse_list_file(link, output_directory, file_name):
    base_file_name = os.path.splitext(file_name)[
        0
    ]  # Get the base file name without extension

    if link.endswith(".json"):
        file_name = process_json_file(
            link, output_directory, base_file_name
        )  # Process sing-box's JSON file
    else:
        file_name = process_other_files(
            link, output_directory, base_file_name
        )  # Process other file types

    compile_to_binary(file_name)  # Compile the file to binary
    return file_name


def main():
    with open("./source.yml", "r") as links_file:
        links = yaml.safe_load(links_file)  # Load links from source.yml

    output_dir = "./output/"
    result_file_names = []

    for link_info in links:
        result_file_name = parse_list_file(
            link_info["url"],
            output_directory=output_dir,
            file_name=link_info["file_name"],
        )  # Parse and process each link
        result_file_names.append(result_file_name)

    for file_name in result_file_names:
        print(file_name)  # Print the result file names


if __name__ == "__main__":
    main()
