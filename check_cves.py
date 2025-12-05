import requests
import json
from datetime import datetime, timezone
from packaging import version
import os
import re

# --- CONFIG ---
KEYWORDS = [
    {"sdk": "RTL8720CM", "search": "RTL8720CM"},
    {"sdk": "Ameba SDK", "search": "Ameba"},
    {"sdk": "FreeRTOS v10.2.0", "search": "FreeRTOS", "version": "10.2.0"},
    {"sdk": "Bluetooth Core Specification 4.2", "search": "Bluetooth Core Specification 4.2"},
    {"sdk": "cJSON v1.6.0", "search": "cJSON", "version": "1.6.0"},
    {"sdk": "IwIP 2.0.2", "search": "lwIP", "version": "2.0.2"},
    {"sdk": "mbed TLS 2.16.4", "search": "mbedtls", "version": "2.16.4"},
    {"sdk": "Newlib 2.5.0", "search": "Newlib", "version": "2.5.0"},
    {"sdk": "wpa_supplicant 2.2", "search": "wpa_supplicant", "version": "2.2"},
    {"sdk": "IEEE 802.1X, WPA, WPA2, RSN, IEEE 802.11i", "search": "IEEE 802.1X"},
    {"sdk": "RealtekSDK(7.1d+v06 full patch)", "search": "RealtekSDK 7.1d v06"},
    {"sdk": "MINIX3", "search": "MINIX3", "version": "3.3.0"},
    {"sdk": "easy-ecc", "search": "easy-ecc"}
]

headers = {"User-Agent": "cve-monitor/1.0"}
results = []

def is_version_vulnerable(cpe_config, target_version):
    if not target_version:
        return True
    try:
        target_v = version.parse(target_version)
    except:
        return False

    configs = cpe_config if isinstance(cpe_config, list) else [cpe_config]
    for config in configs:
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                vs = cpe.get("versionStartIncluding") or cpe.get("versionStartExcluding")
                ve = cpe.get("versionEndExcluding") or cpe.get("versionEndIncluding")
                try:
                    if vs:
                        start = version.parse(vs)
                        if cpe.get("versionStartExcluding") and not (start < target_v):
                            continue
                        elif not (start <= target_v):
                            continue
                    if ve:
                        end = version.parse(ve)
                        if cpe.get("versionEndExcluding") and not (target_v < end):
                            continue
                        elif not (target_v <= end):
                            continue
                    return True
                except:
                    continue
    return False

def search_nvd(keyword, target_version):
    index = 0
    nvd_results = []

    try:
        while True:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 200,
                "startIndex": index
            }
            r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", headers=headers, params=params, timeout=10)
            data = r.json()
            vulns = data.get("vulnerabilities", [])

            for vuln in vulns:
                cve = vuln["cve"]
                configs = cve.get("configurations", {})
                if not is_version_vulnerable(configs, target_version):
                    continue

                title = cve.get("titles", [{}])[0].get("title", "")
                description = cve.get("descriptions", [{}])[0].get("value", "N/A")

                if "wpa_supplicant" in keyword.lower() and "2.2" in sdk:
                    found_versions = re.findall(r"wpa_supplicant[_ ]?(\d+(?:\.\d+)+)", description.lower())
                    if found_versions and all(not v.startswith("2.2") for v in found_versions):
                        continue

                if target_version and target_version not in description and target_version not in title:
                    found_versions = re.findall(r"v?(\d+\.\d+(?:\.\d+)?)", description)
                    if found_versions and all(v != target_version for v in found_versions):
                        continue

                refs = cve.get("references", [])
                metrics = cve.get("metrics", {})
                cvss_data = (
                    metrics.get("cvssMetricV31", [{}])[0].get("cvssData") or
                    metrics.get("cvssMetricV30", [{}])[0].get("cvssData") or
                    metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
                )
                weaknesses = cve.get("weaknesses", [])
                cwes = weaknesses[0]["description"][0]["value"] if weaknesses else "N/A"

                nvd_results.append({
                    "source": "NVD",
                    "id": cve["id"],
                    "title": title,
                    "description": description,
                    "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
                    "cvss": cvss_data.get("baseScore", "N/A"),
                    "cwe": cwes,
                    "published": cve.get("published", "N/A"),
                    "reference": refs[0]["url"] if refs else "https://nvd.nist.gov/vuln/detail/" + cve["id"]
                })

            index += 200
            if index >= data.get("totalResults", 0):
                break
    except Exception as e:
        print(f"[NVD ERROR] {e}")
    return nvd_results

# Main scanning loop
for item in KEYWORDS:
    sdk = item["sdk"]
    keyword = item["search"]
    version_str = item.get("version")

    print(f"\n🔍 Searching CVEs for {sdk} using keyword '{keyword}' and version '{version_str}'")
    nvd_results = search_nvd(keyword, version_str)

    for result in nvd_results:
        result["sdk"] = sdk
        results.append(result)

# Save to output
output = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "results": results
}

os.makedirs("output", exist_ok=True)
with open("output/results.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"✅ Scan complete. {len(results)} CVEs saved to output/results.json")


