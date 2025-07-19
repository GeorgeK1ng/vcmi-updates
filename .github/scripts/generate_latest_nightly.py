import urllib.request
import re
from datetime import datetime
import json
import os

# Define channels and systems
channels = ["develop", "beta"]
platforms = {
    "windows": ["x64"],
    "macos": ["intel", "arm"],
    "android": ["armeabi-v7a", "arm64-v8a"],
    "ios": ["ios"]
}

extensions = {
    "windows": ".exe",
    "macos": ".dmg",
    "android": ".apk",
    "ios": ".ipa"
}

# Correct folder names with proper case
folder_names = {
    "windows": "Windows",
    "macos": "macOS",
    "android": "Android",
    "ios": "iOS"
}

result = {}

def fetch_html(url):
    with urllib.request.urlopen(url) as response:
        return response.read().decode("utf-8")

def extract_file_and_date(html, ext, system="", variant="", url=""):
    rows = re.findall(
        r'<tr><td><a href="([^"]+%s)".*?</a></td><td[^>]*>\s*\d+\s*</td><td[^>]*>([^<]+)</td>' % re.escape(ext),
        html
    )
    if not rows:
        print(f"❌ No match for {system}/{variant} at {url}")
        return None, None
    filename, date_str = rows[0]
    print(f"✅ Found file for {system}/{variant} → {filename}")
    return filename, date_str

for channel in channels:
    base_url = f"https://builds.vcmi.download/branch/{channel}"
    channel_obj = {}

    # Get version from Windows x64 build
    win_url = f"{base_url}/Windows/"
    html = fetch_html(win_url)
    filename, date_str = extract_file_and_date(html, ".exe", "windows", "x64", win_url)
    if not filename:
        raise RuntimeError(f"No Windows x64 build found for {channel}")

    build_hash_match = re.search(r'VCMI-branch-[a-z]+-([a-f0-9]+)\.exe', filename)
    if not build_hash_match:
        raise RuntimeError("Build hash not found in filename")

    build_hash = build_hash_match.group(1)
    build_date = datetime.strptime(date_str, "%Y-%b-%d %H:%M").isoformat()

    channel_obj["version"] = f"VCMI 1.7-dev-{build_hash}"
    channel_obj["commit"] = build_hash
    channel_obj["buildDate"] = build_date
    channel_obj["changeLog"] = "Latest nightly build from develop branch."

    for system, variants in platforms.items():
        folder = folder_names[system]
        system_obj = {}

        for variant in variants:
            if system in ["windows", "ios"]:
                url = f"{base_url}/{folder}/"
            else:
                url = f"{base_url}/{folder}/{variant}/"

            try:
                html = fetch_html(url)
            except Exception as e:
                print(f"⚠️ Failed to fetch {url}: {e}")
                continue

            filename, _ = extract_file_and_date(html, extensions[system], system, variant, url)
            if not filename:
                continue

            download_url = url + filename
            system_obj[variant] = {
                "download": download_url
            }

        if system_obj:
            channel_obj[system] = system_obj

    result[channel] = channel_obj

# Write output JSON
os.makedirs("updates", exist_ok=True)
output_path = "updates/vcmi-update.json"
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

print(f"\n✅ Generated {output_path}")
