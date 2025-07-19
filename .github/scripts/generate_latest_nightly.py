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

result = {}

def fetch_html(url):
    with urllib.request.urlopen(url) as response:
        return response.read().decode("utf-8")

def extract_file_and_date(html, ext):
    match = re.search(
        rf'<tr><td><a href="([^"]+{re.escape(ext)})".*?</a></td><td>.*?</td><td>([0-9]{{4}}-[A-Za-z]{{3}}-[0-9]{{2}} [0-9]{{2}}:[0-9]{{2}})</td></tr>',
        html
    )
    if not match:
        return None, None
    return match.group(1), match.group(2)

for channel in channels:
    base_url = f"https://builds.vcmi.download/branch/{channel}"
    channel_obj = {}

    # First: get version from Windows x64 build
    win_url = f"{base_url}/Windows/"
    html = fetch_html(win_url)
    filename, date_str = extract_file_and_date(html, ".exe")
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
        system_obj = {}
        for variant in variants:
            if system == "windows":
                url = f"{base_url}/Windows/"
            elif system == "ios":
                url = f"{base_url}/iOS/"
            else:
                url = f"{base_url}/{system}/{variant}/"

            try:
                html = fetch_html(url)
            except:
                continue

            filename, _ = extract_file_and_date(html, extensions[system])
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
with open("updates/vcmi-update.json", "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

print("✅ Generated updates/vcmi-update.json")
