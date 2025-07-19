import urllib.request
import re
from datetime import datetime
import json
import os

# Define channels and systems
channels = ["develop", "beta"]
platforms = {
    "windows": ["x64", "x86"],
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

# Correct folder names with proper casing
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
        html,
        flags=re.IGNORECASE
    )
    if not rows:
        print(f"❌ No match for {system}/{variant} at {url}")
        return None, None
    filename, date_str = rows[0]
    print(f"✅ Found file for {system}/{variant} → {filename}")
    return filename, date_str

# Handle nightly channels (develop + beta)
for channel in channels:
    base_url = f"https://builds.vcmi.download/branch/{channel}"
    channel_obj = {}

    # Get version info from Windows x64 build
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

# Handle stable channel via GitHub API
print("\n🔍 Fetching stable release from GitHub...")
try:
    with urllib.request.urlopen("https://api.github.com/repos/vcmi/vcmi/releases/latest") as response:
        release = json.load(response)

    stable_obj = {
        "version": release["tag_name"],
        "buildDate": release["published_at"],
        "changeLog": release.get("body", "Latest stable release.")
    }

    # Define expected stable asset patterns
    stable_mapping = {
        "windows": {
            "x64": "VCMI-Windows.exe",
            "x86": "VCMI-Windows32bit.exe"
        },
        "macos": {
            "arm": "VCMI-macOS-arm.dmg",
            "intel": "VCMI-macOS-intel.dmg"
        },
        "android": {
            "armeabi-v7a": "VCMI-Android-armeabi-v7a.apk",
            "arm64-v8a": "VCMI-Android-arm64-v8a.apk"
        },
        "ios": {
            "ios": "VCMI-iOS.ipa"
        }
    }

    for system, variants in stable_mapping.items():
        system_obj = {}
        for variant, filename in variants.items():
            asset = next((a for a in release.get("assets", []) if a["name"] == filename), None)
            if asset:
                print(f"✅ Found stable {system}/{variant}: {filename}")
                system_obj[variant] = {
                    "download": asset["browser_download_url"]
                }
            else:
                print(f"❌ Missing stable {system}/{variant}: {filename}")
        if system_obj:
            stable_obj[system] = system_obj

    result["stable"] = stable_obj

except Exception as e:
    print(f"⚠️ Failed to fetch stable release: {e}")

# Write final JSON
os.makedirs("updates", exist_ok=True)
output_path = "updates/vcmi-update.json"
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

print(f"\n✅ Generated {output_path}")
