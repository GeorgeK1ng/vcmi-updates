import urllib.request
import re
from datetime import datetime, timezone
import json
import tempfile
import pefile

# Mapping of actual folder names to logical system/variant pairs
platform_dirs = {
    "windows-x64": ("windows", "x64"),
    "windows-x86": ("windows", "x86"),
    "windows-arm64": ("windows", "arm64"),
    "macos-intel": ("macos", "intel"),
    "macos-arm": ("macos", "arm"),
    "android-armeabi-v7a": ("android", "armeabi-v7a"),
    "android-arm64-v8a": ("android", "arm64-v8a"),
    "ios": ("ios", "ios")
}

# File extensions per platform
extensions = {
    "windows": ".exe",
    "macos": ".dmg",
    "android": ".apk",
    "ios": ".ipa"
}

def fetch_html(url):
    """Download and return the HTML content of a URL."""
    with urllib.request.urlopen(url) as response:
        return response.read().decode("utf-8")

def extract_file_and_date(html, ext, system="", variant="", url=""):
    """
    Extract the most recent file based on the date column.
    Returns (filename, date_str)
    """
    rows = re.findall(
        r'<tr><td><a href="([^"]+%s)".*?</a></td><td[^>]*>\s*\d+\s*</td><td[^>]*>([^<]+)</td>' % re.escape(ext),
        html,
        flags=re.IGNORECASE
    )
    if not rows:
        print(f"❌ No match for {system}/{variant} at {url}")
        return None, None

    def parse_date(date_str):
        try:
            return datetime.strptime(date_str, "%Y-%b-%d %H:%M")
        except ValueError:
            return datetime.min

    # Sort by newest
    rows.sort(key=lambda x: parse_date(x[1]), reverse=True)
    filename, date_str = rows[0]
    print(f"✅ Found newest file for {system}/{variant} → {filename}")
    return filename, date_str

def get_file_version_from_exe_url(url):
    """Extract FileVersion from EXE PE header."""
    try:
        with urllib.request.urlopen(url) as response:
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(response.read())
                tmp_path = tmp_file.name

        pe = pefile.PE(tmp_path)
        for fileinfo in pe.FileInfo:
            for entry in fileinfo:
                if hasattr(entry, 'StringTable'):
                    for st in entry.StringTable:
                        version = st.entries.get(b"FileVersion") or st.entries.get("FileVersion")
                        if version:
                            version = version.decode("utf-8") if isinstance(version, bytes) else version
                            return version.replace(" ", "").strip()
    except Exception as e:
        print(f"⚠️ Could not extract version from EXE: {e}")
    return "1.6.8"

# Prepare empty download map template
empty_download_map = {f"{system}-{variant}": "" for _, (system, variant) in platform_dirs.items()}

# Process nightly branches: develop and beta
channels = ["develop", "beta"]
channel_results = {}

for channel in channels:
    base_url = f"https://builds.vcmi.download/branch/{channel}"
    channel_obj = {
        "download": dict(empty_download_map)
    }

    # Get latest Windows x64 build info
    win_url = f"{base_url}/windows-x64/"
    html = fetch_html(win_url)
    filename, date_str = extract_file_and_date(html, ".exe", "windows", "x64", win_url)

    if not filename:
        print(f"⚠️ No Windows x64 build found for {channel} — using fallback metadata")
        channel_obj["version"] = "1.7-dev"
        channel_obj["commit"] = "unknown"
        channel_obj["buildDate"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        channel_obj["changeLog"] = "Partial build info. Windows x64 missing."
    else:
        build_hash_match = re.search(r'VCMI-branch-[\w\-]+-([a-fA-F0-9]+)\.exe', filename)
        if not build_hash_match:
            raise RuntimeError("Build hash not found in filename")

        build_hash = build_hash_match.group(1)
        build_date = datetime.strptime(date_str, "%Y-%b-%d %H:%M").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

        exe_url = f"{win_url}{filename}"
        version_string = get_file_version_from_exe_url(exe_url)
        channel_obj["version"] = version_string
        channel_obj["commit"] = build_hash
        channel_obj["buildDate"] = build_date
        channel_obj["changeLog"] = "Latest nightly build from develop branch."

    # Detect builds for all platforms
    for folder_name, (system, variant) in platform_dirs.items():
        url = f"{base_url}/{folder_name}/"
        try:
            html = fetch_html(url)
        except Exception as e:
            print(f"⚠️ Failed to fetch {url}: {e}")
            continue

        filename, _ = extract_file_and_date(html, extensions[system], system, variant, url)
        if not filename:
            continue

        download_url = url + filename
        key = f"{system}-{variant}"
        channel_obj["download"][key] = download_url

    channel_results[channel] = channel_obj

# Write develop and beta JSON files
for channel, data in channel_results.items():
    filename = f"vcmi-{channel}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"📄 Written {filename}")

# Fetch latest stable release from GitHub
print("\n🔍 Fetching stable release from GitHub...")
try:
    with urllib.request.urlopen("https://api.github.com/repos/vcmi/vcmi/releases/latest") as response:
        release = json.load(response)

    stable_obj = {
        "version": release["tag_name"],
        "buildDate": release["published_at"].replace("+00:00", "Z") if release["published_at"].endswith("+00:00") else release["published_at"],
        "changeLog": release.get("body", "Latest stable release."),
        "download": dict(empty_download_map)
    }

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
        for variant, filename in variants.items():
            asset = next((a for a in release.get("assets", []) if a["name"] == filename), None)
            key = f"{system}-{variant}"
            if asset:
                print(f"✅ Found stable {key}: {filename}")
                stable_obj["download"][key] = asset["browser_download_url"]
            else:
                print(f"❌ Missing stable {key}: {filename}")

    with open("vcmi-stable.json", "w", encoding="utf-8") as f:
        json.dump(stable_obj, f, indent=2, ensure_ascii=False)
    print("📄 Written vcmi-stable.json")

except Exception as e:
    print(f"⚠️ Failed to fetch stable release: {e}")
