import urllib.request
import re
from datetime import datetime
import json
import os

URL = "https://builds.vcmi.download/branch/beta/Windows/"
FILENAME = "updates/latest-nightly.json"

print("Fetching builds index...")
response = urllib.request.urlopen(URL)
html = response.read().decode('utf-8')

# Parse lines from <pre> section
lines = html.splitlines()
builds = []

for line in lines:
    # Match line like: <a href="VCMI-branch-beta-a00ec58.exe">VCMI-branch-beta-a00ec58.exe</a>       19-Jul-2025 03:42
    match = re.search(r'href="(VCMI-branch-beta-[a-f0-9]+\.exe)".*?([0-9]{2}-[A-Za-z]{3}-[0-9]{4}) ([0-9]{2}:[0-9]{2})', line)
    if match:
        filename = match.group(1)
        date_str = match.group(2) + " " + match.group(3)
        try:
            dt = datetime.strptime(date_str, "%d-%b-%Y %H:%M")
            builds.append((dt, filename))
        except Exception as e:
            print(f"Skipping line: {line.strip()} due to error: {e}")

if not builds:
    raise RuntimeError("No valid builds found!")

# Sort and get the latest build
builds.sort()
latest_dt, latest_filename = builds[-1]
build_hash_match = re.match(r'VCMI-branch-beta-([a-f0-9]+)\.exe', latest_filename)
if not build_hash_match:
    raise RuntimeError("Could not extract hash from filename.")

build_hash = build_hash_match.group(1)
download_url = f"{URL}{latest_filename}"

# Debug output
print("Found builds:")
for dt, fn in builds:
    print(f" - {fn} @ {dt.isoformat()}")

print(f"\nLatest: {latest_filename} ({build_hash}) @ {latest_dt.isoformat()}")

# Output JSON
data = {
    "updateType": "nightly",
    "version": f"VCMI 1.7-dev-{build_hash}",
    "commit": build_hash,
    "buildDate": latest_dt.isoformat(),
    "changeLog": "Latest nightly build from develop branch.",
    "downloadLinks": {
        "windows": download_url
    },
    "history": []
}

# Write to file
os.makedirs("updates", exist_ok=True)
with open(FILENAME, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

print(f"\n✅ Generated {FILENAME}")
