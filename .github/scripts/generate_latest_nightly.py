import urllib.request
import re
from datetime import datetime
import json
import os

URL = "https://builds.vcmi.download/branch/beta/Windows/"
FILENAME = "updates/latest-nightly.json"

print("Fetching builds index...")
response = urllib.request.urlopen(URL)
html = response.read().decode("utf-8")

# Match the first occurrence of an .exe file row in the table
match = re.search(
    r'<tr><td><a href="(VCMI-branch-beta-([a-f0-9]+)\.exe)".*?</a></td><td>.*?</td><td>([0-9]{4}-[A-Za-z]{3}-[0-9]{2} [0-9]{2}:[0-9]{2})</td></tr>',
    html
)

if not match:
    raise RuntimeError("No matching build row found!")

filename = match.group(1)
build_hash = match.group(2)
date_str = match.group(3)
build_date = datetime.strptime(date_str, "%Y-%b-%d %H:%M")

download_url = f"{URL}{filename}"

# Debug
print(f"Matched file: {filename}")
print(f"Build hash: {build_hash}")
print(f"Build date: {build_date.isoformat()}")

# Generate JSON
data = {
    "updateType": "nightly",
    "version": f"VCMI 1.7-dev-{build_hash}",
    "commit": build_hash,
    "buildDate": build_date.isoformat(),
    "changeLog": "Latest nightly build from develop branch.",
    "downloadLinks": {
        "windows": download_url
    },
    "history": []
}

# Write output
os.makedirs("updates", exist_ok=True)
with open(FILENAME, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

print(f"\n✅ Generated {FILENAME}")
