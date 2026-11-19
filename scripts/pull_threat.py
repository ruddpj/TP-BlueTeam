import ipaddress
import os
import urllib.request

FEEDS = [
    (
        "abusech_feodo_c2",
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    ),
    ("abusech_sslbl", "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"),
    (
        "emerging_threats",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    ),
    ("cins_army", "https://cinsscore.com/list/ci-badguys.txt"),
    ("blocklist_de", "https://lists.blocklist.de/lists/all.txt"),
]

OUTPUT_PATH = os.environ.get(
    "THREAT_INTEL_OUTPUT_PATH",
    "/usr/share/logstash/config/threat-intel/threat-intel.yml",
)
TMP_PATH = OUTPUT_PATH + ".tmp"

ioc_map = {
    "192.0.2.10": "test_c2_server",
    "192.0.2.55": "test_brute_force",
}

successful_feeds = 0

for provider, url in FEEDS:
  try:
    req = urllib.request.Request(
        url, headers={"User-Agent": "SOC-TI-Fetcher/1.0"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
      for raw_line in resp.read().decode("utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
          continue
        try:
          # Overí, že ide o validnú jednotlivú IPv4 adresu
          ip = str(ipaddress.IPv4Address(line))
          ioc_map.setdefault(ip, provider)
        except ValueError:
          continue
    successful_feeds += 1
  except Exception as e:
    print(f"Chyba pri sťahovaní {provider}: {e}")

if successful_feeds == 0:
  raise RuntimeError("Nepodarilo sa stiahnuť žiadny feed; existujúci zoznam zostal zachovaný.")

with open(TMP_PATH, "w", encoding="utf-8") as f:
  for ip, provider in ioc_map.items():
    f.write(f'"{ip}": "{provider}"\n')

os.replace(TMP_PATH, OUTPUT_PATH)
print(f"Uložených {len(ioc_map)} unikátnych IOC záznamov.")