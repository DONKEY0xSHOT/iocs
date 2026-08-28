# iocs

A collector for public malware IOCs. 
It fetches around two dozen threat feeds, normalizes them, tracks who reported what, and writes one sorted file you can use : )
The project currently collects 45M+ hashes, 1M+ domains, 800K+ URLs and 50K+ IPs!


## Advantages

- **Provenance per IOC** - every record lists the independent origins that reported it.
- **IOC confidence rating** - using the MISP decay model with per type lifetimes.
- **FP filtering** - Exclusions layered with the MISP warninglists. Every exclusion is written to `out/excluded.json` with a reason.
- **Offline lookup** - `lookup` uses the local file, so no network connection is needed.

## Usage

```bash
pip install -e .
python -m iocs collect
```

No API keys or configuration whatsoever : )

```bash
python -m iocs lookup 45.155.205.233
```

`lookup` answers offline and prints defanged. 

```bash
python -m iocs sources
 ```
 
`sources` lists every feed, its license, and whether its data may be passed on.
