# OPTIMJACK: indicators and detections for the Optimizely `track.js` attack

Indicators of compromise, hunting queries and YARA rules for the compromise of Optimizely Web snippets on
16 November 2026. Report URI disclosed the attack that day. This repository holds what HECAVEX added in a follow-up
investigation: all 26 builds of the injected `track.js`, the infrastructure behind it and the payments to the
attacker's wallets.

**Full write-up:** [OPTIMJACK: Inside track.js, 26 Builds and the Money Trail of the Optimizely Attack](https://hecavex.com/en/research/optimizely-supply-chain-track-js/)
(also [in Lithuanian](https://hecavex.com/lt/tyrimai/optimizely-supply-chain-track-js/)).

## What the payload did

A few lines added to the Project JavaScript of Optimizely snippets loaded `track.js` from an attacker's host on every
page that used the snippet. Over one day the file changed 26 times. Depending on the build, it:

- replaced cryptocurrency addresses on the page and in the clipboard with the attacker's own;
- rewrote payment links and QR codes;
- skimmed payment card fields and sent them to `card.php`;
- collected cookies for a few hours (`hook.php`);
- loaded an iOS exploit kit through a separate router domain.

## Main indicators

Hosts are defanged here and in the CSV files. The query and rule files in `detections/` contain them in live form,
because they have to match.

| Type | Indicator | Role |
| --- | --- | --- |
| Domain | `1688360[.]cc` | Payload host and collector: `/track.js`, `/hit.php`, `/card.php`, `/hook.php` |
| Domain | `5vobauua3ojpklx[.]icu` | iOS router, `/boot.js` |
| Domain | `eil786npto9u5bq[.]icu` | Second iOS router, `/JIUJIU888/index.js` |
| Domain | `l7bcsnwc7nzr3uo[.]icu` | Telemetry, `POST /api/iptj` |
| Domain | `webshell[.]lol` | Injector, `/get.js` |
| Marker | `window._k7`, `window._cc`, `window._shot` | Clipper, card skimmer and screenshot already running on the page |
| BTC | `19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW` | Replacement address |

The complete list, with who first reported each indicator, is in [`iocs/iocs.csv`](iocs/iocs.csv).

## Files

### `iocs/`

| File | Contents |
| --- | --- |
| `iocs.csv` | Every indicator: domains, URL paths, hashes, page markers and wallet addresses |
| `track-js-builds.csv` | The 26 builds of `track.js` with SHA-256, size, server time and what changed in each |
| `snippet-versions.csv` | Versions of infected and clean Optimizely snippets seen in URLScan and the Wayback Machine |
| `urlscan-observations.csv` | 424 URLScan sessions that requested an indicator host |
| `infrastructure.csv` | Registration, registrar, name servers, A records and certificates for the indicator domains |
| `onchain-transfers.csv` | Transfers to and from the replacement addresses, with transaction IDs |
| `lt-sweep.csv` | 223 Lithuanian brand domains checked for an Optimizely snippet |

### `detections/`

| File | Use |
| --- | --- |
| `structure.yar` | Two YARA hunting rules: the loader inside a snippet, and the decoded payload |
| `hunt.kql` | Microsoft Defender XDR advanced hunting query |
| `hunt.spl` | Splunk search over proxy or web gateway logs |
| `weblog.txt` | Patterns for your own web server, CDN and CSP report logs |
| `check_snippet.py` | Checks an Optimizely snippet (URL or file) for the loader, in plain or base64 form |
| `decode_rules.py` | Unpacks the rule-engine build of `track.js` without running it |

Each folder has its own README with the method, what was tested and the limits of the data.

## Check your own snippet

```sh
python3 detections/check_snippet.py https://cdn.optimizely.com/js/<your project id>.js
```

The script downloads the file, prints its SHA-256 and `Last-Modified` time and reports whether the loader is in it.
It searches bytes and evaluates nothing.

## Handling

No sample was executed in this research and no indicator host was contacted. The payload text is not published
here. Do not open the indicator hosts in a browser.

The rules and queries are hunting aids. Review a match before you block on it, and do not read an empty result as
proof that a site was clean.

## Credit and use

Report URI disclosed the attack, and StepSecurity published an independent analysis. `iocs.csv` records who
first reported each indicator.

Use these files freely for defensive work. If they end up in a report or a product, please cite the article:

> Deividas Lis, "OPTIMJACK: Inside track.js, 26 Builds and the Money Trail of the Optimizely Attack", HECAVEX,
> 17 November 2026. https://hecavex.com/en/research/optimizely-supply-chain-track-js/

Corrections are welcome through an issue here or the [contact page](https://hecavex.com/en/contact/).
