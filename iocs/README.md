# Optimizely Web / track.js follow-up: research data

Release: `v1.1.0`
HECAVEX snapshot: 17 November 2026, about 08:20 UTC.

Publication:

- <https://hecavex.com/en/research/optimizely-supply-chain-track-js/>
- <https://hecavex.com/lt/tyrimai/optimizely-supply-chain-track-js/>

This bundle adds to Report URI's disclosure of 16 November 2026, "World's Largest Brands Infected With Malware Via Optimizely". It does not repeat their list of affected organisations.

## Files

- `iocs.csv`: every indicator used in the article, with its role and who first reported it (Report URI or HECAVEX).
- `track-js-builds.csv`: 26 builds of `track.js` with SHA-256, length, the server's Last-Modified time, ETag, first and last URLScan session, and what changed from the build before.
- `snippet-versions.csv`: versions of Optimizely snippets seen in URLScan sessions and Wayback captures, with the server's Last-Modified time, SHA-256 and whether the loader or an indicator request was present.
- `urlscan-observations.csv`: 424 URLScan sessions that requested an indicator host, with the `track.js` hash received and any rule-engine request sent to the page's own origin.
- `infrastructure.csv`: registration time, registrar, status, name servers, A record and certificates for the twelve indicator domains.
- `onchain-transfers.csv`: inflows to and outflows from the replacement addresses, with transaction IDs. The TRON rows are the account's complete TRC-20 history. The Bitcoin, Litecoin and Ethereum rows are the transfers discussed in the article.
- `lt-sweep.csv`: the 223 Lithuanian brand domains whose home pages were checked for an Optimizely snippet.

## Reading the files

- Indicator hosts are defanged (`[.]`, `hxxps`). Hosts in `urlscan-observations.csv` are defanged without exception, including legitimate sites, because the column mixes both.
- All times are UTC. `server_last_modified_utc` is the HTTP `Last-Modified` header as the scanner or archive received it.
- A URLScan row proves what one scan session received. It does not prove what every visitor received, that a handler fired or that anyone lost money.
- An inflow to a replacement address is a payment to an address that was hard-coded in the payload. Without confirmation from the payer it is not a proven theft.
- `lt-sweep.csv` reflects one request for each home page on 17 November 2026. A snippet loaded only on inner pages or through a tag manager is not visible to that method.
- All 26 builds were read as text from URLScan's stored responses through a signed-in session and compared as strings. Two were cross-checked against independent copies: `1ec4245b…` against the Wayback capture of 08:08:15 UTC, and `c2a34c57…` against the base64 body embedded in the Wayback capture of the BBC's snippet at 19:20:42 UTC. The payload text itself is not published here.

## Changes in v1.1.0

17 November 2026. The first release listed 21 builds. Scans of the payload host's own front page had been sampled, not read in full. All 464 public result pages are now read, which adds five builds (12:58:55, 13:19:49, 13:39:03, 13:53:22 and 15:21:40 UTC) and moves three feature times one build earlier: link and QR rewriting to 12:58:55, the card skimmer to 13:39:03 and the `Function.prototype.call` patch to 15:21:40. `track-js-builds.csv`, `urlscan-observations.csv`, `snippet-versions.csv` and `iocs.csv` are regenerated.

## Method

No sample was executed and no indicator host was contacted. Sources: the Wayback Machine, URLScan's search API, result pages and stored responses, RDAP, DNS over HTTPS, Cert Spotter, and the public APIs of Mempool, Litecoin Space, Blockscout, TronGrid, TonAPI and a Solana RPC node.

Hunting queries, a snippet checker and YARA rules are in [`../detections/`](../detections/).
