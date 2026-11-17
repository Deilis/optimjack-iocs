# Optimizely Web / track.js hunting files

Release: `v1.0.0`, 17 November 2026.

Publication:

- <https://hecavex.com/en/research/optimizely-supply-chain-track-js/>
- <https://hecavex.com/lt/tyrimai/optimizely-supply-chain-track-js/>

## Files

- `check_snippet.py`: downloads or opens an Optimizely Web snippet, prints its SHA-256 and Last-Modified time, and reports the loader in plain or base64 form. It hashes and searches bytes and evaluates nothing.
- `decode_rules.py`: unpacks the rule-engine build of `track.js` (08:01 UTC) by reading its configuration as JSON and reversing each rule's base64 body. It evaluates nothing.
- `hunt.kql`: Microsoft Defender XDR advanced hunting query for the indicator hosts and addresses.
- `hunt.spl`: Splunk search over proxy or web gateway logs.
- `weblog.txt`: patterns for your own web server, CDN and CSP report logs, including the rule engine's `/px` and `/_geo` requests that land on the visited site's own origin.
- `structure.yar`: two YARA hunting rules, one for the loader inside a snippet and one for the decoded payload.

## What was tested

- `check_snippet.py` reports the loader in archived copies of an infected snippet with the plain loader and one with the base64 loader, and reports nothing in a snippet that was not written during the incident.
- `decode_rules.py` recovers both rules of the archived 08:01 build.
- Every string in `structure.yar` was checked as a plain substring against the decoded 14:47 build, the 08:01 build, three archived infected snippets and one clean snippet. No string matched the clean snippet. Three strings added later (`/hook.php`, `userled_user_id`, `W._qxc = 1`) were confirmed in the builds that contain them through URLScan's stored copies. The rules were not compiled or run with YARA.
- `hunt.kql` and `hunt.spl` were not executed. Field names (`url`, `dest_ip`, `http_referrer`, `RemoteUrl`) depend on your data model.

These are hunting aids. A match needs review before any block is built on it, and no match is not proof of absence: the loader's base64 form defeats a plain-text search for the host name, and the first-party `/px` trail exists only for the first builds of the morning.

## Handling

Indicator host names are written in live form inside the query and rule files because they have to match. Do not open them in a browser. The published article and the data bundle write them defanged.
