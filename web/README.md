# Packet Analyzer Playground (web)

The browser demo behind **https://packet-analyzer-playground.vercel.app**.

- `index.html` — static UI: drag-and-drop a `.pcap`, or analyze the bundled
  sample; renders protocol/talker/port/flag/DNS tables, the flow table and a
  per-packet decode.
- `api/analyze.py` — a Vercel Python serverless function. `POST {sample:true}`
  or `{pcap_b64:"..."}` -> the analysis JSON. Classic `.pcap` only, 5 MB cap,
  50k packets; the file is parsed in memory and not stored. The sample capture
  is base64-embedded in the function.
- `pktanalyzer/` — a vendored snapshot of the package.

Deploy: `cd web && vercel deploy --prod`.
