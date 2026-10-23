# Why One Actor Deserves a Book

Public reporting by governments, blockchain analytics firms and threat intelligence vendors consistently attributes a large share of all stolen cryptocurrency to clusters linked to the Democratic People's Republic of Korea (DPRK). Yearly totals in the billions of US dollars have been reported, with 2025 including the largest single crypto theft on record (Bybit, ~US$1.5B, attributed by the FBI to the "TraderTraitor" activity).

For Web3 defenders, this is the most capable and persistent adversary they are likely to face. Their tradecraft targets people and operations, not just code.

The reason it deserves a dedicated book is not glamour. It is that the defensive lessons are specific: recruitment-themed lures aimed at engineers, compromise of vendors in the signing path, patience measured in months, and a laundering operation that runs within minutes of a theft. Generic "patch and phish-train" programmes do not cover these well.

## A note on attribution

This book relies only on **public attributions** by authorities (FBI, US Treasury, Japan's National Police Agency, South Korean agencies) and reputable vendors. Names like Lazarus Group, APT38, TraderTraitor, AppleJeus and "Contagious Interview" refer to overlapping clusters as defined by the reporting organisations; vendors draw boundaries differently. Treat names as labels for tradecraft, not precise org charts.

Three levels are worth keeping apart in every note you write:

| Level | Example | Who can establish it |
|---|---|---|
| Observation | "Funds moved from the victim's cold wallet to address A at block N" | anyone with the chain data |
| Technical linkage | "Address A later funded address B used in another incident" or "the loader shares code with family X" | analysts, with evidence |
| Attribution | "Activity is attributed to TraderTraitor (DPRK)" | the named government or vendor, in a named report |

Your organisation will rarely be in a position to attribute. You can observe and link, and then cite who attributed. That is enough to defend.

## Selected publicly attributed incidents

| Year | Target | Approx. loss | Reported vector |
|---|---|---|---|
| 2022 | Ronin bridge | ~US$600M+ | validator key compromise; social engineering of an engineer reported |
| 2022 | Harmony Horizon bridge | ~US$100M | multisig key compromise |
| 2023 | Atomic Wallet users | ~US$100M | not fully disclosed; attributed by analytics firms |
| 2024 | DMM Bitcoin | ~US$300M | attributed by FBI/NPA to TraderTraitor; vendor-side social engineering reported |
| 2025 | Bybit | ~US$1.5B | Safe{Wallet} developer machine compromise → malicious frontend JS |

Figures are approximate, in US dollars at the time of the theft, as reported by the cited authorities and vendors. Ronin and Harmony were attributed by the FBI (2022 and 2023 respectively); Atomic Wallet by blockchain analytics firms such as Elliptic. Check the primary source before quoting a number.

## Recurring themes

1. **People first:** fake recruiters, fake investors, fake job candidates.
2. **Developer endpoints** as the entry point to production keys.
3. **Patience:** months of preparation before a single high-value theft.
4. **Laundering at scale** across chains, bridges, mixers and OTC brokers.

Each theme maps to a chapter: initial access (Chapter 2), the path from intrusion to the signing ceremony (Chapter 3), laundering (Chapter 4), hunting (Chapter 5) and the organisational programme (Chapter 6). Related material lives in the **Web3 Supply Chain Security**, **Browser Extension Wallet Malware** and **On-Chain Malware Analysis** books.

## Who is targeted

Reporting repeatedly names the same roles: software engineers (especially those with deployment or cloud access), DevOps staff, people who participate in multisig signing, executives approached as "investors", and HR teams receiving fraudulent candidates. Small companies are not safe because they are small: a vendor with ten staff whose software sits in a large exchange's signing path is a high-value target.

## Worked example

_Not executed in this book's CI; verify locally. Outputs shown are expected results, not captured runs._

Goal: build an evidence table for one incident from primary sources, with observation and attribution clearly separated. Use Bybit (2025) as the example; the method is the same for any case.

1. Collect primary sources and record each with date and URL in a source list: the FBI public service announcement (Feb 2025, ic3.gov), Bybit's own statements, Safe{Wallet}'s statement, and the forensic firms' published summaries.

2. Extract on-chain observations yourself. The FBI PSA listed attacker addresses; for each, pull first activity and balances.

```bash
export RPC=https://ethereum-rpc.publicnode.com
for a in 0x<address-from-psa-1> 0x<address-from-psa-2>; do
  echo "$a nonce=$(cast nonce $a --rpc-url $RPC) balance=$(cast balance $a --ether --rpc-url $RPC)"
done
```

3. Fill the table.

| # | Statement | Type | Source | Confidence |
|---|---|---|---|---|
| 1 | Cold-wallet Safe executed a transaction that changed its implementation | observation | tx hash, your trace | certain |
| 2 | Signers saw a different transaction in the UI | reported | Bybit / forensic summary | as reported |
| 3 | Malicious JS was served from Safe{Wallet} infrastructure | reported | Safe{Wallet} and forensic firm statements | as reported |
| 4 | Activity attributed to TraderTraitor (DPRK) | attribution | FBI PSA, Feb 2025 | as stated by FBI |

4. Add a "lessons for us" column that cites only the observation and reported rows. Attribution changes who you call; it rarely changes which control you fix.

Expected result: a single table you can hand to leadership, where every number and claim has a source and a type.

## Common pitfalls

- Mixing vendor cluster names as if they were the same group, or as if they were org units.
- Repeating loss figures from social media rather than the attributing authority or a named vendor report.
- Writing "we were hit by Lazarus" on day one of an incident. Say what you observed and let authorities attribute.
- Assuming the actor only targets large exchanges, and ignoring your role as someone else's vendor.
- Treating IOCs from old reports as current. Infrastructure rotates quickly.

## Exercises

1. Pick one incident above and read the primary attribution source. Separate observed facts from attribution.
2. Map which of your organisation's roles would be targeted first by this tradecraft.
3. Find your organisation's single point of failure that resembles the Bybit or Ronin vector.
4. Build the evidence table above for a second incident and compare which rows you could verify yourself.

## Further reading

- FBI PSA on the Bybit theft (Feb 2025): <https://www.ic3.gov>
- FBI/NPA statement on DMM Bitcoin (Dec 2024)
- CISA advisory "TraderTraitor: North Korean State-Sponsored APT Targets Blockchain Companies" (AA22-108A): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a>
- Chainalysis Crypto Crime reports: <https://www.chainalysis.com/blog/>
- UN Panel of Experts reports on DPRK sanctions (historic, through 2024)
