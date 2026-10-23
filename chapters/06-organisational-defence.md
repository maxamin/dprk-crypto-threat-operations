# Organisational Defence Programme

Technical controls fail if the organisation's processes give a single compromised person the ability to move funds. This chapter is a programme outline for Web3 companies.

## Principles

1. **No single endpoint can move funds.** Signing requires independent devices and independent verification.
2. **Assume every employee will be targeted** by recruitment lures.
3. **Verify vendors** whose software sits in the signing path.
4. **Practise incident response** for theft scenarios, including laundering response.

## Programme components

| Area | Actions |
|---|---|
| People | lure awareness training; reporting channel for suspicious recruiters; HR processes for identity verification |
| Endpoints | EDR everywhere; disposable environments for external code; separate signing devices |
| Identity | phishing-resistant MFA; short-lived credentials; monitoring for impossible travel and VPN use |
| Treasury operations | change tickets for every transfer; independent hash verification; delegatecall bans; timelocks for large moves |
| Vendors | security questionnaires focusing on build/deploy integrity; independent verification of vendor UIs |
| Response | runbook with SEAL 911, exchanges, stablecoin issuers and law enforcement contacts |

## Sequencing for a small team

Most Web3 companies cannot do everything at once. A practical order, based on which controls break the most reported chains for the least effort:

| Phase | Controls | Why first |
|---|---|---|
| 1 (weeks) | independent hash verification by each signer; disposable environment for external code; phishing-resistant MFA | breaks the Bybit-style and coding-test chains directly |
| 2 (1–3 months) | dedicated signing devices; delegatecall and owner-change policy; CDN/storage write alerting | reduces blast radius of an endpoint compromise |
| 3 (quarter) | vendor reviews; hiring identity checks; hunts from Chapter 5; tabletop | turns ad hoc controls into a programme |
| Ongoing | metrics and exercises | keeps controls alive as staff change |

## Measuring it

Pick a few metrics that show whether controls are used, not only whether they exist:

- Share of treasury transactions with independent hash verification recorded by every signer.
- Number of external-code executions in the disposable environment versus on managed laptops (from EDR).
- Time from "suspicious recruiter" report to organisation-wide notice.
- Time to share attacker addresses with SEAL 911 and exchanges in the last exercise.

## Tabletop scenario

> A senior engineer completed a "take-home test" from a recruiter two weeks ago. Today, a routine cold-to-warm transfer is scheduled. The signing frontend is hosted on infrastructure the engineer can modify.

Walk through: what detects it, who can stop the transfer, and how signers verify.

## Worked example

_Not executed in this book's CI; verify locally. Outputs shown are expected results, not captured runs._

Goal: run the tabletop above in 90 minutes and leave with owned actions. Participants: treasury signers, an engineering lead, security, legal or compliance, and communications.

1. Preparation (facilitator, one day before). Write four timed injects and the questions for each.

| Time | Inject | Questions |
|---|---|---|
| T+0 | EDR flagged `node.exe` reading a wallet extension directory on the engineer's laptop two weeks ago; nobody triaged it | Who owns that alert queue? Would it have been escalated? |
| T+20 | Signers open the usual UI; one notices the hardware wallet hash does not match what a colleague computed | Is there a written rule to stop? Who can halt the ceremony? |
| T+40 | A different signer already signed; threshold is one short | Can a signed transaction be invalidated (e.g. by consuming the nonce)? Who does it? |
| T+60 | Assume funds moved; attacker addresses known | Who contacts SEAL 911, issuers, exchanges? With what template? |

2. During the session, record decisions and gaps in a shared sheet, not in chat.

3. For each gap, write an action with an owner and a date. Typical outputs:

```text
A1  Security   Add triage SLA for wallet-storage access alerts           2 weeks
A2  Treasury   Written "stop on hash mismatch" rule, signed by all signers 1 week
A3  Treasury   Rehearse nonce-invalidation transaction on testnet         1 month
A4  Security   Pre-filled exchange/issuer notification template           2 weeks
```

4. Re-run a shortened version a quarter later and check which actions closed.

Expected result: four to eight concrete actions, each traceable to an inject, and a date for the next exercise.

## Common pitfalls

- Buying hardware wallets and calling signing "secure" without any independent verification of what is signed.
- Awareness training that describes phishing emails but not recruiter lures, fake candidates or investor outreach.
- Tabletops without treasury signers in the room.
- Contact lists for exchanges and issuers that are discovered to be stale during a real incident.
- Treating vendor questionnaires as a substitute for verifying what vendor software asks you to sign.

## Exercises

1. Run the tabletop with your treasury and engineering teams.
2. Score your organisation against the programme table.
3. Prepare the contact list for the response runbook.
4. Choose three metrics from this chapter and collect a baseline value for each.

## Further reading

- SEAL frameworks: <https://frameworks.securityalliance.org>
- CISA AA22-108A (TraderTraitor) mitigations section
- NIST SP 800-61 Rev. 3: <https://csrc.nist.gov/pubs/sp/800/61/r3/final>
- CISA tabletop exercise packages: <https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages>
