# Initial Access Tradecraft

Public reporting describes a consistent set of lures. Knowing them is the best defence, because they target people who do not think of themselves as security-relevant.

## Fake job offers to employees

Recruiters on LinkedIn or Telegram approach engineers with attractive roles. The "technical assessment" is a repository or app that runs malware when installed or tested. Vendors track variants under names like "Contagious Interview" (Unit 42) and "Operation Dream Job" (ESET and others). Payloads reported include JavaScript stealers (BeaverTail) and Python backdoors (InvisibleFerret), aimed at browser wallets, keychains and credentials.

The execution trigger is usually mundane: an `npm install` that runs a `postinstall` script, a test file that loads an obfuscated module, or a "starter" backend that fetches code at startup. Later variants reported by vendors have moved the malicious code into dependencies, configuration files or remote fetches so that the repository itself looks clean at a glance. Some reporting also describes video-interview lures that ask candidates to install a "fixed" camera or conferencing driver.

## Fake candidates applying to you

The reverse direction: DPRK IT workers using fabricated identities apply for remote roles at Web3 companies. US authorities have issued multiple advisories. Risks range from revenue generation for the regime to insider access to code and keys.

Signals reported in public guidance include reluctance to appear on camera, requests to ship laptops to an address different from the stated home, use of remote-access tools on company devices, consumer VPN logins, and payment requests to third-party accounts. None is proof on its own; together they justify escalation.

## Trojanised trading and wallet apps

AppleJeus (CISA advisory AA21-048A) described fake crypto trading applications. The 3CX supply-chain compromise (2023) was reported by Mandiant to have started from a trojanised version of a trading application (X_Trader), a supply chain compromise that cascaded into another supply chain compromise.

## Compromised third parties

The Bybit case shows the pattern of attacking a **vendor** (Safe{Wallet}) to reach a high-value **customer**. DMM Bitcoin's reporting similarly described compromise of a wallet software vendor's employee, reportedly via a recruitment-themed lure.

## Defensive controls

| Lure | Control |
|---|---|
| Coding test repos | run in disposable VMs/containers; never on machines with signing or prod access |
| Fake candidates | live video interviews with ID verification, hardware shipped to verified address, watch for remote-access tools and VPN anomalies |
| Trojanised apps | software allowlisting; download from verified sources; EDR |
| Vendor compromise | independent verification of what vendor software asks you to sign (see **Web3 Supply Chain Security**) |
| Investor or partner outreach | meeting links and files only through company-managed tools; no installs requested by a counterpart |

The single most effective policy is simple to state: **nobody runs externally supplied code on a machine that can touch production, cloud consoles, or signing keys.** Make the safe path easy by providing a ready-made disposable environment.

## Worked example

_Not executed in this book's CI; verify locally. Outputs shown are expected results, not captured runs._

Goal: inspect an externally supplied "take-home" repository safely, before anyone runs it. This is a defensive review workflow, not malware analysis; if you find something malicious, stop, preserve the repository and hand it to your security team.

1. Clone into a disposable container with no network and no credentials.

```bash
mkdir -p ~/quarantine && cd ~/quarantine
git clone --depth 1 https://example.com/recruiter/assessment.git    # placeholder URL
docker run --rm -it --network none -v "$PWD/assessment:/src:ro" node:20-bookworm bash
```

2. Inside the container, list everything that would run automatically.

```bash
cd /src
jq '.scripts' package.json                      # preinstall / install / postinstall / prepare
grep -rnE '"(pre|post)?install"|"prepare"' --include=package.json . | grep -v node_modules
ls -la .vscode 2>/dev/null && cat .vscode/tasks.json 2>/dev/null   # editor auto-run tasks
```

3. Search for common obfuscation and remote-fetch shapes.

```bash
grep -rnE 'eval\(|new Function\(|child_process|Buffer\.from\([^)]*base64|atob\(' \
  --include=*.js --include=*.cjs --include=*.mjs --exclude-dir=node_modules . | head -50
find . -name '*.js' -size +100k -not -path '*/node_modules/*'      # unusually large single files
awk 'length > 2000 {print FILENAME": line "FNR" is "length" chars"}' $(git ls-files '*.js') 2>/dev/null
```

4. Check dependencies against the registry without installing them.

```bash
jq -r '.dependencies,.devDependencies | to_entries[] | "\(.key)@\(.value)"' package.json
# outside the container, check each name's age, maintainers and download counts on the registry
```

5. If you must run it, use `npm install --ignore-scripts` in a throwaway VM with egress logging, and record every outbound connection.

Expected result: a short note listing auto-run scripts, suspicious files and unusual dependencies. A clean result reduces risk; it does not prove safety, which is why execution still happens only in a disposable VM.

## Common pitfalls

- Running the test "just quickly" on a work laptop because the deadline the recruiter gave is tight. Urgency is part of the lure.
- Reviewing only the top-level code and missing `postinstall`, editor task files or a malicious dependency.
- Treating a fake candidate as an HR problem only. Revoke access, preserve logs and involve security.
- Relying on static IOCs (package names, domains) from old reports; they rotate quickly.
- No reporting channel, so the second engineer who receives the same lure never hears about the first.

## Exercises

1. Write a one-page "recruitment lure" awareness brief for your engineering team.
2. Design a hiring checklist that mitigates fake-identity candidates.
3. Set up a disposable VM workflow for any externally supplied code.
4. Run the review workflow above on a benign open-source starter repository and time it.

## Further reading

- Unit 42 on Contagious Interview: <https://unit42.paloaltonetworks.com>
- CISA AA21-048A (AppleJeus): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a>
- Mandiant on the 3CX supply chain compromise (2023): <https://cloud.google.com/blog/topics/threat-intelligence>
- US guidance on DPRK IT workers (FBI/State/Treasury, 2022 and later updates)
- npm scripts documentation: <https://docs.npmjs.com/cli/using-npm/scripts>
