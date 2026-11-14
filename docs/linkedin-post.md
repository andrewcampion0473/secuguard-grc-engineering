# LinkedIn post

A draft to post with the 90-second video. Change anything that does not sound like you. Put the repository link in the first comment if you find LinkedIn shows the post to fewer people when the link is in the body.

## The post

Most compliance evidence is still a screenshot in a folder. It is out of date the day it is taken, nothing proves it is real, and the same setting gets captured again for every framework that asks about it.

I wanted to see what the alternative looks like in practice, so I built one.

SecuGuard is a fictional card-issuing company running in a real AWS account. Around it I built a system that:

- Collects evidence from AWS every day, with read-only access and no stored keys
- Fingerprints every file and links each run to the one before it, so any edit is caught
- Stores the copy of record where it cannot be deleted, even by an administrator
- Runs 26 checks, each written once and reported against PCI DSS 4.0.1, SOC 2, and FedRAMP 20x
- Works out PCI scope from the firewall rules and flags systems that are labelled out of scope but can reach card data
- Blocks a risky infrastructure change on GitHub before it can be merged

I planted weaknesses on purpose, because a tool that only ever says "compliant" proves nothing.

It is a demonstration, not a compliance programme. It speaks to 16 of FedRAMP 20x's 46 Key Security Indicators and lists the other 30 as not covered. The mappings are my own reading of each framework.

I come from technical writing, so the repository includes a manual that takes someone with no AWS or terminal experience from nothing to a working system.

Code, manual, and a sample report: https://github.com/andrewcampion0473/secuguard-grc-engineering

#GRC #GRCEngineering #PCIDSS #SOC2 #FedRAMP #ComplianceAutomation

## A shorter version

I built a small fictional company in AWS and a system that collects its compliance evidence automatically, proves the evidence has not been altered, and grades it once against PCI DSS, SOC 2, and FedRAMP 20x. It also blocks risky changes before they are made. 90-second walkthrough below. Code and a plain-language manual: https://github.com/andrewcampion0473/secuguard-grc-engineering

## Notes

- The video's first three seconds decide whether people keep watching. The "screenshot in a folder" line is the hook, so keep it first.
- If someone asks whether this replaces an audit, the honest answer is no. It replaces the evidence gathering, and it shows an assessor exactly what was tested and what was not.
