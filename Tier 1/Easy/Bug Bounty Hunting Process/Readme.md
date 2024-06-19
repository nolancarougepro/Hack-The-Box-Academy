## Bug Bounty Programs :

As mentioned in this module's summary, we usually consider a bug bounty program as a crowdsourcing initiative through which individuals can receive recognition and compensation for discovering and reporting software bugs.

[HackerOne](https://www.hackerone.com) aptly describes their bug bounty platform (that can host bug bounty programs) as "Continuous testing, constant protection" and as something that can be integrated seamlessly into an organization's existing development life cycle.

A bug bounty program can be `private` or `public`.

- `(Private bug bounty programs` are not publicly available. Bug bounty hunters can only participate in a private bug bounty program upon receiving specific invitations.
- `Public bug bounty programs` are accessible by the entire hacking community.
- [Parent/Child Programs](https://docs.hackerone.com/en/articles/8368957-parent-child-programs) also exist where a bounty pool and a single cyber security team are shared between a parent company and its subsidiaries.

Something important to note is that the terms `Bug Bounty Program (BBP)` and `Vulnerability Disclosure Program (VDP)` should not be used interchangeably.

If you want to study the anatomy of a vulnerability disclosure program, refer to the following resource. [VDP vs. BBP](https://docs.hackerone.com/organizations/vdp-vs-bbp.html#gatsby-focus-wrapper)

If you want to become an established bug bounty hunter, you will have to strike a balance between professionalism and technical capability. We strongly suggest that you go over [HackerOne's Code of Conduct](https://www.hacker101.com/resources/articles/code_of_conduct) to familiarize yourself with such documents.

A bug bounty program usually consists of the following elements :

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%201/Easy/Bug%20Bounty%20Hunting%20Process/Images/bb_program.png)

One of the best online resources to identify bug bounty programs of your liking is [HackerOne's Directory](https://hackerone.com/directory/programs).

## Writing a Good Report : 

By documenting our findings clearly and concisely, we get straight to our point in a way that the security or triage team can comprehend. Most importantly, bug reports should include information on how exploitation of each vulnerability can be reproduced step-by-step.

The essential elements of a good bug report are (the element order can vary) :

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%201/Easy/Bug%20Bounty%20Hunting%20Process/Images/good_report.png)

MITRE describes [Common Weaknesses Enumeration (CWE)](https://cwe.mitre.org/) as a community-developed list of software and hardware weakness types. It serves as a common language, a measuring stick for security tools, and as a baseline for weakness identification, mitigation, and prevention efforts.

When it comes to communicating the severity of an identified vulnerability, then [Common Vulnerability Scoring System (CVSS)](https://www.first.org/cvss/) should be used, as it is a published standard used by organizations worldwide.

We can use the [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1) identify the severity of an identified vulnerability.

Find below some examples of using CVSS 3.1 to communicate the severity of vulnerabilities.

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%201/Easy/Bug%20Bounty%20Hunting%20Process/Images/ex_1.png)

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%201/Easy/Bug%20Bounty%20Hunting%20Process/Images/ex_2.png)

Find below some good report examples selected by HackerOne:

- [SSRF in Exchange leads to ROOT access in all instances](https://hackerone.com/reports/341876)
- [Remote Code Execution in Slack desktop apps + bonus](https://hackerone.com/reports/783877)
- [Full name of other accounts exposed through NR API Explorer (another workaround of #476958)](https://hackerone.com/reports/520518)
- [A staff member with no permissions can edit Store Customer Email](https://hackerone.com/reports/980511)
- [XSS while logging in using Google](https://hackerone.com/reports/691611)
- [Cross-site Scripting (XSS) on HackerOne careers page](https://hackerone.com/reports/474656)

## Interacting with Organizations/BBP Hosts : 

Well, to begin with, do not interact with them. Allow the security/triage team some time to process your report, validate your finding, and maybe ask questions.

If the security/triage team does not get back to you in a reasonable amount of time, then if the submission was through a bug bounty platform, you can contact [Mediation](https://docs.hackerone.com/hackers/hacker-mediation.html).

A professional bug report should be accompanied by professional communication. Remain calm and interact with the security/triage team as a security professional would.

During your interaction with the security/triage team, there could be disagreements about the severity of the bug or the bounty. A bug's impact and severity play a significant role during the bounty amount assignment. In the case of such a disagreement, proceed as follows.

- Explain your rationale for choosing this severity score and guide the security/triage team through each metric value you specified in the CVSS calculator. Eventually, you will come to an agreement.
- Go over the bug bounty program's policy and scope and ensure that your submission complies with both. Also, make sure that the bounty amount resembles the policy of the bug bounty program.
- If none of the above was fruitful, contact mediation or a similar platform service.
