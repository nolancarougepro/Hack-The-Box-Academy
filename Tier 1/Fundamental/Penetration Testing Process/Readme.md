## Introduction to the Penetration Tester Path :

We are highly skilled, and great trust is placed in us. Do not abuse this trust, `always work ethically and within the bounds of the law`. `Document, document, document`. When in doubt, document and overcommunicate.

## Academy Modules Layout :

![[0-PT-Process.webp]]

- The pre-engagement stage is where the main commitments, tasks, scope, limitations, and related agreements are documented in writing.
- Information gathering is an essential part of any assessment. Because information, the knowledge gained from it, the conclusions we draw, and the steps we take are based on the information available.
- The vulnerability assessment stage is divided into two areas. On the one hand, it is an approach to scan for known vulnerabilities using automated tools. On the other hand, it is analyzing for potential vulnerabilities through the information found. From this stage, there are four paths we can take, depending on how far we have come :

![[path.png]]

- Exploitation is the attack performed against a system or application based on the potential vulnerability discovered during our information gathering and enumeration. From this stage, there are four paths we can take, depending on how far we have come :

![[path_2.png]]

- In most cases, when we exploit certain services for our purposes to gain access to the system, we usually do not obtain the highest possible privileges. Bypassing these restrictions is the next step we take in this stage. From this stage, there are four paths we can take, depending on how far we have come :

![[path_3.png]]

- Lateral movement is one of the essential components for moving through a corporate network. We can use it to overlap with other internal hosts and further escalate our privileges within the current subnet or another part of the network. There are three paths we can take from this stage :

![[path_4.png]]

-  The `Proof-Of-Concept` (`POC`) is merely proof that a vulnerability found exists. From this stage, there is only one path we can take :

![[path_5.png]]

- The `Post-Engagement` stage also includes cleaning up the systems we exploit so that none of these systems can be exploited using our tools.

## Penetration Testing Overview : 

A `Penetration Test` (`Pentest`) is an organized, targeted, and authorized attack attempt to test IT infrastructure and its defenders to determine their susceptibility to IT security vulnerabilities. A pentest uses methods and techniques that real attackers use. 

`A pentest aims to uncover and identify ALL vulnerabilities in the systems under investigation and improve the security for the tested systems.`

`Vulnerability analysis` is a generic term that can include vulnerability or security assessments and penetration tests. In contrast to a penetration test, vulnerability or security assessments are performed using purely automated tools. Systems are checked against known issues and security vulnerabilities by running scanning tools like [Nessus](https://www.tenable.com/products/nessus), [Qualys](https://www.qualys.com/apps/vulnerability-management/), [OpenVAS](https://www.openvas.org/), and similar.

On the other hand, a pentest is a mix of automated and manual testing/validation and is performed after extensive, in most cases, manual information gathering.

Each pentest can be performed from two different perspectives:

- `External` or `Internal`

Many pentests are performed from an external perspective or as an anonymous user on the Internet. Most customers want to ensure that they are as protected as possible against attacks on their external network perimeter.

An internal pentest is when we perform testing from within the corporate network.

![[types_pentest.png]]

## Laws and Regulations : 

Each country has specific federal laws which regulate computer-related activities, copyright protection, interception of electronic communications, use and disclosure of protected health information, and collection of personal information from children, respectively. It is essential to follow these laws to protect individuals from `unauthorized access` and `exploitation of their data` and to ensure their privacy.

![[laws.png]]

![[precautionary.png]]

## Penetration Testing Process : 

`A penetration testing process is defined by successive steps and events performed by the penetration tester to find a path to the predefined objective.`

Here is the various stage for a pentest (cf Academy Modules Layout) :

![[stages.png]]

## Pre-Engagement : 

Pre-engagement is the stage of preparation for the actual penetration test. The entire pre-engagement process consists of three essential components :

1. Scoping questionnaire
    
2. Pre-engagement meeting
    
3. Kick-off meeting

Before any of these can be discussed in detail, a `Non-Disclosure Agreement` (`NDA`) must be signed by all parties. There are several types of NDAs : 

![[NDA.png]]

Here is a list of the documents needed before, duri ng and after the pentest : 

![[Documents.png]]

After initial contact is made with the client, we typically send them a `Scoping Questionnaire` to better understand the services they are seeking.

Finally, we will want to ask about information disclosure and evasiveness (if applicable to the assessment type):

- Is the Penetration Test black box (no information provided), grey box (only IP address/CIDR ranges/URLs provided), white box (detailed information provided)
    
- Would they like us to test from a non-evasive, hybrid-evasive (start quiet and gradually become "louder" to assess at what level the client's security personnel detect our activities), or fully evasive.

Based on the `Contract Checklist` and the input information shared in scoping, the `Penetration Testing Proposal` (`Contract`) and the associated `Rules of Engagement` (`RoE`) are created.

![[rules_of_engagment.png]]

## Information Gathering : 

We can obtain the necessary information relevant to us in many different ways. However, we can divide them into the following categories :

- Open-Source Intelligence
- Infrastructure Enumeration
- Service Enumeration
- Host Enumeration

All four categories should and must be performed by us for each penetration test. This is because the `information` is the main component that leads us to successful penetration testing and identifying security vulnerabilities.

Let's assume that our client wants us to see what information we can find about his company on the internet. For this purpose, we use what is known as `Open Source Intelligence` (`OSINT`). OSINT is a process for finding publicly available information on a target company or individuals that allows the identification of events (i.e., public and private meetings), external and internal dependencies, and connections.

During the infrastructure enumeration, we try to overview the company's position on the internet and intranet. We use services such as DNS to create a map of the client's servers and hosts and develop an understanding of how their `infrastructure` is structured. This includes name servers, mail servers, web servers, cloud instances, and more.

In service enumeration, we identify services that allow us to interact with the host or server over the network (or locally, from an internal perspective).

Once we have a detailed list of the customer's infrastructure, we examine every single host listed in the scoping document. We try to identify which `operating system` is running on the host or server, which `services` it uses, which `versions` of the services, and much more.

Another essential step is `Pillaging`. After hitting the `Post-Exploitation` stage, pillaging is performed to collect sensitive information locally on the already exploited host, such as employee names, customer data, and much more.

## Vulnerability Assessment : 

During the `vulnerability assessment` phase, we examine and analyze the information gathered during the information gathering phase. The vulnerability assessment phase is an analytical process based on the findings.

`An analysis is a detailed examination of an event or process, describing its origin and impact, that with the help of certain precautions and actions, can be triggered to support or prevent future occurrences.`

![[analysis_type.png]]

`Information Gathering` and `Vulnerability Research` can be considered a part of descriptive analysis. `Vulnerability Research`, we look for known vulnerabilities, exploits, and security holes that have already been discovered and reported. We can find vulnerability disclosures for each component using many different sources. These include, but are not limited to :

- [CVEdetails](https://www.cvedetails.com/)
- [Exploit DB](https://www.exploit-db.com)
- [Packet Storm Security](https://packetstormsecurity.com)
- [NIST](https://nvd.nist.gov/vuln/search?execution=e2s1)
- [Vulners](https://vulners.com)

This is where `Diagnostic Analysis` and `Predictive Analysis` is used.

Suppose we are unable to detect or identify potential vulnerabilities from our analysis. In that case, we will return to the `Information Gathering` stage and look for more in-depth information than we have gathered so far.

## Exploitation : 

During the `Exploitation` stage, we look for ways that these weaknesses can be adapted to our use case to obtain the desired role (i.e., a foothold, escalated privileges, etc.).

Once we have found one or two vulnerabilities during the `Vulnerability Assessment` stage that we can apply to our target network/system, we can prioritize those attacks. Which of those attacks we prioritize higher than the others depends on the following factors:

- Probability of Success
- Complexity
- Probability of Damage

First, we need to assess the `probability of successfully` executing a particular attack against the target. [CVSS Scoring](https://nvd.nist.gov/vuln-metrics/cvss) can help us here, using the [NVD calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator) better to calculate the specific attacks and their probability of success.

Priozitization Example : 

![[priority.png]]

## Post-Exploitation : 

The `Post-Exploitation` stage aims to obtain sensitive and security-relevant information from a local perspective and business-relevant information that, in most cases, requires higher privileges than a standard user. 

Evasive testing is divided into three different categories:

- **`Evasive`**
- **`Hybrid Evasive`**
- **`Non-Evasive`**

Since we have gained a new perspective on the system and the network of our target system in the Exploitation stage, we are basically in a new environment. In the `Post-Exploitation` stage, we go through the `Information Gathering` and `Vulnerability Assessment` stages again, which we can consider as parts of the current stage.

Pillaging is the stage where we examine the role of the host in the corporate network. We analyze the network configurations, including but not limited to:

Once we have an overview of the system, our immediate next step is maintaining access to the exploited host. This way, if the connection is interrupted, we can still access it. This step is essential and often used as the first step before the `Information Gathering` and `Pillaging` stages.

If we can maintain access and have a good overview of the system, we can use the information about the system and its services and any other data stored on it to repeat the `Vulnerability Assessment` stage, but this time from inside the system.

Privilege escalation is significant, and in most cases, it represents a critical moment that can open many more new doors for us. Getting the highest possible privileges on the system or domain is often crucial. Therefore we want to get the privileges of the `root` (on `Linux-based` systems) or the domain `administrator`/`local administrator`/`SYSTEM` (on `Windows-based` systems).

During the `Information Gathering` and `Pillaging` stage, we will often be able to find, among other things, considerable personal information and customer data. Some clients will want to check whether it is possible to exfiltrate these types of data. This means we try to transfer this information from the target system to our own. Security systems such as `Data Loss Prevention` (`DLP`) and `Endpoint Detection and Response` (`EDR`) help detect and prevent data exfiltration.

## Lateral Movement : 

If everything went well and we were able to penetrate the corporate network (`Exploitation`) successfully, gather locally stored information, and escalate our privileges (`Post-Exploitation`), we next enter the `Lateral Movement` stage.

In this stage, we want to test how far we can move manually in the entire network and what vulnerabilities we can find from the internal perspective that might be exploited. In doing so, we will again run through several phases:

1. Pivoting
2. Evasive Testing
3. Information Gathering
4. Vulnerability Assessment
5. (Privilege) Exploitation
6. Post-Exploitation

Some techniques allow us to use the exploited host as a proxy and perform all the scans from our attack machine or VM. In this way, we make non-routable networks (and therefore publicly unreachable) can still be reached. This allows us to scan them for vulnerabilities and penetrate deeper into the network. This process is also known as `Pivoting` or `Tunneling`.

There are many ways to protect against lateral movement, including network (micro) `segmentation`, `threat monitoring`, `IPS`/`IDS`, `EDR`, etc. To bypass these efficiently, we need to understand how they work and what they respond to.

Before we target the internal network, we must first get an `overview` of which systems and how many can be reached from our system. We return to the Information Gathering stage, but this time, we do it from inside the network with a different view of it.

Vulnerability assessment from the inside of the network differs from the previous procedures. This is because far more errors occur inside a network than on hosts and servers exposed to the Internet.

Once we have found and prioritized these paths, we can jump to the step where we use these to access the other systems. We often find ways to crack passwords and hashes and gain higher privileges. For example, we can use the tool [Responder](https://github.com/lgandx/Responder) to intercept NTLMv2 hashes. If we can intercept a hash from an administrator, then we can use the `pass-the-hash` technique to log in as that administrator (in most cases) on multiple hosts and servers.

After all, the `Lateral Movement` stage aims to move through the internal network. Existing data and information can be versatile and often used in many ways.

Once we have reached one or more hosts or servers, we go through the steps of the post-exploitation stage again for each system. Here we again collect system information, data from created users, and business information that can be presented as evidence.

## Proof-of-Concept : 

`Proof of Concept` (`PoC`) or `Proof of Principle` is a project management term. In project management, it serves as proof that a project is feasible in principle.

A `PoC` can have many different representations. For example, `documentation` of the vulnerabilities found can also constitute a PoC. The more practical version of a PoC is a `script` or `code` that automatically exploits the vulnerabilities found.

Once the administrators and developers have received such a script from us, it is easy for them to "fight" against our script. They focus on changing the systems so that the script we created no longer works.

## Post-Engagement : 

Once testing is complete, we should perform any necessary cleanup, such as deleting tools/scripts uploaded to target systems, reverting any (minor) configuration changes we may have made, etc. We should have detailed notes of all of our activities, making any cleanup activities easy and efficient.

Before completing the assessment and disconnecting from the client's internal network or sending "stop" notification emails to signal the end of testing (meaning no more interaction with the client's hosts), we must make sure to have adequate documentation for all findings that we plan to include in our report.

We should already have a detailed list of the findings we will include in the report and all necessary details to tailor the findings to the client's environment. Our report deliverable (which is covered in detail in the [Documentation & Reporting](https://academy.hackthebox.com/module/details/162) module) should consist of the following:

- An attack chain (in the event of full internal compromise or external to internal access) detailing steps taken to achieve compromise
- A strong executive summary that a non-technical audience can understand
- Detailed findings specific to the client's environment that include a risk rating, finding impact, remediation recommendations, and high-quality external references related to the issue
- Adequate steps to reproduce each finding so the team responsible for remediation can understand and test the issue while putting fixes in place
- Near, medium, and long-term recommendations specific to the environment
- Appendices which include information such as the target scope, OSINT data (if relevant to the engagement), password cracking analysis (if relevant), discovered ports/services, compromised hosts, compromised accounts, files transferred to client-owned systems, any account creation/system modifications, an Active Directory security analysis (if relevant), relevant scan data/supplementary documentation, and any other information necessary to explain a specific finding or recommendation further

In penetration test assessments, generally, we deliver a report marked `DRAFT` and give the client a chance to review and comment. Once the client has submitted feedback (i.e., management responses, requests for clarification/changes, additional evidence, etc.) either by email or (ideally) during a report review meeting, we can issue them a new version of the report marked `FINAL`.

