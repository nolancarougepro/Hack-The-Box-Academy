## Incident Handling : 

Incident handling (IH) has become an important part of an organization's defensive capability against cybercrime. While protective measures are constantly being implemented to prevent or lower the amount of security incidents, an incident handling capability is undeniably a necessity for any organization that cannot afford a compromise of its data confidentiality, integrity, or availability.

An `event` is an action occurring in a system or network. Examples of events are :

- A user sending an email
- A mouse click
- A firewall allowing a connection request

An `incident` is an event with a negative consequence. It is important to note that incident handling is not limited to intrusion incidents alone.

One of the most widely used resources on incident handling is [NIST's Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf). The document aims to assist organizations in mitigating the risks from computer security incidents by providing practical guidelines on responding to incidents effectively and efficiently.

## Cyber Kill Chain : 

This lifecycle describes how attacks manifest themselves.

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%201/Fundamental/Incident%20Handling%20Process/Images/Cyber_kill_chain.png)

The `recon` stage is the initial stage, and it involves the part where an attacker chooses their target.
In the `weaponize` stage, the malware to be used for initial access is developed and embedded into some type of exploit or deliverable payload.
In the `delivery` stage, the exploit or payload is delivered to the victim(s).
The `exploitation` stage is the moment when an exploit or a delivered payload is triggered.
In the `installation` stage, the initial stager is executed and is running on the compromised machine.
In the `command and control` stage, the attacker establishes a remote access capability to the compromised machine.
The final stage of the chain is the `action` or objective of the attack.

Our objective is to `stop an attacker from progressing further up the kill chain`, ideally in one of the earliest stages.

## Incident Handling Process Overview : 

Just like the cyber kill chain, there are different stages, when responding to an incident, defined as the `incident handling process`. The `incident handling process` defines a capability for organizations to prepare, detect, and respond to malicious events.

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%201/Fundamental/Incident%20Handling%20Process/Images/handling_process.webp)

Incident handlers spend most of their time in the first two stages, `preparation` and `detection & analysis`.

When a malicious event is detected, we then move on to the next stage and respond to the event `(but there should always be resources operating on the first two stages, so that there is no disruption of preparation and detection capabilities)`.

So, incident handling has two main activities, which are `investigating` and `recovering`. The investigation aims to :

- Discover the initial 'patient zero' victim and create an (ongoing if still active) incident timeline
- Determine what tools and malware the adversary used
- Document the compromised systems and what the adversary has done

## Preparation Stage (Part 1) : 

In the `preparation` stage, we have two separate objectives. The first one is the establishment of incident handling capability within the organization. The second is the ability to protect against and prevent IT security incidents by implementing appropriate protective measures.

During the preparation, we need to ensure that we have :

- Skilled incident handling team members (incident handling team members can be outsourced, but a basic capability and understanding of incident handling are necessary in-house regardless)
- Trained workforce (as much as possible, through security awareness activities or other means of training)
- Clear policies and documentation
- Tools (software and hardware)


Some of the written policies and documentation should contain an up-to-date version of the following information :

- Contact information and roles of the incident handling team members
- Contact information for the legal and compliance department, management team, IT support, communications and media relations department, law enforcement, internet service providers, facility management, and external incident response team
- Incident response policy, plan, and procedures
- Incident information sharing policy and procedures
- Baselines of systems and networks, out of a golden image and a clean state environment
- Network diagrams
- Organization-wide asset management database
- User accounts with excessive privileges that can be used on-demand by the team when necessary (also to business-critical systems, which are handled with the skills needed to administer that specific system). These user accounts are normally enabled when an incident is confirmed during the initial investigation and then disabled once it is over. A mandatory password reset is also performed when disabling the users.
- Ability to acquire hardware, software, or an external resource without a complete procurement process (urgent purchase of up to a certain amount). The last thing you need during an incident is to wait for weeks for the approval of a $500 tool.
- Forensic/Investigative cheat sheets

Moving forward, we also need to ensure that we have the right tools to perform the job. These include, but are not limited to :

- Additional laptop or a forensic workstation for each incident handling team member to preserve disk images and log files, perform data analysis, and investigate without any restrictions (we know malware will be tested here, so tools such as antivirus should be disabled). These devices should be handled appropriately and not in a way that introduces risks to the organization.
- Digital forensic image acquisition and analysis tools
- Memory capture and analysis tools
- Live response capture and analysis
- Log analysis tools
- Network capture and analysis tools
- Network cables and switches
- Write blockers
- Hard drives for forensic imaging
- Power cables
- Screwdrivers, tweezers, and other relevant tools to repair or disassemble hardware devices if needed
- Indicator of Compromise (IOC) creator and the ability to search for IOCs across the organization
- Chain of custody forms
- Encryption software
- Ticket tracking system
- Secure facility for storage and investigation
- Incident handling system independent of your organization's infrastructure

## Preparation Stage (Part 2) : 

Another part of the `preparation` stage is to protect against incidents.

[DMARC](https://dmarcly.com/blog/how-to-implement-dmarc-dkim-spf-to-stop-email-spoofing-phishing-the-definitive-guide#what-is-dmarc) is an email protection against phishing built on top of the already existing [SPF](https://dmarcly.com/blog/how-to-implement-dmarc-dkim-spf-to-stop-email-spoofing-phishing-the-definitive-guide#what-is-spf) and [DKIM](https://dmarcly.com/blog/how-to-implement-dmarc-dkim-spf-to-stop-email-spoofing-phishing-the-definitive-guide#what-is-dkim). The idea behind DMARC is to reject emails that 'pretend' to originate from your organization.

Some highly important actions (that actually work) to note and do something about are :

- Disable LLMNR/NetBIOS
- Implement LAPS and remove administrative privileges from regular users
- Disable or configure PowerShell in "ConstrainedLanguage" mode
- Enable Attack Surface Reduction (ASR) rules if using Microsoft Defender
- Implement whitelisting. We know this is nearly impossible to implement. Consider at least blocking execution from user-writable folders (Downloads, Desktop, AppData, etc.). These are the locations where exploits and malicious payloads will initially find themselves. Remember to also block script types such as .hta, .vbs, .cmd, .bat, .js, and similar. Please pay attention to [LOLBin](https://lolbas-project.github.io) files while implementing whitelisting. Do not overlook them; they are really used in the wild as initial access to bypass whitelisting.
- Utilize host-based firewalls. As a bare minimum, block workstation-to-workstation communication and block outbound traffic to LOLBins
- Deploy an EDR product. At this point in time, [AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps) provides great visibility into obfuscated scripts for antimalware products to inspect the content before it gets executed. It is highly recommended that you only choose products that integrate with AMSI.

Network segmentation is a powerful technique to avoid having a breach spread across the entire organization. Additionally, when speaking of network protection you should consider IDS/IPS systems. Additionally, ensure that only organization-approved devices can get on the network

A common mistake is that admin users either have a weak (but often complex) password or a shared password with their regular user account (which can be obtained via multiple attack vectors such as keylogging).

Perform continuous vulnerability scans of your environment and remediate at least the "high" and "critical" vulnerabilities that are discovered.

Training users to recognize suspicious behavior and report it when discovered is a big win for us.

The best way to detect security misconfigurations or exposed critical vulnerabilities is by looking for them from the perspective of an attacker. Doing your own reviews (or hiring a third party if the skillset is missing from the organization) will ensure that when an endpoint device is compromised, the attacker will not have a one-step escalation possibility to high privileges on the network.

## Detection & Analysis Stage (Part 1) : 

The `detection & analysis` phase involves all aspects of detecting an incident, such as utilizing sensors, logs, and trained personnel. It also includes information and knowledge sharing, as well as utilizing context-based threat intelligence.

Threats are introduced to the organization via an infinite amount of attack vectors, and their detection can come from sources such as :

- An employee that notices abnormal behavior
- An alert from one of our tools (EDR, IDS, Firewall, SIEM, etc.)
- Threat hunting activities
- A third-party notification informing us that they discovered signs of our organization being compromised

It is highly recommended to create levels of detection by logically categorizing our network as follows.

- Detection at the network perimeter (using firewalls, internet-facing network intrusion detection/prevention systems, demilitarized zone, etc.)
- Detection at the internal network level (using local firewalls, host intrusion detection/prevention systems, etc.)
- Detection at the endpoint level (using antivirus systems, endpoint detection & response systems, etc.)
- Detection at the application level (using application logs, service logs, etc.)

When a security incident is detected, you should conduct some initial investigation and establish context before assembling the team and calling an organization-wide incident response. To sum up, we should aim to collect as much information as possible at this stage about the following :

- Date/Time when the incident was reported. Additionally, who detected the incident and/or who reported it ?
- How was the incident detected ?
- What was the incident? Phishing? System unavailability ? etc.
- Assemble a list of impacted systems (if relevant)
- Document who has accessed the impacted systems and what actions have been taken. Make a note of whether this is an ongoing incident or the suspicious activity has been stopped
- Physical location, operating systems, IP addresses and hostnames, system owner, system's purpose, current state of the system
- (If malware is involved) List of IP addresses, time and date of detection, type of malware, systems impacted, export of malicious files with forensic information on them (such as hashes, copies of the files, etc.

With that information at hand, we can make decisions based on the knowledge we have gathered.

When handling a security incident, we should also try to answer the following questions to get an idea of the incident's severity and exten :

- What is the exploitation impact ?
- What are the exploitation requirements ?
- Can any business-critical systems be affected by the incident ?
- Are there any suggested remediation steps ?
- How many systems have been impacted ?
- Is the exploit being used in the wild ?
- Does the exploit have any worm-like capabilities ?

## Detection & Analysis Stage (Part 2) : 

The investigation starts based on the initially gathered (and limited) information that contain what we know about the incident so far. With this initial data, we will begin a 3-step cyclic process that will iterate over and over again as the investigation evolves. This process includes :

- Creation and usage of indicators of compromise (IOC)
- Identification of new leads and impacted systems
- Data collection and analysis from the new leads and impacted systems

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%201/Fundamental/Incident%20Handling%20Process/Images/investigation_new.webp)

In order to reach a conclusion, an investigation should be based on valid leads that have been discovered not only during this initial phase but throughout the entire investigation process.

An indicator of compromise is a sign that an incident has occurred. IOCs are documented in a structured manner, which represents the artifacts of the compromise. Examples of IOCs can be IP addresses, hash values of files, and file names. In fact, because IOCs are so important to an investigation, special languages such as OpenIOC have been developed to document them and share them in a standard manner.

After searching for IOCs, you expect to have some hits that reveal other systems with the same signs of compromise. These hits may not be directly associated with the incident we are investigating.

Once we have identified systems that included our IOCs, we will want to collect and preserve the state of those systems for further analysis in order to uncover new leads and/or answer investigative questions about the incident.

## Containment, Eradication, & Recovery Stage : 

In this stage, we take action to prevent the spread of the incident. We divide the actions into `short-term containment` and `long-term containment`. It is important that containment actions are coordinated and executed across all systems simultaneously.

In short-term containment, the actions taken leave a minimal footprint on the systems on which they occur. Some of these actions can include, placing a system in a separate/isolated VLAN, pulling the network cable out of the system(s) or modifying the attacker's C2 DNS name to a system under our control or to a non-existing one.

In long-term containment actions, we focus on persistent actions and changes. These can include changing user passwords, applying firewall rules, inserting a host intrusion detection system, applying a system patch, and shutting down systems.

Once the incident is contained, eradication is necessary to eliminate both the root cause of the incident and what is left of it to ensure that the adversary is out of the systems and network. Some of the activities in this stage include removing the detected malware from systems, rebuilding some systems, and restoring others from backup.

In the recovery stage, we bring systems back to normal operation. Of course, the business needs to verify that a system is in fact working as expected and that it contains all the necessary data.

All restored systems will be subject to heavy logging and monitoring after an incident, as compromised systems tend to be targets again if the adversary regains access to the environment in a short period of time. Typical suspicious events to monitor for are :

- Unusual logons (e.g. user or service accounts that have never logged in there before)
- Unusual processes
- Changes to the registry in locations that are usually modified by malware

## Post-Incident Activity Stage : 

In this stage, our objective is to document the incident and improve our capabilities based on lessons learned from it.

The final report is a crucial part of the entire process. A complete report will contain answers to questions such as :

- What happened and when ?
- Performance of the team dealing with the incident in regard to plans, playbooks, policies, and procedures
- Did the business provide the necessary information and respond promptly to aid in handling the incident in an efficient manner? What can be improved ?
- What actions have been implemented to contain and eradicate the incident ?
- What preventive measures should be put in place to prevent similar incidents in the future ?
- What tools and resources are needed to detect and analyze similar incidents in the future ?
