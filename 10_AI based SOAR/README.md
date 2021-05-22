# AI Based SOAR

# Group Members

Rahul Vast(17104042),
Shruti Sawant(18204001),
Aishwarya Thorbole(18204002)

# Project Implementation

Our system here focus on orchestrating various security tools like Firewall, IDS, IPS, Threat Intelligence System, etc under a single roof. Thus making all this tools work together helps us to achieve every detail of the ongoing attack which is they sent to our AI Agent. AI will then try to filter out the false positives and the true positives further reducing the burden of filtering out overwhelming alerts. If AI founds the alert is truely an ongoing attack, it will try to collect the indicators of compromise, the evidences, etc. If the attack is known to the system, it will also try to mitigate it using playbooks, runbooks, etc else handover to user. Apart from this it also gather and threat intelligence from open sources, make it available in stix 2.1 and even maintains a Threat Intelligence Repository which is utilized for dealing with future attacks.
