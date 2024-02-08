---
title: "Blackduck Binary Analysis"
toc_hide: true
---

#### **What** ####
Black Duck Binary Analysis gives you visibility into open source and third-party dependencies that have been compiled into executables, libraries, containers, and firmware. You can analyze individual files using an intuitive user interface or Black Duck multifactor open source detection, which automates the scanning of binary artifacts.

Using a combination of static and string analysis techniques coupled with fuzzy matching against the Black Duck KnowledgeBase, Black Duck Binary Analysis quickly and reliably identifies components, even if they’ve been modified.

For more info, check out Black Duck Binary Analysis [here](https://www.synopsys.com/software-integrity/software-composition-analysis-tools/binary-analysis.html).

#### **Why** ####
Open source vulnerabilities aren’t the only security issues that might be lurking in application binaries.

Black Duck Binary Analysis can also detect if sensitive information like email addresses, authorization tokens, compiler switches, and passwords are exposed, and it identifies when mobile applications request excessive permissions—all of which puts your organization and users' personal data at risk.

#### **How** ####
* Initiate Black Duck Binary Analysis scans using the UI, REST API, or drivers such as [pwn_bdba_scan](https://github.com/0dayinc/pwn/blob/master/bin/pwn_bdba_scan) found within the security automation framework, [PWN](https://github.com/0dayinc/pwn)
* Import a single BDBA vulnerabilty csv results file into DefectDojo leveraging the UI, REST API, or drivers such as [pwn_defectdojo_importscan](https://github.com/0dayInc/pwn/blob/master/bin/pwn_defectdojo_importscan) or [pwn_defectdojo_reimportscan](https://github.com/0dayInc/pwn/blob/master/bin/pwn_defectdojo_reimportscan).

### Sample Scan Data
Sample Blackduck Binary Analysis scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/blackduck_binary_analysis).