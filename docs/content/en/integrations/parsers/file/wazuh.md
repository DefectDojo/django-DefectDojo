---
title: "Wazuh Scanner"
toc_hide: true
---

Import findings from Wazuh. The export from Wazuh can be done via 2 ways. Choose the one which you prefer.

- export the Wazuh findings from API and upload them to DefectDojo as json file. This method may be the easiest one but does export all known vulnerabilities at once. It is not possible to sort them after clients or any other categories. You will receive all vulnerabilities in one engagement.
- export the findings via the script [available here](https://github.com/quirinziessler/wazuh-findings-exporter). The script fetches the findings by Wazuh client groups and saves them as json, ready for upload. You will receive one file per group allowing you to separate the clients via engagements in Wazuh. It also exports the endpoints hostname and displays them in DefectDojo UI.

Independent of your above choice: Have in mind to adjust the max file size via "DD_SCAN_FILE_MAX_SIZE" if you see files larger than the default value of 100MB. Depending on the amount and category of integrated devices, the file size jumps rapidly.