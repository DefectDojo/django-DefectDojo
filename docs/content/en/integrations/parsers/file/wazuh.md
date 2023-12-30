---
title: "Wazuh Scanner"
toc_hide: true
---
Import findings from Wazuh. The export from wazuh should be done via the script [available here](https://github.com/quirinziessler/wazuh-findings-exporter). The script fetches the findings by Wazuh client groups and saves them as json, ready for upload. Have in mind to adjust the max file size via "DD_SCAN_FILE_MAX_SIZE" if the file is larger than the default value of 100MB.