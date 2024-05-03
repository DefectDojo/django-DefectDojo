---
title: "Fortify"
toc_hide: true
---
You can either import the findings in .xml or in .fpr file format. </br>
If you import a .fpr file, the parser will look for the file 'audit.fvdl' and analyze it. An extracted example can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/fortify/audit.fvdl).

### Sample Scan Data
Sample Fortify scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/fortify).

#### Generate XML Output from Foritfy
This section describes how to import XML generated from a Fortify FPR. It assumes you 
already have, or know how to acquire, an FPR file. Once you have the FPR file you will need
use Fortify's ReportGenerator tool (located in the bin directory of your fortify install).
```FORTIFY_INSTALL_ROOT/bin/ReportGenerator```

By default, the Report Generator tool does _not_ display all issues, it will only display one
per category. To get all issues, copy the [DefaultReportDefinitionAllIssues.xml](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/fortify/DefaultReportDefinitionAllIssues.xml) to:  
```FORTIFY_INSTALL_ROOT/Core/config/reports```

Once this is complete, you can run the following command on your .fpr file to generate the
required XML:
```
./path/to/ReportGenerator -format xml -f /path/to/output.xml -source /path/to/downloaded/artifact.fpr -template DefaultReportDefinitionAllIssues.xml
```