# Usage
To use this importer you will need an XML generated from a Fortify FPR. This guide assumes you 
already have, or know how to acquire, an FPR file. Once you have the FPR file you will need
use Fortify's ReportGenerator tool (located in the bin directory of your fortify install).
```FORTIFY_INSTALL_ROOT/bin/ReportGenerator```

### Getting All Issues
By default, the Report Generator tool does _not_ display all issues, it will only display one
per category. To get all issues, copy the DefaultReportDefinitionAllIssues.xml file from this
directory to:  
```FORTIFY_INSTALL_ROOT/Core/config/reports```

Once this is complete, you can run the following command on your .fpr file to generate the
required XML:
```
./path/to/ReportGenerator -format xml -f /path/to/output.xml -source /path/to/downloaded/artifact.fpr -template DefaultReportDefinitionAllIssues.xml
```
