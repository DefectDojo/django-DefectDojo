---
title: "Burp XML"
toc_hide: true
---
### File Types
DefectDojo parser accepts Burp Issue data as an .xml file.
To parse an HTML file instead, use this method: https://documentation.defectdojo.com/integrations/parsers/file/burp_enterprise/

When the Burp report is generated, **the recommended option is Base64
encoding both the request and response fields** - e.g. check the box
that says \"Base64-encode requests and responses\". These fields will be
processed and made available in the \'Finding View\' page.

See also: Burp documentation - XML export is described under "Export Issue data".  https://portswigger.net/burp/documentation/enterprise/work-with-scan-results/generate-reports

### Acceptable XML Format
All XML elements are required and will be parsed as strings.

~~~
<issues burpVersion="1.6.05" exportTime="Sat Sep 13 22:39:44 CEST 2014">
  <issue>
    <serialNumber>exampleSerialNumber</serialNumber>
    <type>exampleTypeNumber</type>
    <name>Example Issue Name</name>
    <host ip="192.168.187.137">http://bwa</host>
    <path><![CDATA[/bodgeit/basket.jsp]]></path>
    <location><![CDATA[/bodgeit/basket.jsp [b_id cookie]]]></location>
    <severity>Example Severity</severity>
    <confidence>Firm</confidence>
    <issueBackground><![CDATA[Example issue background.]]></issueBackground>
    <remediationBackground><![CDATA[Example remediation info.]]></issueDetail>
    <remediationDetail><![CDATA[Example remediation details.]]></remediationDetail>
    <requestresponse>
      <request method="POST" base64="true"><![CDATA[exampleDataString=]]></request>
      <response base64="true"><![CDATA[exampleBase64DataString]]></response>
      <responseRedirected>false</responseRedirected>
    </requestresponse>
  </issue>
  ...
</issues>
~~~

### Sample Scan Data
Sample Burp scans can be found at https://github.com/DefectDojo/sample-scan-files/tree/master/burp.