---
title: "Parser Documentation Template"
toc_hide: true
weight: 1
---

Use this template as part of writing a new parser.  

* Copy this .md file and add it to `/docs/content/en/connecting_your_tools/parsers/file` in the GitHub repository.
* Update the title to match the name of your new parser.
* Fill out all sections listed below.

### File Types
Specify all file types accepted by your parser (e.g., CSV, JSON, XML).  
Include instructions on how to create or export the acceptable file format from the related security tool.

### Total Fields in [File Format]
List the total number of fields in the file format (e.g., CSV, JSON, XML).  
Provide a brief description of each field and how it maps to DefectDojo's data model.  
Include all fields, noting any fields that are not parsed.

Fields in order of appearance:
1. **Field 1** - Description of how this field is mapped (e.g., maps to finding title, endpoint host, etc.).
2. **Field 2** - Description of how this field is mapped or not mapped.
3. **Field 3** - Description of how this field is mapped or not mapped.
4. **Field 4** - Description of how this field is mapped or not mapped.
continue for every field in the file.

### Field Mapping Details
For each finding created, include details of how the parser parses specific data. For example:
- Explains how endpoints are created (e.g., combining IP, Domain, Port, and Protocol fields).
- Describes how occurrences are handled (e.g., default `nb_occurences` set to 1, incremented for duplicates).
- Explains how deduplication is handled (e.g., using a hash of severity + title + description).
- Describes the default severity if no mapping is matched.

### Sample Scan Data
Add a link to the relevant unit tests or sample scan data folder in the GitHub repository. For example:
- [Sample Scan Data Folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/[parser-name])

### Link To Tool
Provide a link to the scanner or tool itself (e.g., GitHub repository, vendor website, or documentation). For example:
- [Tool Name](https://www.example.com/)
