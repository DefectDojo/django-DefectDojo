---
title: "Parser Documentation Template"
toc_hide: true
weight: 1
---

This template is designed to document a new or existing parser. Please feel free to improve with any additional information that might help your fellow security professionals.

* Copy this .md file and add it to `/docs/content/en/connecting_your_tools/parsers/file` in the GitHub repository.
* Update the title to match the name of your new or existing parser.
* Fill out all sections listed below. Please remove any instructions or examples found within each section or examples.

### File Types
_Specify all file types accepted by your parser (e.g., CSV, JSON, XML)._
_Include instructions on how to create or export the acceptable file format from the related security tool._

### Total Fields in [File Format]
Total data fields:  _Total number of fields contained in the security tool's export file._
Total data fields parsed:  _Total number of fields parsed into DefectDojo finding._
Total data fields NOT parsed: _Total number of fields NOT parsed into DefectDojo finding._

_Using the format below, provide a brief description of each field and how it maps to DefectDojo's data model._
_Include all fields found in the security tool's export tile, in order of appearance, and noting any fields that are not parsed._

Fields in order of appearance:
1. **Field 1** - _Description of how this field is mapped (e.g., maps to finding title, endpoint host.)_
2. **Field 2** - _Description of how this field is mapped / not mapped._
3. **Field 3** - _Description of how this field is mapped / not mapped._
4. **Field 4** - _Description of how this field is mapped / not mapped._
_(continue for every field in the file.)_

### Field Mapping Details
_For each finding created, include details of how the parser parses specific data. For example:_
- How endpoints are created (e.g., combining IP, Domain, Port, and Protocol fields).
- How occurrences are handled (e.g., default `nb_occurences` set to 1, incremented for duplicates).
- How deduplication is handled (e.g., using a hash of severity + title + description).
- Describes the default severity if no mapping is matched.

### Sample Scan Data or Unit Tests
_Add a link to the unit tests or sample scan data folder in the GitHub repository. For example:_
- [Sample Scan Data Folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/[parser-name])

### Link To Tool
_Provide a link to the scanner or tool itself (e.g., GitHub repository, vendor website, or documentation). For example:_
- [Tool Name](https://www.example.com/)
