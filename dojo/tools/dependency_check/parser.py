import hashlib
import logging
import re

from defusedxml import ElementTree

from dojo.models import Finding

logger = logging.getLogger(__name__)

SEVERITY = ['Info', 'Low', 'Medium', 'High', 'Critical']


class DependencyCheckParser(object):
    def get_field_value(self, parent_node, field_name):
        field_node = parent_node.find(self.namespace + field_name)
        field_value = '' if field_node is None else field_node.text
        return field_value

    def get_filename_from_dependency(self, dependency):
        return self.get_field_value(dependency, 'fileName')

    def get_filename_from_related_dependency(self, dependency, related_dependancy):
        file_name = self.get_field_value(dependency, 'fileName')
        file_path = self.get_field_value(dependency, 'filePath')

        # <dependency>
        #     <fileName>app1.war: library2.jar</fileName>
        #     <filePath>/var/lib/jenkins/workspace/dev/app1.war/WEB-INF/lib/library2.jar</filePath>

        file_name_parts = file_name.split(': ')
        artifact_name = file_name_parts[0]
        path_parts = file_path.split(artifact_name)
        path_prefix = path_parts[0]
        path_suffix = ''.join(path_parts[1:])

        print('artifact_name', artifact_name)
        print('path_prefix', path_prefix)
        print('path_suffix', path_suffix)

        # <relatedDependency>
        #     <filePath>/var/lib/jenkins/workspace/dev/app2.war/WEB-INF/lib/library2.jar</filePath>

        file_path_related = self.get_field_value(related_dependancy, 'filePath')
        artifact_name_related = file_path_related[len(path_prefix):]
        print(artifact_name_related)
        artifact_name_related = artifact_name_related[:(len(file_path_related) - len(path_prefix) - len(path_suffix))]
        print(artifact_name_related)

        print('artifact_name_related:', artifact_name_related)
        # file_name_related = artifact_name_related + ': ' + ''.join(file_name_parts[1:])
        file_name_related = file_name.replace(artifact_name, artifact_name_related)
        print(file_name_related)
        return file_name_related

    def get_finding_from_vulnerability(self, vulnerability, filename, test):
        name = self.get_field_value(vulnerability, 'name')
        cwes_node = vulnerability.find(self.namespace + 'cwes')
        if cwes_node is not None:
            cwe_field = self.get_field_value(cwes_node, 'cwe')
        else:
            cwe_field = self.get_field_value(vulnerability, 'cwe')
        description = self.get_field_value(vulnerability, 'description')

        title = '{0} | {1}'.format(filename, name)
        cve = name[:28]
        # Use CWE-1035 as fallback
        cwe = 1035  # Vulnerable Third Party Component
        if cwe_field:
            m = re.match(r"^(CWE-)?(\d+)", cwe_field)
            if m:
                cwe = int(m.group(2))
        cvssv2_node = vulnerability.find(self.namespace + 'cvssV2')
        cvssv3_node = vulnerability.find(self.namespace + 'cvssV3')
        if cvssv3_node is not None:
            severity = self.get_field_value(cvssv3_node, 'baseSeverity').lower().capitalize()
        elif cvssv2_node is not None:
            severity = self.get_field_value(cvssv2_node, 'severity').lower().capitalize()
        else:
            severity = self.get_field_value(vulnerability, 'severity').lower().capitalize()
        if severity in SEVERITY:
            severity = severity
        else:
            tag = "Severity is inaccurate : " + str(severity)
            title += " | " + tag
            print("Warning: Inaccurate severity detected. Setting it's severity to Medium level.\n" + "Title is :" + title)
            severity = "Medium"

        reference_detail = None
        references_node = vulnerability.find(self.namespace + 'references')

        if references_node is not None:
            reference_detail = ''
            for reference_node in references_node.findall(self.namespace +
                                                          'reference'):
                name = self.get_field_value(reference_node, 'name')
                source = self.get_field_value(reference_node, 'source')
                url = self.get_field_value(reference_node, 'url')
                reference_detail += 'name: {0}\n' \
                                     'source: {1}\n' \
                                     'url: {2}\n\n'.format(name, source, url)

        return Finding(
            title=title,
            file_path=filename,
            test=test,
            cwe=cwe,
            cve=cve,
            active=False,
            verified=False,
            description=description,
            severity=severity,
            numerical_severity=Finding.get_numerical_severity(severity),
            static_finding=True,
            references=reference_detail)

    def __init__(self, filename, test):
        self.dupes = dict()
        self.items = ()
        self.namespace = ''

        if filename is None:
            return

        content = filename.read()

        if content is None:
            return

        scan = ElementTree.fromstring(content)
        regex = r"{.*}"
        matches = re.match(regex, scan.tag)
        try:
            self.namespace = matches.group(0)
        except:
            self.namespace = ""

        dependencies = scan.find(self.namespace + 'dependencies')

        if dependencies:
            for dependency in dependencies.findall(self.namespace +
                                                   'dependency'):
                dependency_filename = self.get_filename_from_dependency(
                    dependency)

                filenames = [dependency_filename]

                related_dependencies = dependency.find(self.namespace + 'relatedDependencies')

                if related_dependencies:
                    for related_dependency in related_dependencies:
                        filenames.append(self.get_filename_from_related_dependency(dependency, related_dependency))

                print(filenames)

                for filename in filenames:
                    vulnerabilities = dependency.find(self.namespace +
                                                    'vulnerabilities')
                    if vulnerabilities is not None:
                        for vulnerability in vulnerabilities.findall(
                                self.namespace + 'vulnerability'):
                            finding = self.get_finding_from_vulnerability(
                                vulnerability, filename, test)

                            if finding is not None:
                                key_str = '{}|{}|{}'.format(finding.severity,
                                                            finding.title,
                                                            finding.description)
                                key = hashlib.md5(key_str.encode('utf-8')).hexdigest()

                                if key not in self.dupes:
                                    self.dupes[key] = finding

        self.items = list(self.dupes.values())
