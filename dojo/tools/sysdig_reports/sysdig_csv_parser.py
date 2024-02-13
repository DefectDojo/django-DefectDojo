import csv
import io
from dojo.tools.sysdig_reports.sysdig_data import SysdigData


class CSVParser:
    """
    Sysdig CSV Data Parser
    """

    def parse(self, filename) -> SysdigData:

        if filename is None:
            return ()

        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')

        # normalise on lower case for consistency
        reader.fieldnames = [name.lower() for name in reader.fieldnames]

        csvarray = []

        for row in reader:
            # Compare headers to values.
            if len(row) != len(reader.fieldnames):
                raise ValueError(f"Number of fields in row ({len(row)}) does not match number of headers ({len(reader.fieldnames)})")

            # Check for a CVE value to being with
            if not row[reader.fieldnames[0]].startswith("CVE"):
                raise ValueError(f"Expected 'CVE' at the start but got: {row[reader.fieldnames[0]]}")

            csvarray.append(row)

        arr_csv_data = []

        for row in csvarray:

            csv_data_record = SysdigData()

            csv_data_record.vulnerability_id = row.get('vulnerability id', '')
            csv_data_record.severity = csv_data_record._map_severity(row.get('severity').upper())
            csv_data_record.package_name = row.get('package name', '')
            csv_data_record.package_version = row.get('package version', '')
            csv_data_record.package_type = row.get('package type', '')
            csv_data_record.package_path = row.get('package path', '')
            csv_data_record.image = row.get('image', '')
            csv_data_record.os_name = row.get('os name', '')
            csv_data_record.cvss_version = row.get('cvss version', '')
            csv_data_record.cvss_score = row.get('cvss score', '')
            csv_data_record.cvss_vector = row.get('cvss vector', '')
            csv_data_record.vuln_link = row.get('vuln link', '')
            csv_data_record.vuln_publish_date = row.get('vuln publish date', '')
            csv_data_record.vuln_fix_date = row.get('vuln fix date', '')
            csv_data_record.vuln_fix_version = row.get('fix version', '')
            csv_data_record.public_exploit = row.get('public exploit', '')
            csv_data_record.k8s_cluster_name = row.get('k8s cluster name', '')
            csv_data_record.k8s_namespace_name = row.get('k8s namespace name', '')
            csv_data_record.k8s_workload_type = row.get('k8s workload type', '')
            csv_data_record.k8s_workload_name = row.get('k8s workload name', '')
            csv_data_record.k8s_container_name = row.get('k8s container name', '')
            csv_data_record.image_id = row.get('image id', '')
            csv_data_record.k8s_pod_count = row.get('k8s pod count', '')
            csv_data_record.package_suggested_fix = row.get('package suggested fix', '')
            csv_data_record.in_use = row.get('in use', '') == 'TRUE'
            csv_data_record.risk_accepted = row.get('risk accepted', '') == 'TRUE'
            csv_data_record.registry_name = row.get('registry name', '')
            csv_data_record.registry_image_repository = row.get('registry image repository', '')
            csv_data_record.cloud_provider_name = row.get('cloud provider name', '')
            csv_data_record.cloud_provider_account_id = row.get('cloud provider account ID', '')
            csv_data_record.cloud_provider_region = row.get('cloud provider region', '')
            csv_data_record.registry_vendor = row.get('registry vendor', '')

            arr_csv_data.append(csv_data_record)

        return arr_csv_data
