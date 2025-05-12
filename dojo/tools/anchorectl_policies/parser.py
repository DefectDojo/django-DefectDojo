import json
import logging
import re
from datetime import datetime
from json.decoder import JSONDecodeError

from dojo.models import Finding

logger = logging.getLogger(__name__)


class AnchoreCTLPoliciesParser:
    def get_scan_types(self):
        return ["AnchoreCTL Policies Report"]

    def get_label_for_scan_types(self, scan_type):
        return "AnchoreCTL Policies Report"

    def get_description_for_scan_types(self, scan_type):
        return "AnchoreCTLs JSON policies report format. Both legacy list-based format and new evaluation-based format (from anchorectl policy evaluate -o json) are supported."

    def get_findings(self, filename, test):
        content = filename.read()
        try:
            data = json.loads(str(content, "utf-8"))
        except (JSONDecodeError, TypeError):
            data = json.loads(content)

        find_date = datetime.now()
        items = []

        # Handle new AnchoreCTL format (object with evaluations array)
        if isinstance(data, dict) and "evaluations" in data:
            logger.info("Detected new AnchoreCTL policies format")
            processed_data = []
            # Process each evaluation in the evaluations array
            for evaluation in data.get("evaluations", []):
                # Only process evaluations with findings
                if evaluation.get("numberOfFindings", 0) > 0 and evaluation.get("details"):
                    processed_item = {
                        "detail": [],
                        "digest": data.get("imageDigest", ""),
                        "finalAction": evaluation.get("finalAction", ""),
                        "finalActionReason": evaluation.get("finalActionReason", ""),
                        "lastEvaluation": evaluation.get("evaluationTime", ""),
                        "policyId": data.get("policyId", ""),
                        "status": evaluation.get("status", ""),
                        "tag": data.get("evaluatedTag", "")
                    }
                    
                    # Process details if they exist
                    for detail in evaluation.get("details", []):
                        processed_item["detail"].append(detail)
                    
                    processed_data.append(processed_item)
            
            data = processed_data
        
        if not isinstance(data, list):
            msg = "This doesn't look like a valid Anchore CTRL Policies report: Expected a list with image data at the root of the JSON data or an object with 'evaluations' array"
            raise TypeError(msg)

        for image in data:
            # Skip empty images
            if len(data) == 0:
                continue
                
            # Check for valid structure
            if not isinstance(image, dict):
                msg = "This doesn't look like a valid Anchore CTRL Policies report, expected dict object for image"
                raise ValueError(msg)
                
            # Handle legacy format with detail field
            if image.get("detail") is not None and isinstance(image.get("detail"), list):
                details = image.get("detail")
            # Handle newer format that might have details under a different structure
            elif image.get("details") is not None and isinstance(image.get("details"), list):
                details = image.get("details")
            else:
                msg = "This doesn't look like a valid Anchore CTRL Policies report, missing 'detail' or 'details' list object key for image"
                raise ValueError(msg)

            # Process each finding detail
            for result in details:
                try:
                    # Extract fields with fallbacks for different formats
                    gate = result.get("gate", "unknown")
                    description = result.get("description", "No description provided")
                    policy_id = result.get("policyId", image.get("policyId", "unknown"))
                    status = result.get("status", "unknown")
                    
                    # Handle image tag from different possible locations
                    image_name = result.get("tag", image.get("tag", "unknown:latest"))
                    
                    trigger_id = result.get("triggerId", "unknown")
                    
                    # Split repo and tag safely
                    if ":" in image_name:
                        repo, tag = image_name.split(":", 1)
                    else:
                        repo = image_name
                        tag = "latest"
                        
                    severity, active = get_severity(status, description)
                    vulnerability_id = extract_vulnerability_id(trigger_id)
                    title = (
                        policy_id
                        + " - gate|"
                        + gate
                        + " - trigger|"
                        + trigger_id
                    )
                    find = Finding(
                        title=title,
                        test=test,
                        description=description,
                        severity=severity,
                        active=active,
                        references=f"Policy ID: {policy_id}\nTrigger ID: {trigger_id}",
                        file_path=search_filepath(description),
                        component_name=repo,
                        component_version=tag,
                        date=find_date,
                        static_finding=True,
                        dynamic_finding=False,
                    )
                    if vulnerability_id:
                        find.unsaved_vulnerability_ids = [vulnerability_id]
                    items.append(find)
                except (KeyError, IndexError) as err:
                    msg = f"Invalid format or missing key: {err}. This parser supports both legacy AnchoreCTL format and the new format from 'anchorectl policy evaluate -o json'."
                    logger.warning(msg)
                    # Continue processing other findings instead of failing completely
                    continue
        return items


def map_gate_action_to_severity(status):
    gate_action_to_severity = {
        "stop": "Critical",
        "warn": "Medium",
    }
    if status in gate_action_to_severity:
        return gate_action_to_severity[status], True

    return "Low", True


def get_severity(status, description):
    parsed_severity = description.split()[0]
    valid_severities = ["LOW", "INFO", "UNKNOWN", "CRITICAL", "MEDIUM"]
    if parsed_severity in valid_severities:
        severity = "Info"
        if parsed_severity == "UNKNOWN":
            severity = "Info"
        elif status != "go":
            severity = parsed_severity.lower().capitalize()

        active = status != "go"

        return severity, active

    return map_gate_action_to_severity(status)


def policy_name(policies, policy_id):
    for policy in policies:
        if policy_id == policy["id"]:
            return policy["name"]
    return "unknown"


def extract_vulnerability_id(trigger_id):
    try:
        vulnerability_id, _ = trigger_id.split("+", 2)
    except ValueError:
        return None
    if vulnerability_id.startswith("CVE"):
        return vulnerability_id
    return None


def search_filepath(text):
    match = re.search(r" (/[^/ ]*)+/?", text)
    path = ""
    if match:
        try:
            path = match.group(0)
        except IndexError:
            path = ""
    return path.strip()
