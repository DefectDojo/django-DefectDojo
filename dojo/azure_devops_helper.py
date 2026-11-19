"""
Helper module for Azure DevOps integration, specifically for sprint management.
This module provides utilities to fetch sprint information from Azure DevOps API
using the official azure-devops Python SDK.
"""

import logging
from datetime import date, datetime
from dojo.utils import get_product, extract_field_from_text_regex
from typing import Optional
from urllib.parse import urlparse
from dojo.celery import app
from azure.devops.connection import Connection
from azure.devops.v7_1.work.models import TeamContext
from azure.devops.v7_0.work_item_tracking.models import JsonPatchOperation, Wiql
from django.conf import settings
from msrest.authentication import BasicAuthentication

from dojo.models import GeneralSettings, Dojo_User, Finding

logger = logging.getLogger(__name__)


class AzureDevOpsSprintHelper:
    """Helper class to interact with Azure DevOps API for sprint information using the SDK"""

    def __init__(self, organization_url: str, project: str, team: str, pat: str):
        """
        Initialize Azure DevOps helper.

        Args:
            organization_url: Azure DevOps organization URL (e.g., https://dev.azure.com/myorg)
            project: Project name in Azure DevOps
            team: Team name in Azure DevOps
            pat: Personal Access Token for authentication
        """
        self.project = project
        self.team = team
        credentials = BasicAuthentication("", pat)
        connection = Connection(base_url=organization_url.rstrip("/"), creds=credentials)
        self._work_client = connection.clients.get_work_client()

    def get_next_sprint_start_date(self) -> Optional[date]:
        """
        Fetch the start date of the next sprint from Azure DevOps.

        The "next sprint" is the first future iteration after the current one.

        Returns:
            date object with the start date of the next sprint, or None if not found.

        Raises:
            Exception: If the SDK call fails.
        """
        iterations = self._get_team_iterations()

        if not iterations:
            logger.warning("No iterations found in Azure DevOps")
            return None

        current_sprint = None
        next_sprint = None

        for iteration in iterations:
            if getattr(iteration.attributes, "time_frame", None) == "current":
                current_sprint = iteration
                break

        if current_sprint and getattr(current_sprint.attributes, "finish_date", None):
            current_end = current_sprint.attributes.finish_date
            if isinstance(current_end, str):
                current_end = datetime.fromisoformat(current_end.replace("Z", "+00:00"))

            for iteration in iterations:
                attrs = iteration.attributes
                iter_start = getattr(attrs, "start_date", None)
                time_frame = getattr(attrs, "time_frame", None)
                if iter_start and time_frame == "future":
                    if isinstance(iter_start, str):
                        iter_start = datetime.fromisoformat(iter_start.replace("Z", "+00:00"))
                    if iter_start > current_end:
                        if next_sprint is None:
                            next_sprint = iteration
                        else:
                            next_start = next_sprint.attributes.start_date
                            if isinstance(next_start, str):
                                next_start = datetime.fromisoformat(next_start.replace("Z", "+00:00"))
                            if iter_start < next_start:
                                next_sprint = iteration
        else:
            # No current sprint: pick first future iteration
            for iteration in iterations:
                if getattr(iteration.attributes, "time_frame", None) == "future":
                    next_sprint = iteration
                    break

        if next_sprint:
            start_date = next_sprint.attributes.start_date
            if start_date:
                if isinstance(start_date, str):
                    start_date = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
                # Azure DevOps iteration dates are always midnight UTC and represent a
                # calendar date, not a specific instant in time. We extract just the date
                # component here (instead of returning an aware datetime) because Django
                # would otherwise re-localize an aware datetime to settings.TIME_ZONE when
                # it's saved into a DateField, shifting the date back a day for any
                # timezone behind UTC (e.g. midnight UTC becomes the previous day locally).
                if isinstance(start_date, datetime):
                    start_date = start_date.date()
                logger.info(f"Next sprint start date: {start_date}")
                return start_date

        logger.warning("Could not determine next sprint start date")
        return None

    def _get_team_iterations(self) -> list:
        """
        Fetch all iterations for the team using the Azure DevOps SDK.

        Returns:
            List of TeamSettingsIteration objects.

        Raises:
            Exception: If the SDK call fails.
        """
        team_context = TeamContext(project=self.project, team=self.team)
        logger.debug(f"Fetching iterations for project='{self.project}' team='{self.team}'")
        iterations = self._work_client.get_team_iterations(team_context) or []
        logger.debug(f"Found {len(iterations)} iterations in Azure DevOps")
        return iterations

class AzureDevOpsWorkItemHelper:
   
    @property
    def _organization_url(self):
        organization_url = GeneralSettings.get_value(
            "AZURE_DEVOPS_ORGANIZATION_URL",
            "https://test.azure.com/GrupoTest",
        )
        return organization_url

    @property
    def _project(self):
        project = GeneralSettings.get_value(
                "AZURE_DEVOPS_PROJECT",
                "project name",
            )
        return project

    @property
    def _team_name(self):
        team_name = GeneralSettings.get_value(
            "AZURE_DEVOPS_TEAM_NAME",
            "team name",
        )
        return team_name

    @property
    def _impact_team(self):
        impact_team = GeneralSettings.get_value(
                "AZURE_DEVOPS_IMPACT_TEAM",
                "impact team name",
            )
        return impact_team

    @property
    def _work_item_type(self):
        work_item_type = GeneralSettings.get_value(
            "AZURE_DEVOPS_WORK_ITEM_TYPE",
            "item type",
        )
        return work_item_type


    def _get_connection(self):
        credentials = BasicAuthentication("", settings.AZURE_DEVOPS_TOKEN)
        return Connection(base_url=self._organization_url.rstrip("/"), creds=credentials)

    def _get_profile_connection(self):
        parsed = urlparse(self._organization_url.rstrip("/"))
        org = parsed.path.strip("/") if parsed.netloc.endswith("dev.azure.com") else parsed.netloc
        if parsed.netloc.endswith("dev.azure.com"):
            profile_base = f"https://vssps.dev.azure.com/{org}/"
        else:
            profile_base = self._organization_url.rstrip("/")
        return Connection(
            base_url=profile_base,
            creds=BasicAuthentication("", settings.AZURE_DEVOPS_TOKEN),
        )

    def _get_allowed_values_for_field(wit_client, field_name, project, work_item_type):
        field_name = (field_name or "").strip()
        if not field_name:
            return []

        try:
            fields = wit_client.get_work_item_type_fields(project=project, type=work_item_type)
        except Exception:
            logger.warning("Unable to fetch field definitions for %s/%s", project, work_item_type)
            return []

        for field in fields or []:
            reference_name = getattr(field, "reference_name", None) or getattr(field, "referenceName", None)
            friendly_name = getattr(field, "name", None)
            if field_name in {reference_name, friendly_name} or (
                field_name == "Custom.EquipoImpactado"
                and (friendly_name or "").lower() == "equipo impactado"
            ):
                allowed_values = getattr(field, "allowed_values", None) or []
                if not allowed_values:
                    return []
                values = []
                for item in allowed_values:
                    if isinstance(item, str):
                        values.append(item)
                    elif isinstance(item, dict):
                        value = item.get("value") or item.get("name") or item.get("id")
                        if value is not None:
                            values.append(str(value))
                    else:
                        value = str(item)
                        if value:
                            values.append(value)
                return values
        return []
    
    def _get_description_DOR(self, user: Dojo_User, finding: int, description: str):
        """Get the description for Definition of Ready (DOR)."""
        findings = Finding.objects.filter(id__in=finding)
        user_name = f"{user.username} <{user.email}>"
        product = get_product(findings[0])
        description ="Findings: " + ",\n".join([str(f.id) for f in findings])
        return (
            f"- User requesting the advice:  {user_name} \n" \
            f"- EVC: {product.prod_type.name} \n" \
            f"- CELULA: {extract_field_from_text_regex(product.description, 'AREA RESPONSABLE TI')} \n" \
            f"Problem description: {description}"
        )


    def get_or_create_work_item(
        self,
        title,
        description,
        user,
        evidence_and_image,
        finding,

    ):
        target_type = self._work_item_type
        evidence_and_image = evidence_and_image if evidence_and_image else "Not file input"

        connection = self._get_connection()
        wit_client = connection.clients.get_work_item_tracking_client()
        work_client = connection.clients.get_work_client()

        try:
            description = self._get_description_DOR(user, finding, description)
            profile_connection = self._get_profile_connection()
            profile_client = profile_connection.clients.get_profile_client()
            me = profile_client.get_profile("me")
            team_context = TeamContext(project=self._project, team=self._team_name)
            team_field_values = work_client.get_team_field_values(team_context)
            area_path = getattr(team_field_values, "default_value", None)

            if not area_path:
                logger.warning("No default area path found for team: %s", self._team_name)
                return None
            iterations = work_client.get_team_iterations(
                team_context=team_context,
                timeframe="current",
            )
            if not iterations:
                logger.warning("No current iteration found")
                return None

            current_iteration = iterations[0]
            iteration_path = current_iteration.path
            logger.info("Current iteration: %s", iteration_path)

            wiql_query = (
                "SELECT [System.Id] "
                "FROM WorkItems "
                "WHERE [System.TeamProject] = @project "
                f"AND [System.Title] = '{title.replace("'", "''")}' "
                "AND [System.IterationPath] = @CurrentIteration"
            )
            query_result = wit_client.query_by_wiql(
                wiql=Wiql(query=wiql_query),
                team_context=team_context,
            )

            if query_result.work_items:
                work_item_id = query_result.work_items[0].id
                existing_wi = wit_client.get_work_item(id=work_item_id, project=self._project)

                if existing_wi.fields.get("System.State") == "Closed":
                    logger.info("Reactivating existing work item: %s", work_item_id)
                    patch_doc = [
                        JsonPatchOperation(
                            op="replace",
                            path="/fields/System.State",
                            value="Active",
                        )
                    ]
                    wit_client.update_work_item(
                        document=patch_doc,
                        id=work_item_id,
                        project=self._project,
                    )
                else:
                    logger.info("Using existing active work item: %s", work_item_id)
                return str(work_item_id)

            logger.info("Creating new %s for support case: %s", target_type, title)
            patch_doc = [
                JsonPatchOperation(
                    op="add",
                    path="/fields/System.Title",
                    value=title,
                ),
                JsonPatchOperation(
                    op="add",
                    path="/fields/System.Description",
                    value=description,
                ),
                JsonPatchOperation(
                    op="add",
                    path="/fields/System.AreaPath",
                    value=area_path,
                ),
                JsonPatchOperation(
                    op="add",
                    path="/fields/Custom.EquipoImpactado",
                    value=self._impact_team,
                ),
                JsonPatchOperation(
                    op="add",
                    path="/fields/Custom.Analistquereporta",
                    value="Asesoría técnica en seguridad",
                ),
                JsonPatchOperation(
                    op="add",
                    path="/fields/Custom.e13a15e9-0c55-4fb1-b218-f76f047d4e11",
                    value=evidence_and_image,
                ),
                JsonPatchOperation(
                    op="add",
                    path="/fields/System.CreatedBy",
                    value=f"{user.username} + <{user.email}>",
                ),
                JsonPatchOperation(
                    op="add",
                    path="/fields/System.IterationPath",
                    value=iteration_path,
                ),
            ]
            new_wi = wit_client.create_work_item(
                document=patch_doc,
                project=self._project,
                type=target_type,
            )
            logger.info("Created new %s work item: %s", target_type, new_wi.id)
            return str(new_wi.id)

        except Exception as exc:
            logger.error("Error getting or creating Azure DevOps support case %s", exc)
            return None


@app.task
def create_azure_work_item_task(
    title,
    description,
    user,
    evidence_and_image,
    finding_ids
):
    try:
        user_obj = Dojo_User.objects.get(username=user)
        if not finding_ids:
            raise ValueError("No finding IDs provided")

        work_item_id = AzureDevOpsWorkItemHelper().get_or_create_work_item(
            title,
            description,
            user=user_obj,
            evidence_and_image=evidence_and_image,
            finding=finding_ids,
        )
        if finding_ids and work_item_id:
            findings = Finding.objects.filter(id__in=finding_ids)
            for finding in findings:
                finding.add_note(
                    note_text=f"A work item was automatically created :{work_item_id}",
                    author=user_obj
                )
    except Exception as exc:
        import traceback
        print(traceback.format_exc())
        logger.error("Error creating Azure DevOps work item: %s", exc)