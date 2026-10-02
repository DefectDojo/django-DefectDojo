from dojo.authorization.authorization import user_has_configuration_permission
from dojo.tool_config.models import Tool_Configuration


def get_authorized_tool_configurations(user):
    """
    Configs the user may select; empty queryset (not an error) if they lack view_tool_configuration.
    Back a ModelChoiceField with it so the accepted POST value is gated too, not just the rendered choices.
    """
    if user_has_configuration_permission(user, "dojo.view_tool_configuration"):
        return Tool_Configuration.objects.all().order_by("name")
    return Tool_Configuration.objects.none()
