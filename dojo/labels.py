"""
This module provides centralized access to application text copy. For the time being, this centralization is necessary
as some elements (forms.py, templates) require access to labels from across different model packages.

Each model package that needs to support text copy can provide its own 'labels.py' that can be registered here. That
module should provide a set of stable dictionary keys that can be used to reference text copy within the app, as well as
a dictionary that maps these keys to the text copy.

In this file, the sets of keys and the text copy dictionaries for all such model packages should be imported and added
to the corresponding structures: LabelsProxy should extend the set of keys, and the 'labels' variable should have the
text copy dictionary added to it. The LabelsProxy serves to provide easy autocomplete/linter compatibility with the
full list of text copy keys that exist over the program, until things are more modularized on a per-model basis.

For templates, a `label` context processor has been added, so developers can just use labels.ATTRIBUTE_NAME.

In views/Python code, developers should first import get_labels() and set it to a variable, e.g., labels = get_labels().
Then they can simply use labels.ATTRIBUTE_NAME.

For the stable keys, some conventions used:
    Each copy attribute name starts with a noun representing the overarching model/object type the label is for.
    Attribute suffixes are as follows:
        _LABEL -> short label, used for UI/API fields
        _MESSAGE -> a longer message displayed as a toast or displayed on the page
        _HELP -> helptext (for help_text kwargs/popover content)
"""
import logging

from dojo.asset.labels import AssetLabelsKeys
from dojo.asset.labels import labels as asset_labels
from dojo.organization.labels import OrganizationLabelsKeys
from dojo.organization.labels import labels as organization_labels
from dojo.system_settings.labels import SystemSettingsLabelsKeys
from dojo.system_settings.labels import labels as system_settings_labels

logger = logging.getLogger(__name__)


class LabelsProxy(
    AssetLabelsKeys,
    OrganizationLabelsKeys,
    SystemSettingsLabelsKeys,
):

    """
    Proxy class for text copy. The purpose of this is to allow easy access to the copy from within templates, and to
    allow for IDE code completion. This inherits from the various copy key classes so IDEs can statically determine what
    attributes ("labels") are available. After initialization, all attributes defined on this class are set to the value
    of the appropriate text.
    """

    def _get_label_entries(self):
        """Returns a dict of all "label" entries from this class."""
        cl = self.__class__
        return {
            name: getattr(cl, name) for name in dir(cl) if not name.startswith("_")}

    def __init__(self, label_set: dict[str, str]):
        """
        The initializer takes a dict set of labels and sets the corresponding attribute defined in this class to the
        value specified in the dict (e.g., self.ASSET_GROUPS_DELETE_SUCCESS_MESSAGE is set to
        labels[K.ASSET_GROUPS_DELETE_SUCCESS_MESSAGE]).

        As a side benefit, this will explode if any label defined on this class is not present in the given dict: a
        runtime check that a labels dict must be complete.
        """
        for l_, v_ in self._get_label_entries().items():
            try:
                setattr(self, l_, label_set[v_])
            except KeyError:
                error_message = f"Supplied copy dictionary does not provide entry for {l_}"
                logger.error(error_message)
                raise ValueError(error_message)


# The full set of text copy, mapping the stable key entries to their respective text copy values
labels: dict[str, str] = asset_labels | organization_labels | system_settings_labels


# The labels proxy object
labels_proxy = LabelsProxy(labels)


def get_labels() -> LabelsProxy:
    """Method for getting a LabelsProxy initialized with the correct set of labels."""
    return labels_proxy
