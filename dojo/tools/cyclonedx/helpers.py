from cvss import CVSS3
import logging
from dojo.models import Finding

LOGGER = logging.getLogger(__name__)

class Cyclonedxhelper(object):

    def _get_cvssv3(self, raw_vector):
        if raw_vector is None or "" == raw_vector:
            return None
        if not raw_vector.startswith("CVSS:3"):
            raw_vector = "CVSS:3.1/" + raw_vector
        try:
            return CVSS3(raw_vector)
        except BaseException:
            LOGGER.exception(
                f"error while parsing vector CVSS v3 {raw_vector}"
            )
            return None