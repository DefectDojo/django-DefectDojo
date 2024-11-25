import re


class UniformTrivyVulnID:
    def return_uniformed_vulnid(self, vulnid):
        if vulnid is None:
            return vulnid
        if "cve" in vulnid.lower():
            return vulnid
        if "khv" in vulnid.lower():
            temp = re.compile(r"([a-zA-Z-_]+)([0-9]+)")
            number = str(temp.match(vulnid).groups()[1]).zfill(3)
            avd_category = str(temp.match(vulnid.lower()).groups()[0])
            return avd_category.upper() + number
        if "ksv" in vulnid.lower() or "kcv" in vulnid.lower():
            temp = re.compile(r"([a-zA-Z-_]+)([0-9]+)")
            number = str(temp.match(vulnid).groups()[1]).zfill(4)
            avd_category = str(temp.match(vulnid.lower().replace("_", "").replace("-", "")).groups()[0].replace("avd", ""))
            return "AVD-" + avd_category.upper() + "-" + number
        return vulnid
