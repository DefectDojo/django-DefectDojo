# Implemented according to Sonatype Component Identifiers
# https://help.sonatype.com/en/referencing-package-url--purl--and-component-identifiers.html
from packageurl import PackageURL


class ComponentIdentifier:

    def __init__(self, component):
        self._component_id = ""
        self._component_name = ""
        self._component_version = ""

        component_identifier = component.get("componentIdentifier")
        # Sonatype sends "componentIdentifier": null for components it could not identify
        if not component_identifier or not component_identifier.get("coordinates"):
            self.set_unidentified_component(component)
        else:
            component_coordinates = component_identifier["coordinates"]
            componant_format = component_identifier.get("format")

            if componant_format in {"a-name", "pypi", "rpm", "gem", "golang", "conan", "conda", "bower", "composer",
                                    "cran", "cargo", "cocoapods", "drupal", "pecoff", "swift", "generic",
                                    "operating-system"}:
                self.set_name_version_component(component_coordinates)
            elif componant_format == "maven":
                self.set_maven_component(component_coordinates)
            elif componant_format in {"npm", "nuget"}:
                self.set_package_id_version_component(component_coordinates)
            elif "displayName" in component:
                self._component_id = component["displayName"]
                self._component_name = component["displayName"]

    @property
    def component_id(self):
        return self._component_id

    @property
    def component_name(self):
        return self._component_name

    @property
    def component_version(self):
        return self._component_version

    def set_name_version_component(self, component_coordinates):
        self._component_id = f"{component_coordinates['name']} {component_coordinates['version']}"
        self._component_name = component_coordinates["name"]
        self._component_version = component_coordinates["version"]

    def set_maven_component(self, component_coordinates):
        self._component_id = (f"{component_coordinates['artifactId']} "
                              f"{component_coordinates['groupId']} "
                              f"{component_coordinates['version']}")
        self._component_name = component_coordinates["artifactId"]
        self._component_version = component_coordinates["version"]

    def set_package_id_version_component(self, component_coordinates):
        self._component_id = f"{component_coordinates['packageId']} {component_coordinates['version']}"
        self._component_name = component_coordinates["packageId"]
        self._component_version = component_coordinates["version"]

    def set_unidentified_component(self, component):
        # Fall back so the finding does not get a blank component, which would make unrelated
        # unidentified components share the same title and hash
        if display_name := component.get("displayName"):
            self._component_id = display_name
            self._component_name = display_name
            return
        if purl := component.get("packageUrl"):
            try:
                package_url = PackageURL.from_string(purl)
            except ValueError:
                package_url = None
            if package_url:
                self._component_version = package_url.version or ""
                self._component_id = f"{package_url.name} {self._component_version}".strip()
                self._component_name = package_url.name
                return
        if pathnames := component.get("pathnames"):
            self._component_id = pathnames[0]
            self._component_name = pathnames[0]
