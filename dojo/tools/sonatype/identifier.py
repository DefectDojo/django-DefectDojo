# Implemented according to Sonatype Component Identifiers
# https://help.sonatype.com/en/referencing-package-url--purl--and-component-identifiers.html
class ComponentIdentifier:

    def __init__(self, component):
        self._component_id = ""
        self._component_name = ""
        self._component_version = ""

        if "componentIdentifier" in component:
            component_coordinates = component["componentIdentifier"]["coordinates"]
            componant_format = component["componentIdentifier"]["format"]

            if componant_format in ["a-name", "pypi", "rpm", "gem", "golang", "conan", "conda", "bower", "composer",
                                    "cran", "cargo", "cocoapods", "drupal", "pecoff", "swift", "generic",
                                    "operating-system"]:
                self.set_name_version_component(component_coordinates)
            elif componant_format == "maven":
                self.set_maven_component(component_coordinates)
            elif componant_format in ["npm", "nuget"]:
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
