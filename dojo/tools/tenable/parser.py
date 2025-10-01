from dojo.tools.tenable.csv_format import TenableCSVParser
from dojo.tools.tenable.xml_format import TenableXMLParser


class TenableParser:
    """
    This class is a "dispatcher" that chooses the correct parser (XML or CSV)
    based on the file extension.
    """

    def get_scan_types(self):
        return ["Tenable Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Tenable Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Les rapports peuvent être importés aux formats CSV ou .nessus (XML)."

    def get_findings(self, filename, test):
        """
        Main function that determines which parser to use based on the file extension.
        """
        if filename.name.lower().endswith((".xml", ".nessus")):
            return TenableXMLParser().get_findings(filename, test)
        elif filename.name.lower().endswith(".csv"):
            return TenableCSVParser().get_findings(filename, test)
        else:
            msg = "Extension de fichier non reconnue. Utilisez .xml, .nessus ou .csv"
            raise ValueError(msg)

    # Note: Les fonctions ci-dessous sont pour la documentation et l'interface utilisateur
    # de DefectDojo. J'ai mis à jour les commentaires pour refléter vos nouveaux champs CSV.

    def get_fields(self) -> list[str]:
        """
        Retourne la liste des champs utilisés par les parseurs Tenable.

        Champs pour le parseur CSV (basé sur vos nouveaux en-têtes) :
        - title: Construit à partir de 'definition.name' et 'asset.name'.
        - description: Combinaison de 'definition.synopsis' et 'output'.
        - severity: Mappé à partir du champ 'severity'.
        - mitigation: Provient du champ 'definition.solution'.
        - impact: Provient du champ 'definition.description'.
        - cve: Provient du champ 'definition.cve'.
        - cvssv3_score: Provient du champ 'definition.cvss3.base_score'.
        - references: Provient du champ 'definition.see_also'.
        - component_name: Pourrait être mappé à partir de 'definition.family'.
        
        Champs pour le parseur XML :
        - title: Défini à partir du nom du plugin.
        - description: Combinaison du synopsis et du plugin output.
        - severity: Défini à partir de la sévérité.
        - mitigation: Défini à partir de la solution.
        - impact: Combinaison de la description, des scores CVSS, etc.
        - cwe: Si présent, défini à partir de cwe.
        - cvssv3: Si présent, défini à partir de cvssv3.
        """
        # Cette liste combine les champs possibles des deux parseurs
        return [
            "title",
            "description",
            "severity",
            "mitigation",
            "impact",
            "cve",
            "cvssv3_score",
            "references",
            "component_name",
            "component_version",
            "cwe",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Retourne les champs utilisés pour la déduplication des vulnérabilités.
        """
        return [
            "title",
            "severity",
            "description",
            "cwe",
            # Vous pourriez vouloir ajouter 'component_name' si c'est pertinent
        ]