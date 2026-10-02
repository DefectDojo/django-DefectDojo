"""
Resolve CSAF product identifiers to component names and versions.

A CSAF `product_tree` never states "product X is named Y version Z" in one place. A product id is
defined in one of three ways, and a document may use all three at once:

  * `full_product_names[]` - a flat list of {product_id, name}
  * `branches[]` - an arbitrarily deep tree where the leaf carries a `product` object and the
    ancestors carry the vendor / product-family / version parts of the name
  * `relationships[]` - a synthesised product meaning "A installed on B", whose own
    `full_product_name` defines a NEW product id

Version is only reliably available from a branch of category `product_version`, so the tree has to be
walked rather than just flattened.
"""

# CSAF branch categories. product_version is the only one that names a version.
BRANCH_CATEGORY_VERSION = "product_version"


class ProductTree:

    """Index a CSAF product_tree so a product_id can be resolved in constant time."""

    def __init__(self, product_tree):
        self._names = {}
        self._versions = {}

        product_tree = product_tree or {}

        for entry in product_tree.get("full_product_names", []) or []:
            self._add_full_product_name(entry)

        self._walk_branches(product_tree.get("branches", []) or [], version=None)

        # Relationships are indexed last: a relationship's full_product_name defines the id, and it
        # should win over anything a branch happened to register for the same id.
        for relationship in product_tree.get("relationships", []) or []:
            if isinstance(relationship, dict):
                self._add_full_product_name(relationship.get("full_product_name"))

    def _add_full_product_name(self, entry, version=None):
        if not isinstance(entry, dict):
            return
        product_id = (entry.get("product_id") or "").strip()
        if not product_id:
            return
        name = (entry.get("name") or "").strip()
        if name:
            self._names[product_id] = name
        if version:
            self._versions[product_id] = version

    def _walk_branches(self, branches, version):
        """
        Walk the branch tree, carrying the nearest enclosing product_version down to the leaves.

        A leaf is a branch with a `product` object; its ancestors describe it. The version comes from
        the closest `product_version` ancestor, which is the only place CSAF states one.
        """
        for branch in branches:
            if not isinstance(branch, dict):
                continue

            branch_version = version
            if (branch.get("category") or "").strip() == BRANCH_CATEGORY_VERSION:
                branch_version = (branch.get("name") or "").strip() or version

            if product := branch.get("product"):
                self._add_full_product_name(product, version=branch_version)

            self._walk_branches(branch.get("branches", []) or [], version=branch_version)

    def name(self, product_id):
        """Return the product's name, falling back to the raw id so a finding is never unlabelled."""
        return self._names.get(product_id, product_id)

    def version(self, product_id):
        """Return the product's version, or "" when the tree states none."""
        return self._versions.get(product_id, "")

    def component(self, product_id):
        """
        Return (name, version) for a product id.

        Two shapes have to converge on the same answer, or the same product would deduplicate
        differently depending on how the advisory happened to describe it:

        * branch shape - the leaf `product.name` is the FULL name ("Generic App 1.0.0") and the version
          comes from the enclosing product_version branch. The version is stripped off the name so
          component_name is just "Generic App".
        * full_product_names shape - only a name is given, so the trailing version-looking token is
          split off to populate component_version.
        """
        name = self.name(product_id)
        version = self.version(product_id)

        if version and name.endswith(f" {version}"):
            # Branch shape: drop the version the leaf name repeats.
            return name[: -(len(version) + 1)].strip(), version

        if not version and name:
            head, _, tail = name.rpartition(" ")
            if head and tail and tail[0].isdigit():
                return head, tail

        return name, version
