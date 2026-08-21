from enum import IntEnum, StrEnum


class Action(StrEnum):

    """
    Legacy permission actions. The fine-grained Permissions enum below is
    preserved so existing call sites (`@user_is_authorized(Permissions.X, …)`)
    keep compiling, but every check now flattens to one of these intents:

      * View          — read-only access to an object (membership in
                        authorized_users, or staff/superuser bypass)
      * Edit / Add    — mutating an existing object or creating one
                        (membership in authorized_users + staff bypass)
      * Delete        — destroying an object (staff/superuser only)
      * Import        — bulk ingest of scan results (staff bypass + per-product
                        membership)
      * StaffOnly     — administrative actions like member management or
                        configuration changes
      * SuperuserOnly — system-wide changes that legacy never delegated

    The role hierarchy (Reader / Writer / Maintainer / Owner) does not exist
    in this model; per-product distinctions collapse to membership.
    """

    View = "view"
    Add = "add"
    Edit = "edit"
    Delete = "delete"
    Import = "import"
    StaffOnly = "staff_only"
    SuperuserOnly = "superuser_only"


class Roles(IntEnum):

    """
    Preserved for backward compatibility. Legacy authorization no longer
    branches on roles — these values now act as labels only. The membership
    tables (Product_Member, Product_Type_Member, Global_Role) exist as inert
    data tables that the dojo-pro plugin can adopt; nothing in dojo/ reads
    role assignments after the legacy rewrite.
    """

    Reader = 5
    API_Importer = 1
    Writer = 2
    Maintainer = 3
    Owner = 4

    @classmethod
    def has_value(cls, value):
        try:
            Roles(value)
        except ValueError:
            return False
        return True


def django_enum(cls):
    # decorator needed to enable enums in django templates
    # see
    # https://stackoverflow.com/questions/35953132/how-to-access-enum-types-in-django-templates
    cls.do_not_call_in_templates = True
    return cls


@django_enum
class Permissions(IntEnum):
    Product_Type_Add_Product = 1001
    Product_Type_View = 1002
    Product_Type_Member_Delete = 1003
    Product_Type_Manage_Members = 1004
    Product_Type_Member_Add_Owner = 1005
    Product_Type_Edit = 1006
    Product_Type_Delete = 1007
    Product_Type_Add = 1008

    Product_View = 1102
    Product_Member_Delete = 1103
    Product_Manage_Members = 1104
    Product_Member_Add_Owner = 1105
    Product_Configure_Notifications = 1106
    Product_Edit = 1107
    Product_Delete = 1108

    Engagement_View = 1202
    Engagement_Add = 1203
    Engagement_Edit = 1206
    Engagement_Delete = 1207
    Risk_Acceptance = 1208

    Test_View = 1302
    Test_Add = 1303
    Test_Edit = 1306
    Test_Delete = 1307

    Finding_View = 1402
    Finding_Add = 1403
    Import_Scan_Result = 1404
    Finding_Edit = 1406
    Finding_Delete = 1407

    Location_View = 1502
    Location_Add = 1503
    Location_Edit = 1506
    Location_Delete = 1507

    Benchmark_Edit = 1606
    Benchmark_Delete = 1607

    Component_View = 1702

    Note_View_History = 1802
    Note_Add = 1803
    Note_Edit = 1806
    Note_Delete = 1807

    Finding_Group_View = 1902
    Finding_Group_Add = 1903
    Finding_Group_Edit = 1906
    Finding_Group_Delete = 1907

    Product_Type_Group_View = 2002
    Product_Type_Group_Add = 2003
    Product_Type_Group_Add_Owner = 2005
    Product_Type_Group_Edit = 2006
    Product_Type_Group_Delete = 2007

    Product_Group_View = 2102
    Product_Group_Add = 2103
    Product_Group_Add_Owner = 2105
    Product_Group_Edit = 2106
    Product_Group_Delete = 2107

    Group_View = 2202
    Group_Member_Delete = 2203
    Group_Manage_Members = 2204
    Group_Add_Owner = 2205
    Group_Edit = 2206
    Group_Delete = 2207

    Language_View = 2302
    Language_Add = 2303
    Language_Edit = 2306
    Language_Delete = 2307

    Technology_View = 2402
    Technology_Add = 2403
    Technology_Edit = 2406
    Technology_Delete = 2407

    Product_API_Scan_Configuration_View = 2502
    Product_API_Scan_Configuration_Add = 2503
    Product_API_Scan_Configuration_Edit = 2506
    Product_API_Scan_Configuration_Delete = 2507

    Product_Tracking_Files_View = 2602
    Product_Tracking_Files_Add = 2603
    Product_Tracking_Files_Edit = 2606
    Product_Tracking_Files_Delete = 2607

    @classmethod
    def has_value(cls, value):
        try:
            Permissions(value)
        except ValueError:
            return False
        return True

    @classmethod
    def get_engagement_permissions(cls):
        return {
            "view",
            "edit",
            "delete",
            "add",
            "import",
        }.union(cls.get_test_permissions())

    @classmethod
    def get_test_permissions(cls):
        return {
            "view",
            "edit",
            "delete",
            "add",
            "import",
        }.union(cls.get_finding_permissions())

    @classmethod
    def get_finding_permissions(cls):
        return {
            "view",
            "edit",
            "add",
            "import",
            "delete",
        }.union(cls.get_finding_group_permissions())

    @classmethod
    def get_finding_group_permissions(cls):
        return {
            "view",
            "edit",
            "delete",
        }

    @classmethod
    def get_location_permissions(cls):
        return {
            "view",
            "edit",
            "delete",
        }

    @classmethod
    def get_product_member_permissions(cls):
        return {
            "view",
            "staff_only",
            "delete",
        }

    @classmethod
    def get_product_type_member_permissions(cls):
        return {
            "view",
            "staff_only",
            "delete",
        }

    @classmethod
    def get_product_group_permissions(cls):
        return {
            "view",
            "edit",
            "delete",
        }

    @classmethod
    def get_product_type_group_permissions(cls):
        return {
            "view",
            "edit",
            "delete",
        }

    @classmethod
    def get_group_permissions(cls):
        return {
            "view",
            "delete",
            "staff_only",
            "edit",
        }

    @classmethod
    def get_group_member_permissions(cls):
        return {
            "view",
            "staff_only",
            "delete",
        }

    @classmethod
    def get_language_permissions(cls):
        return {
            "view",
            "edit",
            "delete",
        }

    @classmethod
    def get_technology_permissions(cls):
        return {
            "view",
            "edit",
            "delete",
        }

    @classmethod
    def get_product_api_scan_configuration_permissions(cls):
        return {
            "view",
            "edit",
            "delete",
        }


def get_roles_with_permissions():
    return {
        Roles.Reader: {
            "view",
            "add",
        },
        Roles.API_Importer: {
            "view",
            "add",
            "edit",
            "import",
        },
        Roles.Writer: {
            "view",
            "add",
            "edit",
            "import",
            "delete",
        },
        Roles.Maintainer: {
            "add",
            "view",
            "delete",
            "staff_only",
            "edit",
            "import",
        },
        Roles.Owner: {
            "add",
            "view",
            "delete",
            "staff_only",
            "edit",
            "import",
        },
    }


def get_global_roles_with_permissions():
    """Extra permissions for global roles, on top of the permissions granted to the "normal" roles above."""
    return {
        Roles.Maintainer: {"add"},
        Roles.Owner: {"add"},
    }


def permission_to_action(permission):
    """
    Map a fine-grained Permissions enum member, action string, or legacy
    enum-name string (e.g. "Product_Edit") to an Action.

    The suffix-based mapping captures every Permissions name (which all
    follow the ``<Noun>_<Verb>`` convention); the noun is irrelevant
    because legacy authorization is not noun-aware (the object passed at
    check time determines the membership scope).
    """
    if isinstance(permission, Action):
        return permission

    if isinstance(permission, str):
        try:
            return Action(permission)
        except ValueError:
            name = permission
    else:
        name = getattr(permission, "name", "") or str(permission)

    if name == "Risk_Acceptance":
        return Action.Edit
    if name == "Import_Scan_Result":
        return Action.Import
    if name.endswith(("_View", "_View_History")):
        return Action.View
    if name.endswith(("_Edit", "_Configure_Notifications")):
        return Action.Edit
    if name.endswith("_Delete"):
        return Action.Delete
    if name.endswith(("_Add_Product", "_Add")):
        return Action.Add
    if "_Manage_" in name or name.endswith("_Add_Owner"):
        return Action.StaffOnly

    return Action.View
