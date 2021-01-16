from enum import IntEnum


class Roles(IntEnum):
    Reader = 0
    Technical_User = 1
    Writer = 2
    Maintainer = 3
    Owner = 4

    @classmethod
    def choices(cls):
        return [(key.value, key.name) for key in cls]


def django_enum(cls):
    # decorator needed to enable enums in django templates
    cls.do_not_call_in_templates = True
    return cls


@django_enum
class Permissions(IntEnum):
    Product_Type_Add_Product = 1001
    Product_Type_View = 1002
    Product_Type_Remove_Member = 1003
    Product_Type_Manage_Members = 1004
    Product_Type_Edit = 1005
    Product_Type_Delete = 1006

    Product_View = 1102
    Product_Remove_Yourself = 1103
    Product_Manage_Members = 1104
    Product_Configure_Notifications = 1105
    Product_Edit = 1106
    Product_Delete = 1107

    Finding_View = 1402
    Finding_Add = 1103
    Import_Scan_Result = 1104
    Finding_Edit = 1106
    Finding_Delete = 1107


def get_roles_with_permissions():
    return {
        Roles.Reader: {
            Permissions.Product_Type_View,
            Permissions.Product_Type_Remove_Member,

            Permissions.Product_View,
            Permissions.Product_Remove_Yourself,

            Permissions.Finding_View
        },
        Roles.Technical_User: {
            Permissions.Import_Scan_Result
        },
        Roles.Writer: {
            Permissions.Product_Type_View,
            Permissions.Product_Type_Remove_Member,

            Permissions.Product_View,
            Permissions.Product_Remove_Yourself,

            Permissions.Finding_View,
            Permissions.Finding_Add,
            Permissions.Import_Scan_Result,
            Permissions.Finding_Edit
        },
        Roles.Maintainer: {
            Permissions.Product_Type_Add_Product,
            Permissions.Product_Type_View,
            Permissions.Product_Type_Remove_Member,
            Permissions.Product_Type_Manage_Members,
            Permissions.Product_Type_Edit,

            Permissions.Product_View,
            Permissions.Product_Remove_Yourself,
            Permissions.Product_Manage_Members,
            Permissions.Product_Configure_Notifications,
            Permissions.Product_Edit,

            Permissions.Finding_View,
            Permissions.Finding_Add,
            Permissions.Import_Scan_Result,
            Permissions.Finding_Edit,
            Permissions.Finding_Delete
        },
        Roles.Owner: {
            Permissions.Product_Type_Add_Product,
            Permissions.Product_Type_View,
            Permissions.Product_Type_Remove_Member,
            Permissions.Product_Type_Manage_Members,
            Permissions.Product_Type_Edit,
            Permissions.Product_Type_Delete,

            Permissions.Product_View,
            Permissions.Product_Remove_Yourself,
            Permissions.Product_Manage_Members,
            Permissions.Product_Configure_Notifications,
            Permissions.Product_Edit,
            Permissions.Product_Delete,

            Permissions.Finding_View,
            Permissions.Finding_Add,
            Permissions.Import_Scan_Result,
            Permissions.Finding_Edit,
            Permissions.Finding_Delete
        }
    }
