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

    @classmethod
    def has_value(cls, value):
        try:
            Roles(value)
            return True
        except ValueError:
            return False


def django_enum(cls):
    # decorator needed to enable enums in django templates
    # see https://stackoverflow.com/questions/35953132/how-to-access-enum-types-in-django-templates
    cls.do_not_call_in_templates = True
    return cls


@django_enum
class Permissions(IntEnum):
    Product_Type_Add_Product = 1001
    Product_Type_View = 1002
    Product_Type_Remove_Member = 1003
    Product_Type_Manage_Members = 1004
    Product_Type_Member_Add_Owner = 1005
    Product_Type_Edit = 1006
    Product_Type_Delete = 1007

    Product_View = 1102
    Product_Remove_Member = 1103
    Product_Manage_Members = 1104
    Product_Member_Add_Owner = 1005
    Product_Configure_Notifications = 1106
    Product_Edit = 1107
    Product_Delete = 1108

    Engagement_View = 1202
    Engagement_Add = 1203
    Engagement_Edit = 1206
    Engagement_Delete = 1207

    Test_View = 1202
    Test_Add = 1203
    Test_Edit = 1206
    Test_Delete = 1207

    Finding_View = 1402
    Finding_Add = 1403
    Import_Scan_Result = 1404
    Finding_Edit = 1406
    Finding_Delete = 1407

    Endpoint_View = 1502
    Endpoint_Add = 1503
    Endpoint_Edit = 1506
    Endpoint_Delete = 1507

    @classmethod
    def has_value(cls, value):
        try:
            Permissions(value)
            return True
        except ValueError:
            return False

    @classmethod
    def get_engagement_permissions(cls):
        return {Permissions.Engagement_View, Permissions.Engagement_Add, Permissions.Engagement_Edit, Permissions.Engagement_Delete}

    @classmethod
    def get_test_permissions(cls):
        return {Permissions.Test_View, Permissions.Test_Add, Permissions.Test_Edit, Permissions.Test_Delete}

    @classmethod
    def get_finding_permissions(cls):
        return {Permissions.Finding_View, Permissions.Finding_Add, Permissions.Finding_Edit, Permissions.Import_Scan_Result, Permissions.Finding_Delete}

    @classmethod
    def get_endpoint_permissions(cls):
        return {Permissions.Endpoint_View, Permissions.Endpoint_Add, Permissions.Endpoint_Edit, Permissions.Endpoint_Delete}

    @classmethod
    def get_product_member_permissions(cls):
        return {Permissions.Product_Manage_Members, Permissions.Product_Remove_Member}

    @classmethod
    def get_product_type_member_permissions(cls):
        return {Permissions.Product_Type_Manage_Members, Permissions.Product_Type_Remove_Member}


def get_roles_with_permissions():
    return {
        Roles.Reader: {
            Permissions.Product_Type_View,
            Permissions.Product_Type_Remove_Member,

            Permissions.Product_View,
            Permissions.Product_Remove_Member,

            Permissions.Engagement_View,

            Permissions.Test_View,

            Permissions.Finding_View,

            Permissions.Endpoint_View
        },
        Roles.Technical_User: {
            Permissions.Import_Scan_Result
        },
        Roles.Writer: {
            Permissions.Product_Type_View,
            Permissions.Product_Type_Remove_Member,

            Permissions.Product_View,
            Permissions.Product_Remove_Member,

            Permissions.Engagement_View,
            Permissions.Engagement_Add,
            Permissions.Engagement_Edit,

            Permissions.Test_View,
            Permissions.Test_Add,
            Permissions.Test_Edit,

            Permissions.Finding_View,
            Permissions.Finding_Add,
            Permissions.Import_Scan_Result,
            Permissions.Finding_Edit,

            Permissions.Endpoint_View,
            Permissions.Endpoint_Add,
            Permissions.Endpoint_Edit
        },
        Roles.Maintainer: {
            Permissions.Product_Type_Add_Product,
            Permissions.Product_Type_View,
            Permissions.Product_Type_Remove_Member,
            Permissions.Product_Type_Manage_Members,
            Permissions.Product_Type_Edit,

            Permissions.Product_View,
            Permissions.Product_Remove_Member,
            Permissions.Product_Manage_Members,
            Permissions.Product_Configure_Notifications,
            Permissions.Product_Edit,

            Permissions.Engagement_View,
            Permissions.Engagement_Add,
            Permissions.Engagement_Edit,
            Permissions.Engagement_Delete,

            Permissions.Test_View,
            Permissions.Test_Add,
            Permissions.Test_Edit,
            Permissions.Test_Delete,

            Permissions.Finding_View,
            Permissions.Finding_Add,
            Permissions.Import_Scan_Result,
            Permissions.Finding_Edit,
            Permissions.Finding_Delete,

            Permissions.Endpoint_View,
            Permissions.Endpoint_Add,
            Permissions.Endpoint_Edit,
            Permissions.Endpoint_Delete
        },
        Roles.Owner: {
            Permissions.Product_Type_Add_Product,
            Permissions.Product_Type_View,
            Permissions.Product_Type_Remove_Member,
            Permissions.Product_Type_Manage_Members,
            Permissions.Product_Type_Member_Add_Owner,
            Permissions.Product_Type_Edit,
            Permissions.Product_Type_Delete,

            Permissions.Product_View,
            Permissions.Product_Remove_Member,
            Permissions.Product_Manage_Members,
            Permissions.Product_Member_Add_Owner,
            Permissions.Product_Configure_Notifications,
            Permissions.Product_Edit,
            Permissions.Product_Delete,

            Permissions.Engagement_View,
            Permissions.Engagement_Add,
            Permissions.Engagement_Edit,
            Permissions.Engagement_Delete,

            Permissions.Test_View,
            Permissions.Test_Add,
            Permissions.Test_Edit,
            Permissions.Test_Delete,

            Permissions.Finding_View,
            Permissions.Finding_Add,
            Permissions.Import_Scan_Result,
            Permissions.Finding_Edit,
            Permissions.Finding_Delete,

            Permissions.Endpoint_View,
            Permissions.Endpoint_Add,
            Permissions.Endpoint_Edit,
            Permissions.Endpoint_Delete
        }
    }
