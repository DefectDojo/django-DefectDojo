from enum import IntEnum


class Roles(IntEnum):
    Reader = 0
    API_Importer = 1
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
    Product_Type_Member_Delete = 1003
    Product_Type_Manage_Members = 1004
    Product_Type_Member_Add_Owner = 1005
    Product_Type_Edit = 1006
    Product_Type_Delete = 1007

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

    Endpoint_View = 1502
    Endpoint_Add = 1503
    Endpoint_Edit = 1506
    Endpoint_Delete = 1507

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

    @classmethod
    def has_value(cls, value):
        try:
            Permissions(value)
            return True
        except ValueError:
            return False

    @classmethod
    def get_engagement_permissions(cls):
        return {Permissions.Engagement_View, Permissions.Engagement_Edit,
            Permissions.Engagement_Delete, Permissions.Risk_Acceptance,
            Permissions.Test_Add, Permissions.Import_Scan_Result, Permissions.Note_Add,
            Permissions.Note_Delete, Permissions.Note_Edit, Permissions.Note_View_History} \
            .union(cls.get_test_permissions())

    @classmethod
    def get_test_permissions(cls):
        return {Permissions.Test_View, Permissions.Test_Edit, Permissions.Test_Delete,
            Permissions.Finding_Add, Permissions.Import_Scan_Result, Permissions.Note_Add,
            Permissions.Note_Delete, Permissions.Note_Edit, Permissions.Note_View_History} \
            .union(cls.get_finding_permissions())

    @classmethod
    def get_finding_permissions(cls):
        return {Permissions.Finding_View, Permissions.Finding_Edit, Permissions.Import_Scan_Result,
            Permissions.Finding_Delete, Permissions.Risk_Acceptance, Permissions.Note_Add,
            Permissions.Note_Delete, Permissions.Note_Edit, Permissions.Note_View_History} \
            .union(cls.get_finding_group_permissions())

    @classmethod
    def get_finding_group_permissions(cls):
        return {Permissions.Finding_Group_View, Permissions.Finding_Group_Edit,
            Permissions.Finding_Group_Delete}

    @classmethod
    def get_endpoint_permissions(cls):
        return {Permissions.Endpoint_View, Permissions.Endpoint_Edit, Permissions.Endpoint_Delete}

    @classmethod
    def get_product_member_permissions(cls):
        return {Permissions.Product_View, Permissions.Product_Manage_Members,
            Permissions.Product_Member_Delete}

    @classmethod
    def get_product_type_member_permissions(cls):
        return {Permissions.Product_Type_View, Permissions.Product_Type_Manage_Members,
            Permissions.Product_Type_Member_Delete}


def get_roles_with_permissions():
    return {
        Roles.Reader: {
            Permissions.Product_Type_View,

            Permissions.Product_View,

            Permissions.Engagement_View,

            Permissions.Test_View,

            Permissions.Finding_View,

            Permissions.Finding_Group_View,

            Permissions.Endpoint_View,

            Permissions.Component_View
        },
        Roles.API_Importer: {
            Permissions.Product_Type_View,

            Permissions.Product_View,

            Permissions.Engagement_View,

            Permissions.Test_View,

            Permissions.Finding_View,

            Permissions.Finding_Group_View,

            Permissions.Endpoint_View,

            Permissions.Component_View,

            Permissions.Import_Scan_Result
        },
        Roles.Writer: {
            Permissions.Product_Type_View,

            Permissions.Product_View,

            Permissions.Engagement_View,
            Permissions.Engagement_Add,
            Permissions.Engagement_Edit,
            Permissions.Risk_Acceptance,

            Permissions.Test_View,
            Permissions.Test_Add,
            Permissions.Test_Edit,

            Permissions.Finding_View,
            Permissions.Finding_Add,
            Permissions.Import_Scan_Result,
            Permissions.Finding_Edit,

            Permissions.Finding_Group_View,
            Permissions.Finding_Group_Add,
            Permissions.Finding_Group_Edit,
            Permissions.Finding_Group_Delete,

            Permissions.Endpoint_View,
            Permissions.Endpoint_Add,
            Permissions.Endpoint_Edit,

            Permissions.Benchmark_Edit,

            Permissions.Component_View,

            Permissions.Note_View_History,
            Permissions.Note_Edit,
            Permissions.Note_Add
        },
        Roles.Maintainer: {
            Permissions.Product_Type_Add_Product,
            Permissions.Product_Type_View,
            Permissions.Product_Type_Member_Delete,
            Permissions.Product_Type_Manage_Members,
            Permissions.Product_Type_Edit,

            Permissions.Product_View,
            Permissions.Product_Member_Delete,
            Permissions.Product_Manage_Members,
            Permissions.Product_Configure_Notifications,
            Permissions.Product_Edit,

            Permissions.Engagement_View,
            Permissions.Engagement_Add,
            Permissions.Engagement_Edit,
            Permissions.Engagement_Delete,
            Permissions.Risk_Acceptance,

            Permissions.Test_View,
            Permissions.Test_Add,
            Permissions.Test_Edit,
            Permissions.Test_Delete,

            Permissions.Finding_View,
            Permissions.Finding_Add,
            Permissions.Import_Scan_Result,
            Permissions.Finding_Edit,
            Permissions.Finding_Delete,

            Permissions.Finding_Group_View,
            Permissions.Finding_Group_Add,
            Permissions.Finding_Group_Edit,
            Permissions.Finding_Group_Delete,

            Permissions.Endpoint_View,
            Permissions.Endpoint_Add,
            Permissions.Endpoint_Edit,
            Permissions.Endpoint_Delete,

            Permissions.Benchmark_Edit,
            Permissions.Benchmark_Delete,

            Permissions.Component_View,

            Permissions.Note_View_History,
            Permissions.Note_Edit,
            Permissions.Note_Add,
            Permissions.Note_Delete
        },
        Roles.Owner: {
            Permissions.Product_Type_Add_Product,
            Permissions.Product_Type_View,
            Permissions.Product_Type_Member_Delete,
            Permissions.Product_Type_Manage_Members,
            Permissions.Product_Type_Member_Add_Owner,
            Permissions.Product_Type_Edit,
            Permissions.Product_Type_Delete,

            Permissions.Product_View,
            Permissions.Product_Member_Delete,
            Permissions.Product_Manage_Members,
            Permissions.Product_Member_Add_Owner,
            Permissions.Product_Configure_Notifications,
            Permissions.Product_Edit,
            Permissions.Product_Delete,

            Permissions.Engagement_View,
            Permissions.Engagement_Add,
            Permissions.Engagement_Edit,
            Permissions.Engagement_Delete,
            Permissions.Risk_Acceptance,

            Permissions.Test_View,
            Permissions.Test_Add,
            Permissions.Test_Edit,
            Permissions.Test_Delete,

            Permissions.Finding_View,
            Permissions.Finding_Add,
            Permissions.Import_Scan_Result,
            Permissions.Finding_Edit,
            Permissions.Finding_Delete,

            Permissions.Finding_Group_View,
            Permissions.Finding_Group_Add,
            Permissions.Finding_Group_Edit,
            Permissions.Finding_Group_Delete,

            Permissions.Endpoint_View,
            Permissions.Endpoint_Add,
            Permissions.Endpoint_Edit,
            Permissions.Endpoint_Delete,

            Permissions.Benchmark_Edit,
            Permissions.Benchmark_Delete,

            Permissions.Component_View,

            Permissions.Note_View_History,
            Permissions.Note_Edit,
            Permissions.Note_Add,
            Permissions.Note_Delete
        }
    }
