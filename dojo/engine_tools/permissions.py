

def is_permission_edit_or_review_finding_exclusion(user) -> bool:
    if user.is_superuser:
        return True
    
    if user.is_anonymous:
        return False
    
    if len(user.groups.filter(dojo_group__name="Reviewers_Maintainer")) > 0:
        return True
    
    return False
    
    
def is_permission_reject_finding_exclusion(user) -> bool:
    if user.is_superuser:
        return True
    
    if user.is_anonymous:
        return False
    
    if len(user.groups.filter(dojo_group__name="Reviewers_Maintainer")) > 0 or \
       len(user.groups.filter(dojo_group__name="Approvers_Cibersecurity")) > 0:
        return True
    
    return False


def is_permission_approve_finding_exclusion(user) -> bool:
    if user.is_superuser:
        return True
    
    if user.is_anonymous:
        return False
    
    if len(user.groups.filter(dojo_group__name="Approvers_Cibersecurity")) > 0:
        return True
    
    return False