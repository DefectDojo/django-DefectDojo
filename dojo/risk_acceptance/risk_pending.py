from typing import List
from django.conf import settings
from dataclasses import dataclass


def finding_is_black_list():
    pass

def get_abuse_control():
    # se calcula el control de abuso
    pass

def get_number_acceptance_risk(finding):
    # TODO: number acceptaciones 
    return 1


def rule_risk_acceptance_according_to_critical(finding, user_rol: str):
    risk_critical = "medium" # TODO: parametrica con el finding
    risk_rule = settings.RULE_RISK_ACCEPTANCE_ACCORDING_TO_CRITICALITY.get(risk_critical)
    view_risk_pending = False
    if risk_rule:
        if risk_rule.get("number_acceptors") != 0 or user_rol not in risk_rule.get("roles"):
            view_risk_pending = True
    return view_risk_pending
