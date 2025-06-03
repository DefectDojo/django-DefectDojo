def add_findings_metrics(user_data,
                         status,
                         finding,
                         exclude_field):

    if "findings" not in exclude_field:
        if finding_data := user_data["findings"].get(finding.id):
            finding_data["like"] = status
        else:
            finding_data = {
                "last_updated": "",
                "like": status,
                "engagement": finding.test.engagement.name,
                "product": finding.test.engagement.product.name,
                "product_type": finding.test.engagement.product.prod_type.name,
            }
            user_data["findings"][finding.id] = finding_data
    user_data["interaction_counter"] += 1
    user_data["like_counter"] += 1 if status is True else 0
    user_data["dislike_counter"] += 1 if status is False else 0

    return user_data


def get_metrics_ia_recommendation(data,
                finding,
                flag_counter=True,
                exclude_field=[]):
    status = finding.ia_recommendation["data"].get("like_status", None)
    username = finding.ia_recommendation["data"].get("user", None)
    if user_data := data["users"].get(username):
        user_data = add_findings_metrics(user_data,
                                         status,
                                         finding,
                                         exclude_field)
    else:
        data["users"][username] = {
            "interaction_counter": 0,
            "like_counter": 0,
            "dislike_counter": 0,
            "findings": {}
        }
        data = get_metrics_ia_recommendation(data,
                           finding,
                           flag_counter=False,
                           exclude_field=exclude_field)
    if flag_counter:
        data["interaction_counter"] += 1
        if status is True:
            data["like_counter"] += 1
        if status is False:
            data["dislike_counter"] += 1

    return data