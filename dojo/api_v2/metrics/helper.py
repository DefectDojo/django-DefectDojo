def add_ratings(data, finding, user, flag_counter=True):
    status = finding.ia_recommendation["data"].get("like_status", None)
    if user_data := data["users"].get(user.username):
        if finding_data := user_data["findings"].get(finding.id):
            finding_data["like"] = status
        else:
            finding_data = {
                "like": status,
                "engagement": finding.test.engagement.name,
                "product": finding.test.engagement.product.name,
                "product_type": finding.test.engagement.product.prod_type.name,
            }
            user_data["findings"][finding.id] = finding_data
        user_data["iteration_counter"] += 1
        user_data["like_counter"] += 1 if status is True else 0
        user_data["dislike_counter"] += 1 if status is False else 0
    else:
        data["users"][user.username] = {
            "iteration_counter": 0,
            "like_counter": 0,
            "dislike_counter": 0,
            "findings": {}
        }
        data = add_ratings(data, finding, user, flag_counter=False)
    if flag_counter:
        data["iteration_counter"] += 1
        if status is True:
            data["like_counter"] += 1
        if status is False:
            data["dislike_counter"] += 1

    return data
