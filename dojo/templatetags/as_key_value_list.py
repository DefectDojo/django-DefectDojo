from django import template

register = template.Library()


@register.filter
def as_key_value_list(value: dict):
    if not isinstance(value, dict):
        return value

    result = ['']
    # iterate over the values and generate the table rows
    for key, value in value.items():
        if isinstance(value, dict):
            result.append(f"**{key}**:\n")
            result.append(as_key_value_list(value))
        else:
            result.append(f"**{key}**: {value}\n")

    return ''.join(result)

