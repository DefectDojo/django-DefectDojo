
# import contextlib


# def parse_cwe_from_ref(xref):
#     if xref:
#         for ref in xref.split(";"):
#             key_value = ref.split(":")
#             if len(key_value) == 2 and key_value[0] == "CWE":
#                 with contextlib.suppress(ValueError, TypeError):
#                     return int(key_value[1])
#     return 0
