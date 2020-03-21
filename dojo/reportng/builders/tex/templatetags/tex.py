import re
import subprocess

from django.template import Library
from django.utils.safestring import SafeText, mark_safe


# This map was taken from: https://stackoverflow.com/questions/16259923/how-can-i-escape-latex-special-characters-inside-django-templates
ESCAPE_MAP = {
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\^{}",
    "\\": r"\textbackslash{}",
    "<": r"\textless{}",
    ">": r"\textgreater{}",
}
ESCAPE_REGEX = re.compile(
    "|".join(re.escape(key) for key in sorted(ESCAPE_MAP, key=lambda item: -len(item)))
)

register = Library()


@register.filter
def tex(value):
    """Escapes any character that has a special meaning in TeX."""
    if isinstance(value, SafeText):
        # Value already marked as safe, don't escape it
        return value
    if not isinstance(value, str):
        value = str(value)
    return mark_safe(ESCAPE_REGEX.sub(lambda match: ESCAPE_MAP[match.group()], value))


@register.filter
def to_latex(value, format="gfm"):
    """Converts the value from given format to safely escaped LaTeX using pandoc.

    A source format of gfm is assumed by default.
    """
    process = subprocess.Popen(
        ["pandoc", "--from", format, "--to", "latex"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    if not isinstance(value, str):
        value = str(value)
    output = process.communicate(value.encode("utf-8"))[0]
    return mark_safe(output.decode("utf-8"))
