Snippets
========

Files in this directory serve as reusable snippets to be included in other
templates. Each snippet starts with a documentary comment section explaining the
snippet's purpose and how its behaviour can be configured by passing variables to it.

Parameters accepted by a particular snippet are denoted as follows::

    * <type> <name>[ (<default>)]:
      <description>

When no default value (including the surrounding parentheses) is specified for a
parameter, that parameter is required for the snippet to function correctly. Otherwise,
it's an optional one.

Some examples::

    * str label:                # Required string parameter "label"
    * bool collapsible (True):  # Optional boolean parameter "collapsible", True by default
    * str field_class (""):     # Optional string parameter "field_class", empty by default


The ``as`` Template Tag
-----------------------

When including these snippets, you'll often want to pass a whole block of HTML as
parameter. To make this as easy as possible, a new template tag has been added and
is available in all templates without loading a template library explicitly.

The tag works as follows::

    {% as some_var %}
        This string will be stored as <strong>some_var</strong> in the rendering context, and won't appear here.
    {% endas %}

From that point on, you have a new variable ``some_var`` which can, for instance,
be passed to an included template::

    {% include "./snippets/some_snippet.html" with some_param=some_var only %}

Note that variables are valid until the block they've been defined in ends. Hence
it's recommended to wrap inclusions in a {% block some_unique_name %}...{% endblock
%}. This will have no visible effect and just prevents defined variables from leaking
into the context of snippets included later.


Bases
-----

Some file names end in ``_base.html``. Those snippets aren't supposed to be included
directly using the ``{% include %}`` directive, they should rather be used as base
for another template via ``{% extends %}``. All base snippets include a documentary
comment as well, describing parameters and replaceable blocks.
