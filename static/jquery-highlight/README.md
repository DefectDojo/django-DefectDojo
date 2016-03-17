jQuery.Highlight.js
===================

Text highlighting plugin for jQuery.

Original [code][1] and [documentation][2].

## Usage

How to use this plugin.

_Note: This plugin requires jQuery to be included, which is left up to you._

First you neet to install the module, which can be installed in one
of the following ways:

```bash
npm install jquery-highlight
bower install jquery-highlight
component install knownasilya/jquery-highlight
# or just download it from Github
```

### Available Options

#### $.highlight

The parameters are `highlight(string|array of strings, optional options object)` and the available options are:

  * `className` -- The CSS class of a highlighted element, defaults to 'highlight'.
  * `element` -- The element that wraps the highlighted word, defaults to 'span'.
  * `caseSensitive` -- If the search should be case sensitive, defaults to `false`.
  * `wordsOnly` -- If we want to highlight partial sections of a word, e.g. 'ca' from 'cat', defaults to `false`.

#### $.unhighlight

The parameters are `unhighlight(optional options object)`, and the available options are:

  * `className`  -- The highlights to remove based on CSS class, defaults to 'highlight'.
  * `element` -- The highlights to remove based on HTML element, defaults to 'span'.

### Examples

Below are several ways that you can utilize this plugin.

```js
// wrap every occurrance of text 'lorem' in content
// with <span class='highlight'> (default options)
$('#content').highlight('lorem');

// search for and highlight more terms at once
// so you can save some time on traversing DOM
$('#content').highlight(['lorem', 'ipsum']);
$('#content').highlight('lorem ipsum');

// search only for entire word 'lorem'
$('#content').highlight('lorem', {
  wordsOnly: true
});

// search only for the entire word 'C#'
// and make sure that the word boundary can also
// be a 'non-word' character, as well as a regex latin1 only boundary:
$('#content').highlight('C#', {
  wordsOnly: true,
  wordsBoundary: '[\\b\\W]'
});


// don't ignore case during search of term 'lorem'
$('#content').highlight('lorem', {
  caseSensitive: true
});

// wrap every occurrance of term 'ipsum' in content
// with <em class='important'>
$('#content').highlight('ipsum', {
  element: 'em',
  className: 'important'
});

// remove default highlight
$('#content').unhighlight();

// remove custom highlight
$('#content').unhighlight({
  element: 'em',
  className: 'important'
});
```


## Attribution

Plugin was originally created by Bartek Szopka ([@bartaz][bartaz]).

## License

MIT

[1]: https://github.com/bartaz/sandbox.js/blob/master/jquery.highlight.js
[2]: http://bartaz.github.io/sandbox.js/jquery.highlight.html
[bartaz]: https://github.com/bartaz
