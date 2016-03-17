
## Reporting Bugs

Each bug report MUST have a [JSFiddle/JSBin] recreation before any work can begin. [further instructions &raquo;](http://fullcalendar.io/wiki/Reporting-Bugs/)


## Requesting Features

Please search the [Issue Tracker] to see if your feature has already been requested, and if so, subscribe to it. Otherwise, read these [further instructions &raquo;](http://fullcalendar.io/wiki/Requesting-Features/)


## Contributing Features

The FullCalendar project welcomes [Pull Requests][Using Pull Requests] for new features, but because there are so many feature requests (over 100), and because every new feature requires refinement and maintenance, each PR will be prioritized against the project's other demands and might take a while to make it to an official release.

Furthermore, each new feature should be designed as robustly as possible and be useful beyond the immediate usecase it was initially designed for. Feel free to start a ticket discussing the feature's specs before coding.


## Contributing Bugfixes

In the description of your [Pull Request][Using Pull Requests], please include recreation steps for the bug as well as a [JSFiddle/JSBin] demo. Communicating the buggy behavior is a requirement before a merge can happen.


## Contributing Languages

Please edit the original files in the `lang/` directory. DO NOT edit anything in the `dist/` directory. The build system will responsible for merging FullCalendar's `lang/` data with the [MomentJS locale data].


## Other Ways to Contribute

[Read about other ways to contribute &raquo;](http://fullcalendar.io/wiki/Contributing/)


## Getting Set Up

You will need [Git][git], [Node][node], and NPM installed. For clarification, please view the [jQuery readme][jq-readme], which requires a similar setup.

Also, you will need the [grunt-cli][grunt-cli] and [bower][bower] packages installed globally (`-g`) on your system:

	npm install -g grunt-cli bower

Then, clone FullCalendar's git repo:

	git clone git://github.com/arshaw/fullcalendar.git

Enter the directory and install FullCalendar's development dependencies:

	cd fullcalendar
	./build/init.sh


## What to edit

When modifying files, please do not edit the generated or minified files in the `dist/` directory. Please edit the original `src/` files.


## Development Workflow

After you make code changes, you'll want to compile the JS/CSS so that it can be previewed from the tests and demos. You can either manually rebuild each time you make a change:

	grunt dev

Or, you can run a script that automatically rebuilds whenever you save a source file:

	./build/watch.sh

When you are finished, run the following command to write the distributable files into the `./dist/` directory:

	grunt

If you want to clean up the generated files, run:

	grunt clean


## Style Guide

Please follow the [Google JavaScript Style Guide] as closely as possible. With the following exceptions:

```js
if (true) {
}
else { // please put else, else if, and catch on a separate line
}

// please write one-line array literals with a one-space padding inside
var a = [ 1, 2, 3 ];

// please write one-line object literals with a one-space padding inside
var o = { a: 1, b: 2, c: 3 };
```

Other exceptions:

- please ignore anything about Google Closure Compiler or the `goog` library
- please do not write JSDoc comments

Notes about whitespace:

- **use *tabs* instead of spaces**
- separate functions with *2* blank lines
- separate logical blocks within functions with *1* blank line

Run the command line tool to automatically check your style:

	grunt check


## Before Submitting your Code

If you have edited code (including **tests** and **translations**) and would like to submit a pull request, please make sure you have done the following:

1. Conformed to the style guide (successfully run `grunt check`)

2. Written automated tests. View the [Automated Test Readme]


[JSFiddle/JSBin]: http://fullcalendar.io/wiki/Reporting-Bugs/
[Issue Tracker]: https://github.com/fullcalendar/fullcalendar/issues
[Using Pull Requests]: https://help.github.com/articles/using-pull-requests/
[MomentJS locale data]: https://github.com/moment/moment/tree/develop/locale
[git]: http://git-scm.com/
[node]: http://nodejs.org/
[grunt-cli]: http://gruntjs.com/getting-started#installing-the-cli
[bower]: http://bower.io/
[jq-readme]: https://github.com/jquery/jquery/blob/master/README.md#what-you-need-to-build-your-own-jquery
[Google JavaScript Style Guide]: http://google-styleguide.googlecode.com/svn/trunk/javascriptguide.xml
[Automated Test Readme]: https://github.com/fullcalendar/fullcalendar/wiki/Automated-Tests
