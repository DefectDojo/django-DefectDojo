**Note: DefectDojo is now on Python3.5 and Django 2.2.x Please submit your pull requests to the 'dev' branch as the 'legacy-python2.7' branch is only for bug fixes. Any new features submitted to the legacy branch will be ignored and closed.**

When submitting a pull request, please make sure you have completed the following checklist:

- [ ] Your code is flake8 compliant 
- [ ] Your code is python 3.5 compliant (specific python >=3.6 syntax is currently not accepted)
- [ ] If this is a new feature and not a bug fix, you've included the proper documentation in the ReadTheDocs documentation folder. https://github.com/DefectDojo/Documentation/tree/master/docs or provide feature documentation in the PR.
- [ ] Model changes must include the necessary migrations in the dojo/db_migrations folder.
- [ ] Add applicable tests to the unit tests.
- [ ] Add the proper label to categorize your PR 

Current accepted labels for PRs:
- Import Scans (for new scanners/importers)
- enhancement
- feature
- bugfix
- maintenance (a.k.a chores)
- dependencies
