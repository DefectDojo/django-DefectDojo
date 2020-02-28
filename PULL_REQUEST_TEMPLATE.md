This template is for your information. Please clear everything when submitting your pull request.

**Note: DefectDojo is now on Python3.5 and Django 2.2.x Please submit your pull requests to the 'dev' branch as the 'legacy-python2.7' branch is only for bug fixes. Any new features submitted to the legacy branch will be ignored and closed.**

When submitting a pull request, please make sure you have completed the following checklist:

- [ ] Your code is flake8 compliant.
- [ ] Your code is python 3.5 compliant (specific python >=3.6 syntax is currently not accepted).
- [ ] If this is a new feature and not a bug fix, you've included the proper documentation in the ReadTheDocs documentation folder. https://github.com/DefectDojo/Documentation/tree/master/docs or provide feature documentation in the PR.
- [ ] Model changes must include the necessary migrations in the dojo/db_migrations folder.
- [ ] Add applicable tests to the unit tests.
- [ ] Add the proper label to categorize your PR.


Current accepted labels for PRs:
- Import Scans (for new scanners/importers)
- enhancement
- performance
- feature
- bugfix
- maintenance (a.k.a chores)
- dependencies
- New Migration

# Git Tips
## Rebase on dev branch
If the dev branch has changed since you started working on it, please rebase your work after the current dev.

On your working branch `mybranch`:
```
git rebase dev mybranch
```
In case of conflict:
```
 git mergetool
 git rebase --continue
 ```

When everything's fine on your local branch, force push to your `myOrigin` remote: 
```
git push myOrigin --force-with-lease
```

To cancel everything: 
```
git rebase --abort
```


## Squashing commits
```
git rebase -i origin/dev
```
- Replace `pick` by `fixup` on the commits you want squashed out
- Replace `pick` by `reword` on the first commit if you want to change the commit message
- Save the file and quit your editor

Force push to your `myOrigin` remote: 
```
git push myOrigin --force-with-lease
```
