This template is for your information. Please clear everything when submitting your pull request.

**Note: DefectDojo is now on Python3.6 and Django 2.2.x.**

**Please submit your pull requests to :**

**- evolutions: dev branch**

**- bugfix: latest "release/x.y.z" branch**

**- hotfixes: master branch**

If in doubt you can use dev branch, it will just roll-out later. 

When submitting a pull request, please make sure you have completed the following checklist:

- [ ] Give a meaningful name to your PR, as it may end up being used in the release notes.
- [ ] Your code is flake8 compliant.
- [ ] Your code is python 3.6 compliant (specific python >3.6 syntax is currently not accepted).
- [ ] If this is a new feature and not a bug fix, you've included the proper documentation in the ReadTheDocs documentation folder. https://github.com/DefectDojo/Documentation/tree/master/docs or provide feature documentation in the PR.
- [ ] Model changes must include the necessary migrations in the dojo/db_migrations folder.
- [ ] Add applicable tests to the unit tests.
- [ ] Add the proper label to categorize your PR.


Moderators: Labels currently accepted for PRs:
- Import Scans (for new scanners/importers)
- enhancement
- performance
- feature
- bugfix
- maintenance (a.k.a chores)
- dependencies
- New Migration (when the PR introduces a DB migration)
- settings_changes (when the PR introduces changes or new settings in settings.dist.py)

# Contributors: Git Tips
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
