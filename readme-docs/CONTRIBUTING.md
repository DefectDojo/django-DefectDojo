We greatly appreciate all of our
[contributors](https://github.com/DefectDojo/django-DefectDojo/graphs/contributors).

We would also like to highlight the contributions from Michael Dong and Fatimah
Zohra who contributed to DefectDojo before it was open source.

# Submitting an Issue

## For Bugs

Before submitting, please ensure that you are using the latests code by performing a `git pull`.

Please include your operating system name, your operating system version number (16.04, 18.6, etc), and the dojo install type you are using (setup.bash, docker, k8s, etc).

Bugs that do not have this information will be closed.

# Contributing to DefectDojo

Here are a few things to keep in mind when making changes to DefectDojo.

## Submission Pre-Approval

We don't want to waste your time, so if you're unsure whether your hypothetical enhancement meets the criteria for approval, please file an issue to get pre-approval before beginning work on a PR. If approved, we will add the
`enhancement-approved` label to your issue and you can begin building it out.

Below are some representative examples of what we will and won't support going forward. If you have suggestions or other
feedback, please let us know in the `#defectdojo` channel in [OWASP's Slack](https://owasp.org/slack/invite).

**Acceptable examples:**

* New parser for a currently unsupported tool
* Bug fix for an existing parser or other core feature
* Resolving a security vulnerability
* Adding or improving tests

**Examples where pre-approval is recommended:**

* A new text field to enhance the data that can be collected about a Finding
* Better filtering/sorting capabilities
* Minor changes that make the existing UI more intuitive

**Examples that will not be approved:**

* API routes to support a new 3rd party integration
* A new model to support a new Finding field or other functionality
* A new page in the UI to collect additional metadata

## Writing a New Parser

Please see [the parser guide](https://docs.defectdojo.com/en/open_source/contributing/how-to-write-a-parser/) for guidance on how to write a parser.

## Modifying DefectDojo and Testing

Please use [these test scripts](../tests) to test your changes. These are the scripts we run in our [integration tests](DOCKER.md#run-the-tests-with-docker).

For changes that require additional settings, you can now use local_settings.py file. See the logging section below for more information.

## Python3 Version
For compatibility reasons, the code in dev branch should be python3.13 compliant.

## Database migrations
When changes are made to the database model, a database migration is needed. This migration can be generated using something like
`docker compose exec uwsgi bash -c "python manage.py makemigrations"`.
This will result in a new file in the `dojo/db_migrations` folder that can be committed to `git`
When making downstream database model changes in your fork of Defect Dojo please be aware of the risks of getting out of sync with our upstream migrations.
It requiers proper knowledge of [Django Migrations](https://docs.djangoproject.com/en/5.0/topics/migrations/) to reconcile the migrations before you can upgrade to a newer version of Defect Dojo.

### Linear Migration History

DefectDojo uses [django-linear-migrations](https://github.com/adamchainz/django-linear-migrations) to maintain a linear migration history and avoid merge migration conflicts.

**What this means for you:**
- When you run `makemigrations`, a `max_migration.txt` file is automatically updated in `dojo/db_migrations/`
- This file tracks the latest migration and must be committed along with your migration file
- If you're working on a feature branch and migrations are added to `dev` branch, you may encounter a merge conflict in `max_migration.txt`

**Resolving migration conflicts:**

If you encounter a conflict in `dojo/db_migrations/max_migration.txt` during a rebase or merge, follow these steps:

1. **Abort the current rebase/merge** (you can't switch branches while in conflict):
   ```bash
   git rebase --abort
   # OR if you were merging: git merge --abort
   ```

2. **Reverse your migration** from your local database (you're still on your feature branch):
   ```bash
   # First, check the conflicting migration number (look at your latest migration file)
   # Then migrate back to the last migration before yours
   docker compose exec uwsgi bash -c "python manage.py migrate dojo XXXX_last_migration_before_yours"
   ```

3. **Fetch the latest changes and retry the rebase**:
   ```bash
   git fetch origin
   git rebase origin/dev
   # Git will show a conflict in max_migration.txt
   ```

4. **Use the `rebase_migration` command** to automatically fix the conflict:
   ```bash
   docker compose exec uwsgi bash -c "python manage.py rebase_migration dojo"
   ```
   This command will:
   - Rename your migration to follow the latest migration from `dev`
   - Update its dependencies
   - Update `max_migration.txt`

5. **Continue the rebase**:
   ```bash
   git add dojo/db_migrations
   git rebase --continue
   ```

6. **Apply the rebased migration** to your local database:
   ```bash
   docker compose exec uwsgi bash -c "python manage.py migrate dojo"
   ```

**Tips:**
- If your feature branch has multiple commits modifying the same migration, squash them first before rebasing
- To find the "last migration before yours", look at your migration file's dependencies
- It's also possible to skip steps 1-3 and then in step 6 do `python manage.py migrate dojo XXXX_last_migration_before_yours` and `python manage.py migrate dojo --fake` to skip your migrations if they have already been applied during earlier development.

## Submitting Pull Requests

The following are things to consider before submitting a pull request to
DefectDojo.

0. Base your PR against the `dev` or `bugfix` branch, unless discussed otherwise with the maintainers

0. Make sure that the install is working properly.

0. All tests found in [these test scripts](../tests) should be passing.

0. All submitted code should conform to [__PEP8 standards__][pep8].

0. See [flake8 built-in commit hooks] on how to easily check for for pep8 with flake8 before comitting.

0. Pull requests should be submitted to the `dev` or `bugfix` branch.

0. In dev branch, the code should be python 3.13 compliant.

[dojo_settings]: /dojo/settings/settings.dist.py "DefectDojo settings file"
[pep8]: https://www.python.org/dev/peps/pep-0008/ "PEP8"
[flake8 built-in commit hooks]: https://flake8.pycqa.org/en/latest/user/using-hooks.html#built-in-hook-integration


## Code Review Process

During the review process, one or more reviewers may provide feedback on your changes.
Requested changes from reviewers should stay within the scope of the PR.
Please do not resolve comments without any discussion. If you decide not to make a suggested change,
make sure to leave a brief reply as a response so that everyone
is on the same page. The reviewer can then resolve the comment if the reasoning is acceptable.
