# Releasing Defect Dojo

### Summary

Every release is cut from the `dev` branch. There are two kinds, and they follow the same procedure:

1. **Monthly minor releases** (`x.y.0`)
2. **Weekly patch releases** (`x.y.100`, `x.y.200`, ...)

The release schedule decides which one is next. Dependency updates, bug fixes and security patches, urgent ones included, go into the next release from `dev`. There is no separate branch for bug fixes and no hotfix branch off `master`.

The release process will then:

- Create a `release/merge-dev-into-master-x.y.z` branch from `dev` and a PR to merge it into `master` (`Release-1`)
- Tag the release, build the docker images and push them to Docker Hub (`Release-2`)
- Merge the changes in `master` back into `dev` so the two stay in sync (`Release-3`)

# Before you start

- Make sure the `dev` branch contains exactly what you want to release.
- Make sure there's a section in [os_upgrading](../docs/content/releases/os_upgrading) about any specific instructions when upgrading to this new release.

- Remove existing draft releases with the same version number
The release drafter is not a perfect match for our release process, so delete any draft it has already created with the same version number.

- Go to [Releases](https://github.com/DefectDojo/django-DefectDojo/releases) and delete any draft release that has the same version number as the release you are planning to release today.

![image](https://user-images.githubusercontent.com/4426050/149619158-a467170d-5c5a-4311-a0db-31a825e8d5dd.png)

If you want you can copy the contents of the release somewhere for later use. This is not really needed as in the final step below we will use the release drafter to generate the correct contents and assign it to the correct release.

If you do not delete any existing draft release, you will end up with multiple draft releases with the same version. One will have release notes and the other will have the helm chart. It's safer to start with a clean sheet and follow the steps below.

# Creating the PR to merge into `master`

Run the `Release-1: Create PR for master` action. Leave `from_branch` on `dev` (the only option) and enter the release version: `x.y.0` for a minor release, `x.y.100` / `x.y.200` / ... for a patch release.

![image](https://user-images.githubusercontent.com/4426050/149574288-a4056fb9-859c-413e-9f60-bc59894b0528.png)

The action creates the `release/merge-dev-into-master-x.y.z` branch from `dev`, updates the version numbers in it, removes the `-dev` suffix from the helm chart version, and opens the PR against `master`.

Verify the PR is created, and check if the commits in it make sense:

![image](https://user-images.githubusercontent.com/4426050/149576847-df4d8347-af08-49dc-ab21-ad19ea37b3cd.png)

![image](https://user-images.githubusercontent.com/4426050/149576899-e9fc1d91-de78-4126-a12d-cc6a6fe39d1b.png)


# Merge the PR into master

Go to the bottom of the lists of commits, click on the `Update versions in application files` commit and check the version number updates.

![image](https://user-images.githubusercontent.com/4426050/149577123-572cc6dd-7bf3-44ad-af58-ab6e46905558.png)

Do not wait for CI. The release PR and the merge-back PR are merged as soon as they are conflict-free, to save time and runner cost. CI skips them on purpose: a pull request is skipped when its head branch starts with `release/merge-` and it has the `release-management` label (both release actions add it), and a push is skipped when the branch starts with `release/merge-` or the commit is GitHub's merge commit for such a PR. This is the same rule the other DefectDojo repositories use.

Merge into `master` by *creating a merge commit*. Do NOT squash the commits!

![image](https://user-images.githubusercontent.com/4426050/149577269-d51fe1ee-ba0d-4a9b-94e7-ec286954b5e2.png)

# Make the release and push docker images

Run the `Release-2: Tag, Release, Push` action:

![image](https://user-images.githubusercontent.com/4426050/149578985-879118e1-c9d2-4767-a366-f417041debab.png)

This action will:

- Tag the HEAD of the `master` branch as the new release, i.e. 2.7.0 in the screenshot.
- Create a new release based on this tag
- Generate the helm chart for this release and upload it as a release asset
- Update the `helm` repository stored in the `helm-charts` branch
- Build the `django` and `nginx` docker images and push them to [Docker Hub](https://hub.docker.com/orgs/defectdojo/repositories)

Observe the output of the action to make sure there are no errors.

Verify the results:
- Go to [Release](https://github.com/DefectDojo/django-DefectDojo/releases) to check the new release
- Check if the helm chart is attached:

![image](https://user-images.githubusercontent.com/4426050/149618426-9d2c145f-89f4-4d22-9cb6-b020e7bd2fc2.png)

- We will populate the release notes in a later step
- Check [Docker Hub](https://hub.docker.com/orgs/defectdojo/repositories) to see if the docker images have been uploaded

![image](https://user-images.githubusercontent.com/4426050/149618481-51f4fa73-8611-4477-9ac4-3a6013778ab6.png)

![image](https://user-images.githubusercontent.com/4426050/149618495-97dd7452-492e-49a8-a8a3-dd93ee4505cf.png)

# Bring `dev` in sync with `master`

To avoid merge conflicts and drift between branches, we have to get `dev` back into sync with `master`. This step also sets `dev` to the version of the next scheduled release, with a `-dev` suffix.

Run the `Release-3: PR for merging master into dev` action. Enter the version you just released and the next version for `dev` (`x.y.z-dev`).

![image](https://user-images.githubusercontent.com/4426050/149618563-05707161-7111-4ba9-ad18-6239f66c3aa5.png)

Check the PR and the version number updates.

![image](https://user-images.githubusercontent.com/4426050/149618605-fd94b6a8-d348-4fc5-8eaf-92f23b1b54b7.png)

No tests run on this PR (see above), so merge it as soon as it is conflict-free.

Merge the `Release: Merge back x.y.z into dev from: release/merge-master-into-dev-x.y.z` PR by using a *Merge Commit*. Do NOT squash the commits.

![image](https://user-images.githubusercontent.com/4426050/149618642-276fffca-7e6f-4c51-bd9b-52bb5628cb7b.png)

# Publish the release with release notes

### Generate release notes
Because we have merged the release PR into master, the release draft has been triggered. Check the output to see if it has created a new, or updated an existing, x.y.z draft release.

![image](https://user-images.githubusercontent.com/4426050/149619597-4cc655a6-0476-40d2-a1b5-34eebdf9f64f.png)

![image](https://user-images.githubusercontent.com/4426050/149619614-728736a4-e58f-4792-9b27-ead24ec07fc4.png)

Every release comes from `dev`, so the previous release is the right starting point for the notes: they list the PRs merged since then.

![image](https://user-images.githubusercontent.com/4426050/149619779-1d065baf-be09-41b7-a54c-b2676948a6cb.png)

If the notes need to start from a different release, run the `Release Drafter (custom range)` action and set `filter-by-range` to that release, e.g. `3.1.0`. Use `dry-run` first to confirm where the changeset starts.

As a finishing touch make sure the emoji in the release name is present. We have special emoji for security releases, see a previous security release:

![image](https://user-images.githubusercontent.com/4426050/149619999-0d601ec7-7f91-4399-b396-5f11ebab3b55.png)

![image](https://user-images.githubusercontent.com/4426050/149620011-b2a26d88-0c1c-49c9-9b3c-17d876532d8a.png)

### Publish release

All should be good now, including the release notes. So let's publish!

- Head over to [Release](https://github.com/DefectDojo/django-DefectDojo/releases)
- Click on the 'edit' icon for the release you just created
- Publish: 

![image](https://user-images.githubusercontent.com/4426050/149619971-262104a7-55e6-4dc7-80f8-988c28d1b3ad.png)

# Shout on social media

[@madchap](https://github.com/madchap) has created an automation pipeline that will post the new release on the #defectdojo Slack channel, on the DefectDojo twitter and on LinkedIn.
