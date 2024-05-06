# Releasing Defect Dojo

### Summary

We have two types of releases:

1. **Feature releases** - These are created from the `dev` branch, via a new release branch, i.e. `release/x.y.z`. 
2. **Bugfix releases** - These are created from the `bugfix` branch, via a new release branch, i.e. `release/x.y.z`. 

The release process will then:

- Create a PR to merge that release branch into `master`
- Tag the release, Build the dockers images and Push them to Docker Hub
- Merge the changes in `master` "back into dev" to make sure `dev` and `bugfix` is in sync again with `master`

The steps are identical for both release types, unless specified otherwise below.

# Creating and preparing the release branch

### Feature release
- Make sure the `dev` branch contains exactly that what you want to release. 
- Create a new release branch from the `dev` branch:

![image](https://user-images.githubusercontent.com/4426050/149572033-49a6c2a7-6c5b-4272-84e5-040c661598b4.png)

### Bugfix release
- Create a new branch from `master` which will receive the bugfix PRs for the release, i.e. `release/x.y.z`.

![image](https://user-images.githubusercontent.com/4426050/149616927-d26b3812-f5ce-4bd3-a196-a72293dd9377.png)

- Create bugfix PRs against the new release branch:
- Merge the PRs

### Always
- Make sure there's a section in [upgrading.md](https://documentation.defectdojo.com/dev/getting_started/upgrading/) about any specific instructions when upgrading to this new release.

- Remove existing draft releases with the same version number
Due to the release drafter being a non-perfect match for our git flow based release process, we have to delete any draft that has already been created by the release drafter if it has the same versio number. This is probably not needed if you're doing a bugfix release.

- Go to [Releases](https://github.com/DefectDojo/django-DefectDojo/releases) and delete any draft release that has the same version number as the release you are planning to release today.

![image](https://user-images.githubusercontent.com/4426050/149619158-a467170d-5c5a-4311-a0db-31a825e8d5dd.png)

If you want you can copy the contents of the release somewhere for later use. This is not really needed as in the final step below we will use the release drafter to generate the correct contents and assign it to the correct release.

If you do not delete any existing draft release, you will end up with multiple draft releases with the same version. One will have release notes and the other will have the helm chart. It's safer to start with a clean sheet and follow the steps below.

# Creating the PR to merge into `master`

Run the `Release-1: Create PR for master` action:

![image](https://user-images.githubusercontent.com/4426050/149574288-a4056fb9-859c-413e-9f60-bc59894b0528.png)

Verify the PR is created, and check if the commits in it make sense:

![image](https://user-images.githubusercontent.com/4426050/149576847-df4d8347-af08-49dc-ab21-ad19ea37b3cd.png)

![image](https://user-images.githubusercontent.com/4426050/149576899-e9fc1d91-de78-4126-a12d-cc6a6fe39d1b.png)


# Merge the PR into master

Go to the bottom of the lists of commits, click on the `Update versions in application files` commit and check the version number updates.

![image](https://user-images.githubusercontent.com/4426050/149577123-572cc6dd-7bf3-44ad-af58-ab6e46905558.png)

Ideally we wait until the test suite becomes green. If you're feeling brace, you can skip the waiting and instead wait for the tests to become green after merging into `master`.

Merge into `master` by *creating a merge commit*. Do NOT squash the commits!

![image](https://user-images.githubusercontent.com/4426050/149577269-d51fe1ee-ba0d-4a9b-94e7-ec286954b5e2.png)

Go to [GitHub Actions](https://github.com/DefectDojo/django-DefectDojo/actions) and pray for them to become green.

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

To avoid merge conflicts and drigts between branches, we have to get `dev` back into sync with `master`. This step also bumps the version numbers if needed.

Run the `Release-3: PR for merging master into dev` action.

![image](https://user-images.githubusercontent.com/4426050/149618563-05707161-7111-4ba9-ad18-6239f66c3aa5.png)

Check the PR and versio number updates. For a fix version problably the version numbers are already correct on `dev`.

![image](https://user-images.githubusercontent.com/4426050/149618605-fd94b6a8-d348-4fc5-8eaf-92f23b1b54b7.png)

Wait for the tests to complete. 

You can work on the release notes in the next step while waiting.

Merge the `Release: Merge back x.y.z into dev from: master-into-dev/x.y.z-a.b.c-dev` PR by using a *Merge Commit*. Do NOT squash the commits.

![image](https://user-images.githubusercontent.com/4426050/149618642-276fffca-7e6f-4c51-bd9b-52bb5628cb7b.png)

# Publish the release with release notes

### Generate release notes
Because we have merged the release PR into master, the release draft has been triggered. Check the output to see if it has created a new, or updated an existing, x.y.z draft release.

![image](https://user-images.githubusercontent.com/4426050/149619597-4cc655a6-0476-40d2-a1b5-34eebdf9f64f.png)

![image](https://user-images.githubusercontent.com/4426050/149619614-728736a4-e58f-4792-9b27-ead24ec07fc4.png)

### Bugfix releases
For bugfix releases the release drafter generates the correct release notes. These will contain the merged PRs since the previous release.

![image](https://user-images.githubusercontent.com/4426050/149619779-1d065baf-be09-41b7-a54c-b2676948a6cb.png)


### Feature releases
For features releases the release drafter will mess up if the **previous release was a bugfix release**. If the previous release was a feature release (x.y.0), the release notes will be generated correctly.

For when the previous release was a bugfix release, i.e. 2.6.2:

The release drafter does not look at releases or tags or branches. It just looks as the _date_ of the previous release and it will list all PRs merged since that date. So it will list all PRs merged since for example 2.6.2. This might miss PRs that have been merged _into dev_ between the release date of 2.6.0 and 2.6.2. To correct that, we have a fork of the release drafter that allows you to specify which release to use as the previous release. In this case we want all PRs listed that have been merged since 2.6.0.

Run the `Release Drafter Valentijn` and specify the desired previous (feature) release to use:

![image](https://user-images.githubusercontent.com/4426050/149619852-dc1dad77-b7b6-479d-8d9f-4ac1571ea92c.png)

Output:

![image](https://user-images.githubusercontent.com/4426050/149619893-3f8ce398-aec2-467e-bb66-e8efc8dc66d6.png)

Release notes:

![image](https://user-images.githubusercontent.com/4426050/149619906-f80b805a-67b2-4b3b-9ffb-8edfcf4b7e16.png)

A tiny downside of this is that it will also lists PRs releases in 2.6.1 and 2.6.2, but I think that is acceptable.

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
