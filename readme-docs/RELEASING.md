# Releasing Defect Dojo

### Summary

We have two types of releases:

1. **Feature releases** - These are created from the `dev` branch, via a new release branch, i.e. `release/x.y.z`. 
2. **Bugfix releases** - These are created from the `master` branch,  via a new release branch, i.e. `release/x.y.z`. 

The release process will then:

- Create a PR to merge that release branch into `master`
- Tag the release, Build the dockers images and Push them to Docker Hub
- Merge the changes in `master` "back into dev" to make sure `dev` is in sync again with `master`

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
- Make sure there's a section in [upgrading.md](./docs/content/en/getting_started/upgrading.md) about any specific instructions when upgrading to this new release.

Due to the release drafter being a non-perfect match for our git flow based release process, we have to delete any draft that has already been created by the release drafter if it has the same versio number.

- Go to [Releases]() and delete any draft release that has the same version number as the release you are planning to release today.

![image](https://user-images.githubusercontent.com/4426050/149619158-a467170d-5c5a-4311-a0db-31a825e8d5dd.png)

If you want you can copy the contents of the release somewhere for later use. This is not really needed as in the final step below we will use the release drafter to generate the correct contents and assign it to the correct release.
If you do not delete any existing draft release, you will end up with multiple draft releases with the same version. One will have release notes and the other will have the helm chart. So it's safer to just start with a clean sheet and follow the steps below.

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

### Publich release


# FAQ

## Version numbers

## Release drafter


