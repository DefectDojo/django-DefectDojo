# Releasing Defect Dojo

### Summary

We have two types of releases:

1. Feature releases - These are taking the new commits from dev into a new release branch, i.e. `release/x.y.z`. 
2. Bugfix releases - These are creating a branch from `master` and bugfixes will be added to that branch, i.e. `release/x.y.z`. 

The release process will then:

- Create a PR to merge that release branch into `master`
- Tag the release, Build the dockers images and Push them to Docker Hub
- Merge the changes in `master` "back into dev" to make sure `dev` is in sync again with `master`

# Creating and preparing the release branch

### Feature release
- Make sure the `dev` branch contains exactly that what you want to release. 
- Create a new release branch from the `dev` branch:

![image](https://user-images.githubusercontent.com/4426050/149572033-49a6c2a7-6c5b-4272-84e5-040c661598b4.png)

### Bugfix release
- Create a new branch from `master` which will receive the bugfix PRs for the release, i.e. `release/x.y.z`.

![image](https://user-images.githubusercontent.com/4426050/149572118-cd62bab3-7daf-4c23-829e-0aa2c595376f.png)

- Create bugfix PRs against the new release branch:
- Merge the PRs

### Always
- Make sure there's a section in [upgrading.md](./docs/content/en/getting_started/upgrading.md) about any specific instructions when upgrading to this new release.

# Creating the PR to merge into `master`

Run the `Release-1: Create PR for master` action:

![image](https://user-images.githubusercontent.com/4426050/149574288-a4056fb9-859c-413e-9f60-bc59894b0528.png)

Verify the PR is created, and check if the commits in it make sense:

![image](https://user-images.githubusercontent.com/4426050/149576847-df4d8347-af08-49dc-ab21-ad19ea37b3cd.png)

![image](https://user-images.githubusercontent.com/4426050/149576899-e9fc1d91-de78-4126-a12d-cc6a6fe39d1b.png)


# Merge the PR into master

Go to the bottom of the lists of commits, click on the `Update versions in application files` commit and check the version numbers in `dojo/__init__.py`, `components/package.json` and `helm/defectdojo/Chart.yaml`.

![image](https://user-images.githubusercontent.com/4426050/149577123-572cc6dd-7bf3-44ad-af58-ab6e46905558.png)

Ideally we wait until the test suite becomes green. If you're feeling brace, you can skip the waiting and instead wait for the tests to become green after merging into `master`.

Merge into `master` by *creating a merge commit*. Do NOT squash the commits!

![image](https://user-images.githubusercontent.com/4426050/149577269-d51fe1ee-ba0d-4a9b-94e7-ec286954b5e2.png)

