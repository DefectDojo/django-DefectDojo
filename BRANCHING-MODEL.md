# Introduction
This section describes
- how branches are handled
- defectdojo release cycle

Please be careful to submit your pull requests to the correct branch: 
- bugfix: latest  "release/a.b.x" branch (+ merge using a separate PR against the dev branch)
- evolutions: dev branch

If in doubt please use dev branch.

# Release and hotfix model
![Schemas](doc/branching_model.png)


Diagrams created with https://www.planttext.com/

This model is inspired by https://nvie.com/posts/a-successful-git-branching-model/ with the feature branch being made in each contributor repository.