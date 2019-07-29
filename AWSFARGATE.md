# DefectDojo on AWS Fargate

DefectDojo on AWS Fargate uses a single AWS Cloudformation template

## DefectDojo on AWS Fargate Quickstart

### Requirements:
1. Enough AWS permissions in the AWS account (Administrator/PowerUser or better based on least-privilege)
2. Existence of a target AWS Fargate cluster in your account, including its VPC and subnet(s) dependency needed 
3. Existence of an AWS IAM Role for ECS runtime. This role is used by the AWS Fargate task definition on runtime to access AWS resources. The role requires a trust relationship for ecs-tasks.amazonaws.com and in this setup access to CloudWatch and ECS through AWS IAM Policies
4. Creation of external defectdojo database (like AWS RDS MySQL) where you will need the endpoint, username, password and name

requirements 2 + 3 should be in place if your organisation has experience with AWS Fargate

### Preperation
Modify the parameters in [aws-farget.yml](aws-farget.yml) with the correct values for your AWS account and target environment.

### Execution
aws cloudformation create-stack --stack-name defectdojo --template-body file:///$PWD/aws-fargate.yml

### Clean up
aws cloudformation delete-stack --stack-name defectdojo