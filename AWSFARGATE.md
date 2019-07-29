# DefectDojo on AWS Fargate

DefectDojo on AWS Fargate uses AWS Cloudformation template

## DefectDojo on AWS Fargate Quickstart

### Requirements:
1. Existence and configuration of a target AWS Fargate cluster in your account, including its VPC and subnet(s) dependency needed 
2. Existence of an AWS IAM Role for ECS runtime. This role is used by the AWS Fargate task definition on runtime to access AWS resources. The role requires a trust relationship for ecs-tasks.amazonaws.com and in this setup access to CloudWatch and ECS through AWS IAM Policies
3. Creation of external defectdojo database (like AWS RDS MySQL)

requirements 1 + 2 should be in place if your organisation has experience with AWS Fargate

### Execution

aws cloudformation create-stack --stack-name defectdojo --template-body file:///$PWD/aws-fargate.yml

### Clean up

aws cloudformation delete-stack --stack-name defectdojo