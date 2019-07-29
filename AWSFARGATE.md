# DefectDojo on AWS Fargate

DefectDojo on AWS Fargate uses AWS Cloudformation template

## DefectDojo on AWS Fargate Quickstart

### Requirements:
1. Existence and configuration of a target AWS Fargate cluster in your account including its VPC and Subnet(s) dependency
2. Existence of an AWS IAM Role for ECS runtime, which requires the trust relationship for ecs-tasks.amazonaws.com and access for CloudWatch and ECS through IAM Policies
3. Creation of external defectdojo database (like AWS RDS MySQL)

requirements 1 + 2 should be inplace if your organisation has experience with AWS Fargate

### Execution

aws cloudformation create-stack --stack-name defectdojo --template-body file:///$PWD/aws-fargate.yml

### Clean up

aws cloudformation delete-stack --stack-name defectdojo