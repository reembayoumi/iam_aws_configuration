# Author

Reem Bayoumi (reem.bayoumi@gmail.com)



# AWS Free-Tier Setup with Terraform

This repository contains Terraform scripts to set up an AWS free-tier account with a secure and organized AWS environment with specific IAM and security configurations.

## Prerequisites

- AWS free-tier account. Sign up at [AWS Free Tier](https://aws.amazon.com/free)

## Authenticate Terraform to AWS
To use the environment variables option to authenticate, credentials can be provided by using the AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

- In the command shell, the environment variables are set as follows:

```sh
   $ export AWS_ACCESS_KEY_ID="my-access-key"
   $ export AWS_SECRET_ACCESS_KEY="my-secret-key"
```


## Setup Instructions

1. **Create a Free-Tier AWS Account:**
   - Go to [AWS Free Tier](https://aws.amazon.com/free) and sign up for an account.

2. **Enable AWS Organizations:**
   - AWS Organizations allows you to create and manage multiple AWS accounts. It's always free.

3. **Enable IAM Identity Center "Manual":**
- This should be done in the AWS console.
- Go to the AWS console - Open IAM Identity Center - Click "Enable"

## Repository Structure

- `main.tf`: Main Terraform configuration file.
- `variables.tf`: Variables used in the Terraform scripts.


## Usage

1. **Initialize Terraform:**

    ```sh
   terraform init
    ```

2. **Plan the Infrastructure "Dry Run":**

    ```sh
    terraform plan
    ```

3. **Apply the Terraform Scripts:**

    ```sh
    terraform apply
    ```

4. **Verify AWS Setup:**
   - Check AWS Management Console to ensure that AWS Organizations, IAM Identity Center, Security Hub, and CloudTrail are properly configured.
   - Verify that the SCPs are working as expected by attempting to disable Security Hub and CloudTrail and checking the permissions on the CloudTrail S3 bucket.

