audit IAM
============================
This stack will monitor IAM and alert on things CloudCoreo developers think are violations of best practices


## Description

This repo is designed to work with CloudCoreo. It will monitor IAM against best practices for you and send a report to the email address designated by the config.yaml AUDIT_AWS_IAM_ALERT_RECIPIENT value

## Variables Requiring Your Input

### `AUDIT_AWS_IAM_ALERT_RECIPIENT`:
  * description: email recipient for notification

## Variables Required but Defaulted

### `AUDIT_AWS_IAM_ALERT_LIST`:
  * description: alert list for generating notifications
  * default: iam-unusediamgroup,iam-inactive-key-no-rotation,iam-active-key-no-rotation,iam-passwordreuseprevention,iam-missing-password-policy,iam-expirepasswords,iam-no-mfa,iam-root-no-mfa,iam-root-active-key,iam-root-active-password,iam-user-attached-policies

### `AUDIT_AWS_IAM_ALERT_RECIPIENT`:
  * description: email recipient for notification

### `AUDIT_AWS_IAM_ALLOW_EMPTY`:
  * description: receive empty reports?

### `AUDIT_AWS_IAM_PAYLOAD_TYPE`:
  * description: json or text
  * default: json

### `AUDIT_AWS_IAM_SEND_ON`:
  * description: always or change
  * default: change

### `AUDIT_AWS_IAM_REGIONS`:
  * description: list of AWS regions to check. Default is all regions
  * default: us-east-1,us-west-1,us-west-2

## Variables Not Required

**None**

## Tags

1. Audit
1. Best Practices
1. Alert
1. IAM

## Categories

1. Audit

## Diagram



## Icon



