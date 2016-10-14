
# coreo_aws_advisor_alert "iam-unusediamgroup" do
#   action :define
#   service :iam
#   link "http://kb.cloudcoreo.com/mydoc_iam-unusediamgroup.html"
#   display_name "Unused or empty IAM group"
#   description "There is an IAM group defined without any users in it and therefore unused."
#   category "Access"
#   suggested_action "Ensure that groups defined within IAM have active users in them. If the groups don't have active users or are not being used, delete the unused IAM group."
#   level "Warning"
#   objectives ["groups", "group"]
#   call_modifiers [{}, { :group_name => "groups.group_name" }]
#   formulas ["", "count"]
#   audit_objects ["", "users"]
#   operators ["", "=="]
#   alert_when ["", 0]
# end

coreo_aws_advisor_alert "iam-inactive-key-no-rotation" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-inactive-key-no-rotation.html"
  display_name "Inactive user Access Key not rotated"
  description "User has inactive keys that have not been rotated in the last 90 days."
  category "Access"
  suggested_action "If you regularly use the AWS access keys, we recommend that you also regularly rotate or delete them."
  level "Alert"
  id_map "object.access_key_metadata.access_key_id"
  objectives ["users", "access_keys", "access_keys"]
  audit_objects ["", "access_key_metadata.status", "access_key_metadata.create_date"]
  call_modifiers [{}, {:user_name => "users.user_name"}, {:user_name => "users.user_name"}]
  operators ["", "==", "<"]
  alert_when ["", "Inactive", "7.days.ago"]
end

# coreo_aws_advisor_alert "iam-active-key-no-rotation" do
#   action :define
#   service :iam
#   link "http://kb.cloudcoreo.com/mydoc_iam-active-key-no-rotation.html"
#   display_name "Active user Access Key not rotated"
#   description "User has active keys that have not been rotated in the last 90 days"
#   category "Access"
#   suggested_action "If you regularly use the AWS access keys, we recommend that you also regularly rotate or delete them."
#   level "Alert"
#   id_map "object.access_key_metadata.access_key_id"
#   objectives ["users", "access_keys", "access_keys"]
#   audit_objects ["", "access_key_metadata.status", "access_key_metadata.create_date"]
#   call_modifiers [{}, {:user_name => "users.user_name"}, {:user_name => "users.user_name"}]
#   operators ["", "==", "<"]
#   alert_when ["", "Active", "90.days.ago"]
end

# coreo_aws_advisor_alert "iam-missing-password-policy" do
#   action :define
#   service :iam
#   link "http://kb.cloudcoreo.com/mydoc_iam-missing-password-policy.html"
#   display_name "Password policy doesn't exist"
#   description "There currently isn't a password policy to require a certain password length, password expiration, prevent password reuse, and more."
#   category "Access"
#   suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
#   level "Critical"
#   objectives ["account_password_policy"]
#   audit_objects ["object.password_policy"]
#   operators ["=="]
#   alert_when [nil]
# end

# coreo_aws_advisor_alert "iam-passwordreuseprevention" do
#   action :define
#   service :iam
#   link "http://kb.cloudcoreo.com/mydoc_iam-passwordreuseprevention.html"
#   display_name "Users can reuse old passwords"
#   description "The current password policy doesn't prevent users from reusing thier old passwords."
#   category "Access"
#   suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
#   level "Critical"
#   objectives ["account_password_policy"]
#   audit_objects ["object.password_policy.password_reuse_prevention"]
#   operators ["=="]
#   alert_when [nil]
# end

# coreo_aws_advisor_alert "iam-expirepasswords" do
#   action :define
#   service :iam
#   link "http://kb.cloudcoreo.com/mydoc_iam-expirepasswords.html"
#   display_name "Passwords not set to expire"
#   description "The current password policy doesn't require users to regularly change their passwords. User passwords are set to never expire."
#   category "Access"
#   suggested_action "Configure a strong password policy for your users so that passwords expire such that users must change their passwords periodically."
#   level "Critical"
#   objectives ["account_password_policy"]
#   audit_objects ["object.password_policy.expire_passwords"]
#   operators ["=="]
#   alert_when ["false"]
# end

# coreo_aws_advisor_alert "iam-no-mfa" do
#   action :define
#   service :iam
#   link "http://kb.cloudcoreo.com/mydoc_iam-no-mfa.html"
#   display_name "Multi-Factor Authentication not enabled"
#   description "Cloud user does not have Multi-Factor Authentication enabled on their cloud account."
#   category "Security"
#   suggested_action "Enable Multi-Factor Authentication for every cloud user."
#   level "Critical"
#   id_map "modifiers.user_name"
#   objectives ["users", "mfa_devices"]
#   formulas ["", "count"]
#   call_modifiers [{}, { :user_name => "users.user_name" }]
#   audit_objects ["", "object.mfa_devices"]
#   operators ["", "<"]
#   alert_when ["", 1]
# end

# coreo_aws_advisor_alert "iam-root-no-mfa" do
#   action :define
#   service :iam
#   link "http://kb.cloudcoreo.com/mydoc_iam-root-no-mfa.html"
#   display_name "Multi-Factor Authentication not enabled for root account"
#   description "Root cloud user does not have Multi-Factor Authentication enabled on their cloud account"
#   category "Security"
#   suggested_action "Enable Multi-Factor Authentication for the root cloud user."
#   level "Emergency"
#   id_map "object.user"
#   objectives ["credential_report"]
#   formulas ["CSV[user=<root_account>]"]
#   audit_objects ["object.content.mfa_active"]
#   operators ["=="]
#   alert_when ["false"]
# end

# coreo_aws_advisor_alert "iam-root-active-key" do
#   action :define
#   service :iam
#   link "http://kb.cloudcoreo.com/mydoc_iam-root-active-key.html"
#   display_name "Root user has active Access Key"
#   description "Root user has an Access Key that is active."
#   category "Security"
#   suggested_action "Replace the root Access Key with an IAM user access key, and then disable and remove the root access key."
#   level "Critical"
#   id_map "object.user"
#   objectives ["credential_report"]
#   formulas ["CSV[user=<root_account>]"]
#   audit_objects ["object.content.access_key_1_active"]
#   operators ["=="]
#   alert_when ["true"]
# end

# coreo_aws_advisor_alert "iam-root-active-password" do
#   action :define
#   service :iam
#   link "http://kb.cloudcoreo.com/mydoc_iam-root-active-password.html"
#   display_name "Root user has active password"
#   description "The root user has been logging in using a password."
#   category "Security"
#   suggested_action "Re-set your root account password, don't log in to your root account, and secure root account password in a safe place."
#   level "Critical"
#   id_map "object.user"
#   objectives ["credential_report"]
#   formulas ["CSV[user=<root_account>]"]
#   audit_objects ["object.content.password_last_used"]
#   operators [">"]
#   alert_when ["15.days.ago"]
# end

# coreo_aws_advisor_alert "iam-user-attached-policies" do
#   action :define
#   service :iam
#   link "http://kb.cloudcoreo.com/mydoc_iam-user-attached-policies.html"
#   display_name "Account using inline policies"
#   description "User account is using custom inline policies versus using IAM group managed policies."
#   category "Access"
#   suggested_action "Switch all inline policies to apply to IAM groups and assign users IAMs roles."
#   level "Warning"
#   id_map "modifiers.user_name"
#   objectives ["users", "user_policies"]
#   formulas ["", "count"]
#   call_modifiers [{}, { :user_name => "users.user_name" }]
#   audit_objects ["", "object.policy_names"]
#   operators ["", ">"]
#   alert_when ["", 0]
# end

coreo_aws_advisor_iam "advise-iam" do
  action :advise
  alerts ${AUDIT_AWS_IAM_ALERT_LIST}
end

coreo_uni_util_notify "advise-iam" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_IAM_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_IAM_SEND_ON}"
  payload '{"stack name":"INSTANCE::stack_name",
  "instance name":"INSTANCE::name",
  "number_of_checks":"STACK::coreo_aws_advisor_iam.advise-iam.number_checks",
  "number_of_violations":"STACK::coreo_aws_advisor_iam.advise-iam.number_violations",
  "number_violations_ignored":"STACK::coreo_aws_advisor_iam.advise-iam.number_ignored_violations",
  "violations": STACK::coreo_aws_advisor_iam.advise-iam.report }'
  payload_type "json"
  endpoint ({ 
              :to => '${AUDIT_AWS_IAM_ALERT_RECIPIENT}', :subject => 'CloudCoreo iam advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
            })
end
