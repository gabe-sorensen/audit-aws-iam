
coreo_aws_advisor_alert "iam-inventory-users" do
  action :define
  service :iam
  # link "http://kb.cloudcoreo.com/mydoc_elb-inventory.html"
  include_violations_in_count false
  display_name "IAM User Inventory"
  description "This rule performs an inventory on all IAM Users in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["users"]
  audit_objects ["object.users.user_name"]
  operators ["=~"]
  alert_when [//]
  id_map "object.users.user_name"
end

coreo_aws_advisor_alert "iam-inventory-roles" do
  action :define
  service :iam
  # link "http://kb.cloudcoreo.com/mydoc_elb-inventory.html"
  include_violations_in_count false
  display_name "IAM Role Inventory"
  description "This rule performs an inventory on all IAM Roles in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["roles"]
  audit_objects ["object.roles.role_name"]
  operators ["=~"]
  alert_when [//]
  id_map "object.roles.role_name"
end

coreo_aws_advisor_alert "iam-inventory-policies" do
  action :define
  service :iam
  # link "http://kb.cloudcoreo.com/mydoc_elb-inventory.html"
  include_violations_in_count false
  display_name "IAM Policy Inventory"
  description "This rule performs an inventory on all IAM Policies in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["policies"]
  audit_objects ["object.policies.policy_name"]
  operators ["=~"]
  alert_when [//]
  id_map "object.policies.policy_name"
end

coreo_aws_advisor_alert "iam-inventory-groups" do
  action :define
  service :iam
  # link "http://kb.cloudcoreo.com/mydoc_elb-inventory.html"
  include_violations_in_count false
  display_name "IAM Group Inventory"
  description "This rule performs an inventory on all IAM User Groups in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["groups"]
  audit_objects ["object.groups.group_name"]
  operators ["=~"]
  alert_when [//]
  id_map "object.groups.group_name"
end

coreo_aws_advisor_alert "iam-unusediamgroup" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-unusediamgroup.html"
  display_name "Unused or empty IAM group"
  description "There is an IAM group defined without any users in it and therefore unused."
  category "Access"
  suggested_action "Ensure that groups defined within IAM have active users in them. If the groups don't have active users or are not being used, delete the unused IAM group."
  level "Warning"
  objectives ["groups", "group"]
  call_modifiers [{}, { :group_name => "groups.group_name" }]
  formulas ["", "count"]
  audit_objects ["", "users"]
  operators ["", "=="]
  alert_when ["", 0]
  id_map "object.group.group_name"
end

coreo_aws_advisor_alert "iam-multiple-keys" do
  action :define
  service :iam
  # link "http://kb.cloudcoreo.com/mydoc_iam-unusediamgroup.html"
  display_name "IAM User with multiple keys"
  description "There is an IAM User with multiple access keys"
  category "Access"
  suggested_action "Remove excess access keys"
  level "Warning"
  objectives ["users", "access_keys"]
  call_modifiers [{}, {:user_name => "users.user_name"}]
  formulas ["", "count"]
  audit_objects ["", "object.access_key_metadata"]
  operators ["", ">"]
  alert_when ["", 1]
  id_map "modifiers.user_name"
end

coreo_aws_advisor_alert "iam-inactive-key-no-rotation" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-inactive-key-no-rotation.html"
  display_name "Inactive user Access Key not rotated"
  description "User has inactive keys that have not been rotated in the last 90 days."
  category "Access"
  suggested_action "If you regularly use the AWS access keys, we recommend that you also regularly rotate or delete them."
  level "Critical"
  id_map "object.access_key_metadata.access_key_id"
  objectives ["users", "access_keys", "access_keys"]
  audit_objects ["", "access_key_metadata.status", "access_key_metadata.create_date"]
  call_modifiers [{}, {:user_name => "users.user_name"}, {:user_name => "users.user_name"}]
  operators ["", "==", "<"]
  alert_when ["", "Inactive", "90.days.ago"]
end

coreo_aws_advisor_alert "iam-active-key-no-rotation" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-active-key-no-rotation.html"
  display_name "Active user Access Key not rotated"
  description "User has active keys that have not been rotated in the last 90 days"
  category "Access"
  suggested_action "If you regularly use the AWS access keys, we recommend that you also regularly rotate or delete them."
  level "Critical"
  id_map "modifiers.user_name"
  objectives ["users", "access_keys", "access_keys"]
  audit_objects ["", "access_key_metadata.status", "access_key_metadata.create_date"]
  call_modifiers [{}, {:user_name => "users.user_name"}, {:user_name => "users.user_name"}]
  operators ["", "==", "<"]
  alert_when ["", "Active", "90.days.ago"]
end

coreo_aws_advisor_alert "iam-missing-password-policy" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-missing-password-policy.html"
  display_name "Password policy doesn't exist"
  description "There currently isn't a password policy to require a certain password length, password expiration, prevent password reuse, and more."
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  level "Critical"
  objectives ["account_password_policy"]
  audit_objects ["object"]
  operators ["=="]
  alert_when [nil]
  id_map "static.password_policy"
end

coreo_aws_advisor_alert "iam-passwordreuseprevention" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-passwordreuseprevention.html"
  display_name "Users can reuse old passwords"
  description "The current password policy doesn't prevent users from reusing thier old passwords."
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  level "Critical"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.password_reuse_prevention"]
  operators [">"]
  alert_when [0]
end

coreo_aws_advisor_alert "iam-expirepasswords" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-expirepasswords.html"
  display_name "Passwords not set to expire"
  description "The current password policy doesn't require users to regularly change their passwords. User passwords are set to never expire."
  category "Access"
  suggested_action "Configure a strong password policy for your users so that passwords expire such that users must change their passwords periodically."
  level "Critical"
  objectives ["account_password_policy"]
  audit_objects ["object.password_policy.expire_passwords"]
  operators ["=="]
  alert_when ["false"]
  id_map "static.password_policy"
end

coreo_aws_advisor_alert "iam-no-mfa" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-no-mfa.html"
  display_name "Multi-Factor Authentication not enabled"
  description "Cloud user does not have Multi-Factor Authentication enabled on their cloud account."
  category "Security"
  suggested_action "Enable Multi-Factor Authentication for every cloud user."
  level "Critical"
  id_map "modifiers.user_name"
  objectives ["users", "mfa_devices"]
  formulas ["", "count"]
  call_modifiers [{}, { :user_name => "users.user_name" }]
  audit_objects ["", "object.mfa_devices"]
  operators ["", "<"]
  alert_when ["", 1]
end

coreo_aws_advisor_alert "iam-root-no-mfa" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-root-no-mfa.html"
  display_name "Multi-Factor Authentication not enabled for root account"
  description "Root cloud user does not have Multi-Factor Authentication enabled on their cloud account"
  category "Security"
  suggested_action "Enable Multi-Factor Authentication for the root cloud user."
  level "Emergency"
  id_map "object.user"
  objectives ["credential_report"]
  formulas ["CSV[user=<root_account>]"]
  audit_objects ["object.content.mfa_active"]
  operators ["=="]
  alert_when ["false"]
end

coreo_aws_advisor_alert "iam-root-active-key" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-root-active-key.html"
  display_name "Root user has active Access Key"
  description "Root user has an Access Key that is active."
  category "Security"
  suggested_action "Replace the root Access Key with an IAM user access key, and then disable and remove the root access key."
  level "Critical"
  id_map "object.user"
  objectives ["credential_report"]
  formulas ["CSV[user=<root_account>]"]
  audit_objects ["object.content.access_key_1_active"]
  operators ["=="]
  alert_when ["true"]
end

coreo_aws_advisor_alert "iam-root-active-password" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-root-active-password.html"
  display_name "Root user has active password"
  description "The root user has been logging in using a password."
  category "Security"
  suggested_action "Re-set your root account password, don't log in to your root account, and secure root account password in a safe place."
  level "Critical"
  id_map "object.user"
  objectives ["credential_report"]
  formulas ["CSV[user=<root_account>]"]
  audit_objects ["object.content.password_last_used"]
  operators [">"]
  alert_when ["15.days.ago"]
end

coreo_aws_advisor_alert "iam-user-attached-policies" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-user-attached-policies.html"
  display_name "Account using inline policies"
  description "User account is using custom inline policies versus using IAM group managed policies."
  category "Access"
  suggested_action "Switch all inline policies to apply to IAM groups and assign users IAMs roles."
  level "Warning"
  id_map "modifiers.user_name"
  objectives ["users", "user_policies"]
  formulas ["", "count"]
  call_modifiers [{}, { :user_name => "users.user_name" }]
  audit_objects ["", "object.policy_names"]
  operators ["", ">"]
  alert_when ["", 0]
end

coreo_aws_advisor_alert "iam-password-policy-uppercase" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-missing-password-policy.html"
  display_name "Password policy doesn't require an uppercase letter"
  description "The password policy must require an uppercase letter to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  level "Warning"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.require_uppercase_characters"]
  operators ["=="]
  alert_when [false]
end

coreo_aws_advisor_alert "iam-password-policy-lowercase" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-missing-password-policy.html"
  display_name "Password policy doesn't require an lowercase letter"
  description "The password policy must require an lowercase letter to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  level "Warning"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.require_lowercase_characters"]
  operators ["=="]
  alert_when [false]
end

coreo_aws_advisor_alert "iam-password-policy-symbol" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-missing-password-policy.html"
  display_name "Password policy doesn't require a symbol"
  description "The password policy must require a symbol to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  level "Warning"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.require_symbols"]
  operators ["=="]
  alert_when [false]
end

coreo_aws_advisor_alert "iam-password-policy-number" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-missing-password-policy.html"
  display_name "Password policy doesn't require a number"
  description "The password policy must require a number to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  level "Warning"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.require_numbers"]
  operators ["=="]
  alert_when [false]
end

coreo_aws_advisor_alert "iam-password-policy-min-length" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-missing-password-policy.html"
  display_name "Password policy doesn't require a minimum length of 14 characters"
  description "The password policy must require a minimum length of 14 characters to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  level "Warning"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.minimum_password_length"]
  operators ["<"]
  alert_when [14]
end

coreo_aws_advisor_alert "iam-root-access-key-1" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-root-active-password.html"
  display_name "Root Access Key Exists - Key #1"
  description "Root Access Key #1 exists. Ideally, the root account should not have any active keys."
  category "Security"
  suggested_action "Do not use Root Access Keys. Consider deleting the Root Access keys and using IAM users instead."
  level "Warning"
  id_map "object.user"
  objectives ["credential_report"]
  formulas ["CSV[user=<root_account>]"]
  audit_objects ["object.content.access_key_1_active"]
  operators ["=="]
  alert_when ["true"]
end

coreo_aws_advisor_alert "iam-root-access-key-2" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-root-active-password.html"
  display_name "Root Access Key Exists - Key #2"
  description "Root Access Key #2 exists. Ideally, the root account should not have any active keys."
  category "Security"
  suggested_action "Do not use Root Access Keys. Consider deleting the Root Access keys and using IAM users instead."
  level "Warning"
  id_map "object.user"
  objectives ["credential_report"]
  formulas ["CSV[user=<root_account>]"]
  audit_objects ["object.content.access_key_2_active"]
  operators ["=="]
  alert_when ["true"]
end

coreo_aws_advisor_iam "advise-iam" do
  action :advise
  alerts ${AUDIT_AWS_IAM_ALERT_LIST}
end

coreo_uni_util_jsrunner "jsrunner-process-suppression-iam" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_advisor_iam.advise-iam.report}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
  const fs = require('fs');
  const yaml = require('js-yaml');
  let suppression;
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
  }
  coreoExport('suppression', JSON.stringify(suppression));
  const violations = json_input.violations;
  const result = {};
  let file_date = null;
  const regionKeys = Object.keys(violations);
  regionKeys.forEach(region => {
      result[region] = {};
      const violationKeys = Object.keys(violations[region]);
      violationKeys.forEach(violator_id => {
          result[region][violator_id] = {};
          result[region][violator_id].tags = violations[region][violator_id].tags;
          result[region][violator_id].violations = {};
          const ruleKeys = Object.keys(violations[region][violator_id].violations);
          ruleKeys.forEach(rule_id => {
              let is_violation = true;
              result[region][violator_id].violations[rule_id] = violations[region][violator_id].violations[rule_id];
              const suppressionRuleKeys = Object.keys(suppression);
              suppressionRuleKeys.forEach(suppress_rule_id => {
                  const suppressionViolatorNum = Object.keys(suppression[suppress_rule_id]);
                  suppressionViolatorNum.forEach(suppress_violator_num => {
                      const suppressViolatorIdKeys = Object.keys(suppression[suppress_rule_id][suppress_violator_num]);
                      suppressViolatorIdKeys.forEach(suppress_violator_id => {
                          file_date = null;
                          let suppress_obj_id_time = suppression[suppress_rule_id][suppress_violator_num][suppress_violator_id];
                          if (rule_id === suppress_rule_id) {
  
                              if (violator_id === suppress_violator_id) {
                                  const now_date = new Date();
  
                                  if (suppress_obj_id_time === "") {
                                      suppress_obj_id_time = new Date();
                                  } else {
                                      file_date = suppress_obj_id_time;
                                      suppress_obj_id_time = file_date;
                                  }
                                  let rule_date = new Date(suppress_obj_id_time);
                                  if (isNaN(rule_date.getTime())) {
                                      rule_date = new Date(0);
                                  }
  
                                  if (now_date <= rule_date) {
  
                                      is_violation = false;
  
                                      result[region][violator_id].violations[rule_id]["suppressed"] = true;
                                      if (file_date != null) {
                                          result[region][violator_id].violations[rule_id]["suppressed_until"] = file_date;
                                          result[region][violator_id].violations[rule_id]["suppression_expired"] = false;
                                      }
                                  }
                              }
                          }
                      });
                  });
              });
              if (is_violation) {
  
                  if (file_date !== null) {
                      result[region][violator_id].violations[rule_id]["suppressed_until"] = file_date;
                      result[region][violator_id].violations[rule_id]["suppression_expired"] = true;
                  } else {
                      result[region][violator_id].violations[rule_id]["suppression_expired"] = false;
                  }
                  result[region][violator_id].violations[rule_id]["suppressed"] = false;
              }
          });
      });
  });
  
  callback(result);
  EOH
end

coreo_uni_util_notify "advise-jsrunner-file-suppressions-iam" do
  action :nothing
  type 'email'
  allow_empty true
  payload_type "text"
  payload 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression-iam.jsrunner_file'
  endpoint ({
      :to => '${AUDIT_AWS_IAM_ALERT_RECIPIENT}', :subject => 'jsrunner file for iam suppressions'
  })
end
 
coreo_uni_util_notify "advise-package-suppressions-iam" do
  action :nothing
  type 'email'
  allow_empty true
  payload_type "json"
  payload 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression-iam.packages_file'
  endpoint ({
      :to => '${AUDIT_AWS_IAM_ALERT_RECIPIENT}', :subject => 'package.json file for iam suppressions'
  })
end

coreo_uni_util_variables "iam-for-suppression-update-advisor-output" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_advisor_iam.advise-iam.report' => 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression-iam.return'}
            ])
end

coreo_uni_util_jsrunner "jsrunner-process-table-iam" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_advisor_iam.advise-iam.report}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
    var fs = require('fs');
    var yaml = require('js-yaml');
    try {
        var table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
    } catch (e) {
    }
    coreoExport('table', JSON.stringify(table));
    callback(table);
  EOH
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-iam" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.7.0"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "table": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-table-iam.return,
                "violations": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression-iam.return}'
  function <<-EOH
  
const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_IAM_ALERT_RECIPIENT}";
const OWNER_TAG = "NOT_A_TAG";
const ALLOW_EMPTY = "${AUDIT_AWS_IAM_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_IAM_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;

const VARIABLES = { NO_OWNER_EMAIL, OWNER_TAG,
     ALLOW_EMPTY, SEND_ON, SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditIAM = new CloudCoreoJSRunner(JSON_INPUT, VARIABLES);
const notifiers = AuditIAM.getNotifiers();
callback(notifiers);
  EOH
end

coreo_uni_util_notify "advise-jsrunner-file-html-iam" do
  action :nothing
  type 'email'
  allow_empty true
  payload_type "text"
  payload 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-iam.jsrunner_file'
  endpoint ({
      :to => '${AUDIT_AWS_IAM_ALERT_RECIPIENT}', :subject => 'jsrunner file for iam HTML'
  })
end
 
coreo_uni_util_notify "advise-package-html-iam" do
  action :nothing
  type 'email'
  allow_empty true
  payload_type "json"
  payload 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-iam.packages_file'
  endpoint ({
      :to => '${AUDIT_AWS_IAM_ALERT_RECIPIENT}', :subject => 'package.json file for iam HTML'
  })
end

coreo_uni_util_notify "advise-iam-html-report" do
  action :${AUDIT_AWS_IAM_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-iam.return'
end

