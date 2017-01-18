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
  id_map "object.roles.role_id"
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
  id_map "object.policies.policy_id"
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
  id_map "object.access_key_metadata.access_key_id"
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
  audit_objects ["object.password_policy"]
  formulas ["include?(password_reuse_prevention)"]
  operators ["!="]
  alert_when [true]
  id_map "static.password_policy"
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

# =begin
#   START AWS IAM METHODS
#   JSON SEND METHOD
#   HTML SEND METHOD
# =end

coreo_uni_util_notify "advise-iam-json" do
  action :nothing
  type 'email'
  allow_empty ${AUDIT_AWS_IAM_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_IAM_SEND_ON}'
  payload '{"composite name":"PLAN::stack_name",
  "plan name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_advisor_iam.advise-iam.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_advisor_iam.advise-iam.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_iam.advise-iam.number_ignored_violations",
  "violations": COMPOSITE::coreo_aws_advisor_iam.advise-iam.report }'
  payload_type "json"
  endpoint ({
      :to => '${AUDIT_AWS_IAM_ALERT_RECIPIENT}', :subject => 'CloudCoreo iam advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-iam" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.3.9"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "violations": COMPOSITE::coreo_aws_advisor_iam.advise-iam.report}'
  function <<-EOH
  
const JSON = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_IAM_ALERT_RECIPIENT}";
const OWNER_TAG = "NOT_A_TAG";
const ALLOW_EMPTY = "${AUDIT_AWS_IAM_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_IAM_SEND_ON}";
const AUDIT_NAME = 'iam';

const ARE_KILL_SCRIPTS_SHOWN = false;
const EC2_LOGIC = ''; // you can choose 'and' or 'or';
const EXPECTED_TAGS = ['example_2', 'example_1'];

const WHAT_NEED_TO_SHOWN = {
    OBJECT_ID: {
        headerName: 'AWS Object ID',
        isShown: true,
    },
    REGION: {
        headerName: 'Region',
        isShown: false,
    },
    AWS_CONSOLE: {
        headerName: 'AWS Console',
        isShown: true,
    },
    TAGS: {
        headerName: 'Tags',
        isShown: false,
    },
    AMI: {
        headerName: 'AMI',
        isShown: false,
    },
    KILL_SCRIPTS: {
        headerName: 'Kill Cmd',
        isShown: false,
    }
};


const VARIABLES = {
    NO_OWNER_EMAIL,
    OWNER_TAG,
    AUDIT_NAME,
    ARE_KILL_SCRIPTS_SHOWN,
    EC2_LOGIC,
    EXPECTED_TAGS,
    WHAT_NEED_TO_SHOWN,
    ALLOW_EMPTY,
    SEND_ON
};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditIAM = new CloudCoreoJSRunner(JSON, VARIABLES);
const notifiers = AuditIAM.getNotifiers();
callback(notifiers);
  EOH
end

coreo_uni_util_jsrunner "tags-rollup-iam" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-iam.return'
  function <<-EOH
var rollup_string = "";
let rollup = '';
let emailText = '';
let numberOfViolations = 0;
for (var entry=0; entry < json_input.length; entry++) {
    if (json_input[entry]['endpoint']['to'].length) {
        numberOfViolations += parseInt(json_input[entry]['num_violations']);
        emailText += "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "nViolations: " + json_input[entry]['num_violations'] + "\\n";
    }
}

rollup += 'number of Violations: ' + numberOfViolations + "\\n";
rollup += 'Rollup' + "\\n";
rollup += emailText;

rollup_string = rollup;
callback(rollup_string);
  EOH
end

coreo_uni_util_notify "advise-iam-html-report" do
  action :${AUDIT_AWS_IAM_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-iam.return'
end

coreo_uni_util_notify "advise-iam-rollup" do
  action :${AUDIT_AWS_IAM_ROLLUP_REPORT}
  type 'email'
  allow_empty true
  send_on '${AUDIT_AWS_IAM_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup-iam.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_IAM_ALERT_RECIPIENT}', :subject => 'CloudCoreo iam advisor alerts on PLAN::stack_name :: PLAN::name' # CANT UNCOMMENT
  })
end
=begin
  AWS IAM END
=end
