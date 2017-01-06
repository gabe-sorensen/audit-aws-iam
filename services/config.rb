
#‘aws object id’ title should be ‘group name’
# modify_column [ "aws_object_id", "Group Name"]
# https://cloudcoreo.atlassian.net/browse/PLA-2348
#including the group arn would be helpful
#   e.g. Group ARN: arn:aws:iam::530342348278:group/unusedgrouptest
# add_column [ "///group_arn", "Group ARN" ]
# https://cloudcoreo.atlassian.net/browse/PLA-2349
# PROBLEM - the AWS json return is not part of the advisor output for this advisor
# https://cloudcoreo.atlassian.net/browse/PLA-2350

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
end

# need to include the username, key created date in the list of violations
# these are in the json return structure
#
#access_key_id : AKIAI4FYSVOKIXN3YYZA
#user_name : andrew
#create_date : 2016-09-08T23:22:50Z
#status  : Active
#add_html_column [ "/user_name", "User Name" ] # key name, relative path from "object", display name
#    e.g. Users: andrew, 
#    creation date for key: 2016-09-09 05:22 UTC+0600
# what is the value in the ‘aws object id’?  Not sure this is useful
#  - its the access key ID for that user
# tags, owner email, region - these fields are not applicable for IAM
# https://cloudcoreo.atlassian.net/browse/CON-167
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
  alert_when ["", "Inactive", "90.days.ago"]
end

# same as last
coreo_aws_advisor_alert "iam-active-key-no-rotation" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-active-key-no-rotation.html"
  display_name "Active user Access Key not rotated"
  description "User has active keys that have not been rotated in the last 90 days"
  category "Access"
  suggested_action "If you regularly use the AWS access keys, we recommend that you also regularly rotate or delete them."
  level "Alert"
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
end

# the link does not take me to the policy
# https://cloudcoreo.atlassian.net/browse/CON-168

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
end

# the link does not take me to the policy
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
end

# ‘aws object id’ title should be ‘user name’
# also, I think if console password is ‘disabled’ then this violation should not be flagged.  
#   Ie, this user does not log into the console and therefore MFA is N/A (GEORGE - probably jsrunner?)
# https://cloudcoreo.atlassian.net/browse/CON-172
coreo_aws_advisor_alert "iam-no-mfa" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-no-mfa.html"
  display_name "Multi-Factor Authentication not enabled"
  description "Cloud user does not have Multi-Factor Authentication enabled on their cloud account."
  category "Security"
  suggested_action "Enable Multi-Factor Authentication for every cloud user."
  level "Critical"
  id_map "object.modifiers.user_name"
  objectives ["users", "mfa_devices", "credential_report"]
  formulas ["", "count", "CSV[user=andrew]"]
  call_modifiers [{}, { :user_name => "users.user_name" }, {}]
  audit_objects ["", "object.mfa_devices", "object.content.password_enabled"]
  operators ["", "<", "=="]
  alert_when ["", 1, "false"]


  # objectives ["credential_report"]
  # formulas ["CSV[user=<root_account>]"]
  # audit_objects ["object.content.access_key_1_active"]
  # operators ["=="]
  # alert_when ["true"]
end

# the link does not take me to the policy
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

#the link does not take me to the policy
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

# the link does not take me to the policy
# need to include violation field (i.e. policies attached inline &  group) GEORGE ???
# PROBLEM - the json return does not include anything in the violating_object
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

coreo_aws_advisor_iam "advise-iam" do
  action :advise
  alerts ${AUDIT_AWS_IAM_ALERT_LIST}
end

=begin
  START AWS IAM METHODS
  JSON SEND METHOD
  HTML SEND METHOD
=end
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
                   :version => "1.3.2"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "number_of_checks":"COMPOSITE::coreo_aws_advisor_iam.advise-iam.number_checks",
                "number_of_violations":"COMPOSITE::coreo_aws_advisor_iam.advise-iam.number_violations",
                "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_iam.advise-iam.number_ignored_violations",
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
number_of_checks: COMPOSITE::coreo_aws_advisor_iam.advise-iam.number_checks
number_violations_ignored: COMPOSITE::coreo_aws_advisor_iam.advise-iam.number_ignored_violations
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
