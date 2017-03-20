coreo_aws_rule "iam-unused-access" do
  action :define
  service :iam
  include_violations_in_count false   
  display_name "IAM Root User Activity"
  description "This rule performs an inventory on all users using credential report"
  category "Inventory"
  suggested_action "User credentials that have not been used in 90 days should be removed or deactivated"
  level "Informational"
  meta_cis_id "1.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  id_map "object.content.user"
  objectives ["credential_report"]
  audit_objects ["object.content.user"]
  operators ["=~"]
  raise_when [//]
end

coreo_aws_rule "iam-root-access_key" do
  action :define
  service :iam
  include_violations_in_count false   
  display_name "IAM Root Access Key"
  description "This rule checks for root access keys. Root account should not have access keys enabled"
  category "Inventory"
  suggested_action "Deactivate root access keys"
  level "Informational"
  meta_cis_id "1.12"
  meta_cis_scored "true"
  meta_cis_level "1"
  id_map "object.content.user"
  objectives ["credential_report"]
  audit_objects ["object.content.user"]
  operators ["=="]
  raise_when ["<root_account>"]
end

coreo_aws_rule "iam-root-no-mfa-cis" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_iam-root-no-mfa.html"
  display_name "Multi-Factor Authentication not enabled for root account"
  description "Root cloud user does not have Multi-Factor Authentication enabled on their cloud account"
  category "Security"
  suggested_action "Enable Multi-Factor Authentication for the root cloud user."
  level "Emergency"
  meta_cis_id "1.13"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives ["account_summary"]
  audit_objects ['object.summary_map']
  operators ["!="]
  raise_when [nil]
end

coreo_aws_rule "iam-initialization-access-key" do
  action :define
  service :user
  include_violations_in_count false
  display_name "IAM Root Access Key"
  description "This rule checks for root access keys. Root account should not have access keys enabled"
  category "Inventory"
  suggested_action "Deactivate root access keys"
  level "Internal"
  meta_cis_id "1.23"
  meta_cis_scored "false"
  meta_cis_level "1"
  id_map ""
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
end


coreo_uni_util_variables "iam-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'unset'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.number_violations' => 'unset'}
            ])
end


coreo_aws_rule_runner "advise-iam" do
  service :iam
  action :run
  rules ${AUDIT_AWS_IAM_ALERT_LIST}
end


coreo_uni_util_variables "iam-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner.advise-iam.report'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.number_violations' => 'COMPOSITE::coreo_aws_rule_runner.advise-iam.number_violations'},

            ])
end

coreo_uni_util_jsrunner "ian-iam" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.9.2"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "cloud account name": "PLAN::cloud_account_name",
                "violations":COMPOSITE::coreo_aws_rule_runner.advise-iam.report}'
  function <<-EOH
  
function copyPropForNewJsonInput() {
    newJSONInput['composite name'] = json_input['composite name'];
    newJSONInput['cloud account name'] = json_input['cloud account name'];
    // newJSONInput['number_of_violations'] = violationCounter;
    return newJSONInput;
}

const alertArrayJSON = "['iam-unused-access', 'iam-root-access_key', 'iam-root-no-mfa-cis', 'iam-initialization-access-key']";
const alertArray = JSON.parse(alertArrayJSON.replace(/'/g, '"'));
const newJSONInput = {}
newJSONinput = copyPropForNewJsonInput();
newJSONInput['violations'] = {}
newJSONInput['violations']['us-east-1'] = {}
const users = json_input['violations']['us-east-1'];

function setValueForNewJSONInput() {

  const unusedCredsMetadata = {
        'service': 'iam',
        'display_name': 'IAM Unused credentials',
        'description': 'Checks for unused credentials',
        'category': 'Audit',
        'suggested_action': 'User credentials that have not been used in 90 days should be removed or deactivated',
        'level': 'Warning',
        'meta_cis_id': '1.3',
        'meta_cis_scored': 'true',
        'meta_cis_level': '1'
  };

    const rootMFAMetadata = {
        'service': 'iam',
        'display_name': 'Root MFA disabled',
        'description': 'Checks root MFA status',
        'category': 'Audit',
        'suggested_action': 'Root MFA should be enabled',
        'level': 'Warning',
        'meta_cis_id': '1.13',
        'meta_cis_scored': 'true',
        'meta_cis_level': '1'
    };

    const rootAccessMetadata = {
        'service': 'iam',
        'display_name': 'IAM Root Access Key',
        'description': 'IAM Root Access Key',
        'category': 'Audit',
        'suggested_action': 'IAM Root Access Key',
        'level': 'Warning',
        'meta_cis_id': '1.12',
        'meta_cis_scored': 'true',
        'meta_cis_level': '1'
    };

    const initAccessMetadata = {
        'service': 'iam',
        'display_name': 'IAM Init Access',
        'description': 'IAM Init Access Key',
        'category': 'Audit',
        'suggested_action': 'IAM Init Access Key',
        'level': 'Warning',
        'meta_cis_id': '1.23',
        'meta_cis_scored': 'false',
        'meta_cis_level': '1'
    };

    //if cis 1.3 wanted, the below will run
    if  (alertArray.indexOf('iam-unused-access') > -1) {
        for (var user in users) {
            var keyOneDate = new Date(users[user]['violator_info']['access_key_1_last_used_date']);
            var keyTwoDate = new Date(users[user]['violator_info']['access_key_2_last_used_date']);
            var passwordUsedDate = new Date(users[user]['violator_info']['password_last_used']);
            const ninetyDaysAgo = (new Date()) - 1000 * 60 * 60 * 24 * 90

            const keyOneUnused = keyOneDate < ninetyDaysAgo
            const keyOneEnabled = users[user]['violator_info']['access_key_1_active'] == "true"
            const keyTwoUnused = keyTwoDate < ninetyDaysAgo
            const keyTwoEnabled = users[user]['violator_info']['access_key_2_active'] == "true"
            const passwordUnused = passwordUsedDate < ninetyDaysAgo
            const passwordEnabled = users[user]['violator_info']['password_enabled'] == "true"

            if ((keyOneUnused && keyOneEnabled) || (keyTwoEnabled && keyTwoUnused) || (passwordEnabled && passwordUnused)) {

                if (!newJSONInput['violations']['us-east-1'][user]) {
                    newJSONInput['violations']['us-east-1'][user] = {}
                }
                ;
                if (!newJSONInput['violations']['us-east-1'][user]['violations']) {
                    newJSONInput['violations']['us-east-1'][user]['violations'] = {}
                }
                ;

                newJSONInput['violations']['us-east-1'][user]['violations']['iam-unused-access'] = unusedCredsMetadata

            }
        }
    }

    //if cis 1.12 wanted, the below will run
    if  (alertArray.indexOf('iam-root-access-key') > -1) {
        const keyOneEnabled = users["<root_account>"]['violator_info']['access_key_1_active'] == "false"
        const keyTwoEnabled = users["<root_account>"]['violator_info']['access_key_2_active'] == "false"

        if ((keyOneEnabled || keyTwoEnabled)) {

            if (!newJSONInput['violations']['us-east-1']["<root_account>"]) {
                newJSONInput['violations']['us-east-1']["<root_account>"] = {}
            }
            ;
            if (!newJSONInput['violations']['us-east-1']["<root_account>"]['violations']) {
                newJSONInput['violations']['us-east-1']["<root_account>"]['violations'] = {}
            }
            ;

            newJSONInput['violations']['us-east-1']["<root_account>"]['violations']['iam-root-access_key'] = rootAccessMetadata

        }
    }

    //if cis 1.13 wanted, the below will run
    if  (alertArray.indexOf('iam-root-no-mfa-cis') > -1) {
        if (users["<root_account>"]['violator_info']['mfa_active'] == "false"){

            if (!newJSONInput['violations']['us-east-1']["<root_account>"]) {
                newJSONInput['violations']['us-east-1']["<root_account>"] = {}
            }
            ;
            if (!newJSONInput['violations']['us-east-1']["<root_account>"]['violations']) {
                newJSONInput['violations']['us-east-1']["<root_account>"]['violations'] = {}
            }
            ;
            newJSONInput['violations']['us-east-1']["<root_account>"]['violations']['iam-root-no-mfa-cis'] = rootMFAMetadata
        }
    }


    //if cis 1.23 wanted, the below will run
    if  (alertArray.indexOf('iam-initialization-access-key') > -1) {
        for (var user in users) {
            var keyOneDate = users[user]['violator_info']['access_key_1_last_used_date'] == "N/A";
            var keyTwoDate = users[user]['violator_info']['access_key_2_last_used_date'] == "N/A";
            var keyOneEnabled = users[user]['violator_info']['access_key_1_active'] == "true";
            var keyTwoEnabled = users[user]['violator_info']['access_key_2_active'] == "true";

            if ((keyOneDate && keyOneEnabled) || (keyTwoDate && keyTwoEnabled)) {

                if (!newJSONInput['violations']['us-east-1'][user]) {
                    newJSONInput['violations']['us-east-1'][user] = {}
                }
                ;
                if (!newJSONInput['violations']['us-east-1'][user]['violations']) {
                    newJSONInput['violations']['us-east-1'][user]['violations'] = {}
                }
                ;
                newJSONInput['violations']['us-east-1'][user]['violations']['iam-initialization-access-key'] = initAccessMetadata
            }
        }
    }

}

setValueForNewJSONInput()

const violations = newJSONinput['violations'];
const report = JSON.stringify(violations)

coreoExport('JSONReport', JSON.stringify(newJSONInput));
coreoExport('report', report);

callback(violations);
  EOH
end

coreo_uni_util_variables "iam-update-planwide-2.5" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.ian-iam.JSONReport'},
                {'COMPOSITE::coreo_aws_rule_runner.advise-iam.report' => 'COMPOSITE::coreo_uni_util_jsrunner.ian-iam.report'},
            ])
end

// coreo_uni_util_notify "advise-iam-to-tag-values" do
//   action((("${AUDIT_AWS_IAM_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
//   notifiers 'COMPOSITE::coreo_uni_util_jsrunner.ian-iam.return'
// end

coreo_uni_util_notify "advise-iam-rollup" do
  action((("${AUDIT_AWS_IAM_ALERT_RECIPIENT}".length > 0) and (!"NOT_A_TAG".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_IAM_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_IAM_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.ian-iam.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_IAM_ALERT_RECIPIENT}', :subject => 'PLAN::stack_name New Rollup Report for PLAN::name plan from CloudCoreo'
  })
end
