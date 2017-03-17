coreo_aws_rule "iam-unused-access" do
  action :define
  service :iam
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
  

const alertArrayJSON = "['iam-unused-access']";
const alertArray = JSON.parse(alertArrayJSON.replace(/'/g, '"'));

const newJSONInput = json_input
const users = newJSONInput['violations']['us-east-1'];

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

  for (var user in users) {
      var keyOneDate = new Date(users[user]['violator_info']['access_key_1_active']);
      var keyTwoDate = new Date(users[user]['violator_info']['access_key_2_active']);
      var passwordUsedDate = new Date(users[user]['violator_info']['password_last_used']);
      const ninetyDaysAgo = (new Date()) - 1000 * 60 * 60 * 24 * 90

      const keyOneUnused = keyOneDate < ninetyDaysAgo
      const keyOneEnabled = users[user]['violator_info']['access_key_1_active'] == "true"
      const keyTwoUnused = keyTwoDate < ninetyDaysAgo
      const keyTwoEnabled = users[user]['violator_info']['access_key_2_active'] == "true"
      const passwordUnused = passwordUsedDate < ninetyDaysAgo
      const passwordEnabled = users[user]['violator_info']['password_enabled'] == "true"

      if (keyOneUnused && keyOneEnabled){
          newJSONInput['violations']['us-east-1'][user]['violations']['iam-unused-access'] = unusedCredsMetadata
      }
      else if (keyTwoEnabled && keyTwoUnused){
          newJSONInput['violations']['us-east-1'][user]['violations']['iam-unused-access'] = unusedCredsMetadata
      }
      else if (passwordEnabled && passwordUnused){
          newJSONInput['violations']['us-east-1'][user]['violations']['iam-unused-access'] = unusedCredsMetadata;
      }
  }
}

setValueForNewJSONInput()

const violations = newJSONInput['violations'];

coreoExport('JSONReport', JSON.stringify(newJSONInput));
coreoExport('report', JSON.stringify(violations));

callback(violations);
  EOH
end

coreo_uni_util_variables "iam-update-planwide-2.5" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-iam.JSONReport'},
                {'COMPOSITE::coreo_aws_rule_runner.advise-iam.report' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-iam.report'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-iam.table'}
            ])
end

coreo_uni_util_notify "advise-iam-to-tag-values" do
  action((("${AUDIT_AWS_IAM_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.ian-iam.return'
end

coreo_uni_util_notify "advise-iam-rollup" do
  action((("${AUDIT_AWS_IAM_ALERT_RECIPIENT}".length > 0) and (!"NOT_A_TAG".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_IAM_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_IAM_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.iam-tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_IAM_ALERT_RECIPIENT}', :subject => 'PLAN::stack_name New Rollup Report for PLAN::name plan from CloudCoreo'
  })
end
