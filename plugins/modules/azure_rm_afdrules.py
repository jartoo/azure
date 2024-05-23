#!/usr/bin/python
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_afdrules
version_added: "0.1.0"
short_description: Manage an Azure Front Door Rules
description:
    - Create, update and delete an Azure Front Door Rules to be used by a Front Door Service Profile created using azure_rm_cdnprofile.

options:
    resource_group:
        description:
            - Name of a resource group where the CDN front door rules exists or will be created.
        required: true
        type: str
    name:
        description:
            - Name of the Front Door Rules.
        required: true
        type: str
    profile_name:
        description:
            - Name of the Front Door Profile.
        required: true
        type: str
    location:
        description:
            - Valid Azure location. Defaults to location of the resource group.
        required: true
        type: str
    state:
        description:
            - Assert the state of the CDN profile. Use C(present) to create or update a CDN profile and C(absent) to delete it.
        default: present
        type: str
        choices:
            - absent
            - present

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - Jarret Tooley (@jartoo)
'''

EXAMPLES = '''

'''
RETURN = '''
additional_latency_in_milliseconds:
    description: 
    returned: 
    type: int
    example:
deployment_status:
    description: 
    returned: 
    type: 
    example:
id:
    description: 
    returned: 
    type: str
    example:
name:
    description: 
    returned: 
    type: str
    example:
probe_interval_in_seconds:
    description: 
    returned: 
    type: int
    example:
probe_path:
    description: 
    returned: 
    type: str
    example:
probe_protocol:
    description: 
    returned: 
    type: str
    example:
probe_request_type:
    description: 
    returned: 
    type: str
    example:
provisioning_state:
    description: 
    returned: 
    type: str
    example:
sample_size:
    description: 
    returned: 
    type: int
    example:
session_affinity_state:
    description: 
    returned: 
    type: str
    example:
successful_samples_required:
    description: 
    returned: 
    type: int
    example:
traffic_restoration_time_to_healed_or_new_endpoints_in_minutes:
    description: 
    returned: 
    type: int
    example:
type:
    description: 
    returned: 
    type: str
    example:
'''
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from azure.mgmt.cdn.models import Rule, HeaderActionParameters, DeliveryRuleResponseHeaderAction, \
    DeliveryRuleResponseHeaderAction, RouteConfigurationOverrideActionParameters, \
    DeliveryRuleRouteConfigurationOverrideAction, UrlRedirectAction, UrlRewriteAction, \
    UrlSigningAction, OriginGroupOverride, ResourceReference, ForwardingProtocol, CacheConfiguration, \
    RuleQueryStringCachingBehavior, RuleIsCompressionEnabled, DeliveryRuleUrlPathCondition, \
    UrlPathMatchConditionParameters
    
    from azure.mgmt.cdn import CdnManagementClient
except ImportError as ec:
    # This is handled in azure_rm_common
    pass

def rules_to_dict(rules):
    return dict(
        deployment_status = rules.deployment_status,
        id = rules.id,
        match_processing_behavior=rules.match_processing_behavior,
        name = rules.name,
        order=rules.order,
        provisioning_state = rules.provisioning_state,
        type=rules.type
    )


class AzureRMRules(AzureRMModuleBase):

    def __init__(self):
        self.module_arg_spec = dict(
            name=dict(
                type='str',
                required=True
            ),
            rule_set_name=dict(
                type='str',
                required=True
            ),
            profile_name=dict(
                type='str',
                required=True
            ),
            resource_group=dict(
                type='str',
                required=True
            ),
            match_processing_behavior=dict(
                type='str',
                choices=['Continue', 'Stop'],
                required=True
            ),
            order=dict(
                type='int',
                required=True
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent'],
                required=False
            ),
            actions=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(type='str', required=False),
                    parameters=dict(
                        type='dict',
                        options=dict(
                            header_action=dict(type='str', required=False),
                            header_name=dict(type='str', required=False),
                            type_name=dict(type='str', required=False),
                            value=dict(type='str', required=False),
                        )
                    ),
                ),
                required=False
            ),
            conditions=dict(type='list', elements='dict', required=False)
        )

        self.resource_group = None
        self.name = None
        self.profile_name = None
        self.state = None

        self.rules_client = None

        required_if = [
            # ('state', 'present', ['host_name']) # TODO: Flesh these out
        ]

        self.results = dict(changed=False)

        super(AzureRMRules, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                supports_check_mode=True,
                                                supports_tags=False,
                                                required_if=required_if)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        self.rules_client = self.get_rules_client()

        response = self.get_rules()

        if self.state == 'present':

            if not response:
                self.log("Need to create the Rules")

                if not self.check_mode:
                    new_response = self.create_rules()
                    self.results['id'] = new_response['id']

                self.results['changed'] = True

            else:
                self.log('Results : {0}'.format(response))

        elif self.state == 'absent':
            if not response:
                self.fail("Rules {0} does not exist.".format(self.name))
            else:
                self.log("Need to delete the Rules")
                self.results['changed'] = True

                if not self.check_mode:
                    self.delete_rules()
                    self.results['id'] = response['id']

        return self.results

    def create_rules(self):
        '''
        Creates a Azure Rules.

        :return: deserialized Azure Rules instance state dictionary
        '''
        self.log("Creating the Azure Rules instance {0}".format(self.name))

        conditions = None
        if self.conditions:
            conditions = []
            for condition in self.conditions:
                if condition['name'] == 'UrlPath':
                    conditionrule = DeliveryRuleUrlPathCondition(
                        parameters=UrlPathMatchConditionParameters(
                            type_name=condition['parameters']['type_name'],
                            operator=condition['parameters']['operator'],
                            negate_condition=condition['parameters']['negate_condition'],
                            match_values=condition['parameters']['match_values'],
                            transforms=condition['parameters']['transforms']
                        )
                    )
                    # conditionrule = {
                    #     "additional_properties": {},
                    #     "name": condition['name'],
                    #     "parameters": condition['parameters']
                    # }
                    conditions.append(conditionrule)
        # Need to handle all of the following Action Types:
        # CACHE_EXPIRATION
        # CACHE_KEY_QUERY_STRING
        # MODIFY_REQUEST_HEADER
        # MODIFY_RESPONSE_HEADER
        # ORIGIN_GROUP_OVERRIDE
        # ROUTE_CONFIGURATION_OVERRIDE
        # URL_REDIRECT
        # URL_REWRITE
        # URL_SIGNING
        actions = None
        if self.actions:
            actions = []
            for action in self.actions:
                if action['name'] == 'ModifyResponseHeader':
                    actionrule = DeliveryRuleResponseHeaderAction(
                        parameters=HeaderActionParameters(
                            type_name=action['parameters']['type_name'],
                            header_action = action['parameters']['header_action'],
                            header_name = action['parameters']['header_name'],
                            value = action['parameters']['value']
                        )
                    )
                    # actionrule = {
                    #     "additional_properties": {},
                    #     "name": action['name'],
                    #     "parameters": {
                    #         "additional_properties": {},
                    #         "header_action": action['parameters']['header_action'],
                    #         "header_name": action['parameters']['header_name'],
                    #         "value": action['parameters']['value']
                    #     }
                    # }
                    actions.append(actionrule)
                if action['name'] == 'RouteConfigurationOverride':
                    origin_group_override = None
                    if 'origin_group_id' in action['parameters'].keys():
                        origin_group_override = OriginGroupOverride(
                            origin_group=ResourceReference(
                                id=action['parameters']['origin_group_id']
                            ),
                            forwarding_protocol=ForwardingProtocol(
                                action['parameters']['forwarding_protocol']
                            )
                        )
                    cache_configuration = None
                    if 'query_string_caching_behavior' in action['parameters'].keys():
                        cache_configuration=CacheConfiguration(
                            query_string_caching_behavior=action['parameters']['query_string_caching_behavior'],
                            query_parameters=action['parameters']['query_parameters'],
                            is_compression_enabled=action['parameters']['is_compression_enabled'],
                            cache_behavior=action['parameters']['cache_behavior'],
                            cache_duration=action['parameters']['cache_duration']
                        )
                    actionrule = DeliveryRuleRouteConfigurationOverrideAction(
                        parameters=RouteConfigurationOverrideActionParameters(
                            type_name = "DeliveryRuleRouteConfigurationOverrideActionParameters",
                            origin_group_override=origin_group_override,
                            cache_configuration=cache_configuration
                        )
                    )
                    # actionrule = {
                    #     "additional_properties": {},
                    #     "name": action['name'],
                    #     "parameters": {
                    #         "additional_properties": {},
                    #         "type_name": action['parameters']['type_name'] # TODO: Add origin_group_override and cache_configuration https://learn.microsoft.com/en-us/python/api/azure-mgmt-cdn/azure.mgmt.cdn.models.routeconfigurationoverrideactionparameters?view=azure-python
                    #     }
                    # }
                    actions.append(actionrule)

        parameters = Rule(
            order=self.order,
            conditions=conditions,
            actions=actions,
            match_processing_behavior=self.match_processing_behavior
        )
        # parameters = {
        #     "additional_properties": {},
        #     "id": None,
        #     "name": self.name,
        #     "type": None,
        #     "order": self.order,
        #     "conditions": conditions,
        #     "actions": actions,
        #     "match_processing_behavior": self.match_processing_behavior,
        #     "provisioning_state": None,
        #     "deployment_status": None
        # }

        print(parameters)
        try:
            poller = self.rules_client.rules.begin_create(
                resource_group_name=self.resource_group,
                profile_name=self.profile_name,
                rule_set_name=self.rule_set_name,
                rule_name=self.name,
                rule=parameters
            )
            response = self.get_poller_result(poller)
            return rules_to_dict(response)
        except Exception as exc:
            self.log('Error attempting to create Azure Rules instance.')
            self.fail("Error Creating Azure Rules instance: {0}".format(exc.message))

    def delete_rules(self):
        '''
        Deletes the specified Azure Rules in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the Rules {0}".format(self.name))
        try:
            poller = self.rules_client.rule_sets.begin_delete(resource_group_name=self.resource_group, profile_name=self.profile_name, rule_set_name=self.name)
            self.get_poller_result(poller)
            return True
        except Exception as e:
            self.log('Error attempting to delete the Rules.')
            self.fail("Error deleting the Rules: {0}".format(e.message))
            return False

    def get_rules(self):
        '''
        Gets the properties of the specified Rules.

        :return: deserialized Rules state dictionary
        '''
        self.log(
            "Checking if the Rules {0} is present".format(self.name))
        try:
            response = self.rules_client.rules.get(
                resource_group_name=self.resource_group,
                profile_name=self.profile_name,
                rule_set_name=self.rule_set_name,
                rule_name=self.name
            )
            self.log("Response : {0}".format(response))
            self.log("Rules : {0} found".format(response.name))
            return rules_to_dict(response)
        except Exception as err:
            self.log('Did not find the Rules.' + err.args[0])
            return False

    def get_rules_client(self):
        if not self.rules_client:
            self.rules_client = self.get_mgmt_svc_client(CdnManagementClient,
                                                       base_url=self._cloud_environment.endpoints.resource_manager,
                                                       api_version='2023-05-01')
        return self.rules_client


def main():
    """Main execution"""
    AzureRMRules()
    # x = CdnManagementClient()
    # x.rules.begin_create()
    # y = AFDRules()

if __name__ == '__main__':
    main()
