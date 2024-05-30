#!/usr/bin/python
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# Python SDK Reference: https://learn.microsoft.com/en-us/python/api/azure-mgmt-cdn/azure.mgmt.cdn.operations.policiesoperations?view=azure-python
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_wafpolicy
version_added: "0.1.0"
short_description: Manage an Azure Front Door WAF Policy
description:
    - Create, update and delete an Azure Front Door WAF Policy to be used by a Front Door Service Profile created using azure_rm_cdnprofile.

options:
    resource_group:
        description:
            - Name of a resource group where the WAF Policy exists or will be created.
        required: true
        type: str
    name:
        description:
            - Name of the Front Door WAF Policy.
        required: true
        type: str
    profile_name:
        description:
            - Name of the Azure Front Door Profile.
        required: true
        type: str
    location:
        description:
            - Valid Azure location. Defaults to location of the resource group.
        required: true
        type: str
    sku:
        description:
            - The pricing tier (defines a CDN provider, feature list and rate) of the Policy.
        required: true
        type: str
    tags:
        description:
            - Valid Azure location. Defaults to location of the resource group.
        type: list
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
id:
    description: 
    returned: 
    type: str
    example:
'''
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from azure.mgmt.cdn.models import CdnWebApplicationFirewallPolicy, PolicySettings, RateLimitRuleList, RateLimitRule, CustomRuleList, ManagedRuleSetList
    from azure.mgmt.cdn import CdnManagementClient

except ImportError as ec:
    # This is handled in azure_rm_common
    pass

def wafpolicy_to_dict(wafpolicy):
    return dict(
        deployment_status=wafpolicy.deployment_status,
        enabled_state = wafpolicy.enabled_state,
        forwarding_protocol = wafpolicy.forwarding_protocol,
        https_redirect = wafpolicy.https_redirect,
        id = wafpolicy.id,
        link_to_default_domain = wafpolicy.link_to_default_domain,
        name=wafpolicy.name,
        origin_group_id=wafpolicy.origin_group.id,
        origin_path=wafpolicy.origin_path,
        patterns_to_match=wafpolicy.patterns_to_match,
        provisioning_state=wafpolicy.provisioning_state,
        query_string_caching_behavior=wafpolicy.query_string_caching_behavior,
        rule_sets=wafpolicy.rule_sets,
        supported_protocols=wafpolicy.supported_protocols,
        type=wafpolicy.type
    )

class AzureRMWAFPolicy(AzureRMModuleBase):

    def __init__(self):
        self.module_arg_spec = dict(
            custom_rules=dict(
                type='dict',
                options=dict(
                    rules=dict(
                        type='list',
                        options=dict(
                            name=dict(type='str'),
                            enabled_state=dict(type='str',choices=['Enabled', 'Disabled']),
                            priority=dict(type='int'),
                            match_conditions=dict(
                                type='list',
                                options=dict(
                                    match_variable=dict(type='str',choices=["RemoteAddr", "SocketAddr", "RequestMethod", "RequestHeader", "RequestUri", "QueryString", "RequestBody", "Cookies", "PostArgs"]),
                                    selector=dict(type='str'),
                                    operator=dict(type='str', choices=["Any", "IPMatch", "GeoMatch", "Equal", "Contains", "LessThan", "GreaterThan", "LessThanOrEqual", "GreaterThanOrEqual", "BeginsWith", "EndsWith", "RegEx"]),
                                    negate_condition=dict(type='bool'),
                                    match_value=dict(type='list'),
                                    transforms=dict(type='list')
                                )
                            ),
                            action=dict(type='str', choices=["Allow", "Block", "Log", "Redirect"])
                        )
                    )
                )
            ),
            location=dict(
                type='str',
                required=True
            ),
            managed_rules=dict(
                type='dict',
                options=dict(
                    managed_rule_sets=dict(
                        type='list',
                        options=dict(
                            rule_set_type=dict(type='str'),
                            rule_set_version=dict(type='str'),
                            anomaly_score=dict(type='int'),
                            rule_group_overrides=dict(
                                type='list',
                                options=dict(
                                    rule_group_name=dict(type='str'),
                                    rules=dict(
                                        type='list',
                                        options=dict(
                                            rule_id=dict(type='int'),
                                            enabled_state=dict(type='str', choices=["Enabled, Disabled"]),
                                            action=dict(type='str', choices=["Allow", "Block", "Log", "Redirect"])
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            name=dict(
                type='str',
                required=True
            ),
            policy_settings=dict(
                type='dict',
                options=dict(
                    enabled_state=dict(type='str',choices=['Enabled','Disabled']),
                    mode=dict(type='str',choices=['Detection','Prevention']),
                    default_redirect_url=dict(type='str'),
                    default_custom_block_response_status_code=dict(type='int',choices=[200,403,405,406,429]),
                    default_custom_block_response_body=dict(type='str')
                )
            ),
            rate_limit_rules=dict(
                type='list',
                elements='dict',
                options=dict(
                    rules=dict(
                        type='list',
                        options=dict(
                            name=dict(type='str'),
                            enabled_state=dict(type='str',choices=['Enabled', 'Disabled']),
                            priority=dict(type='int'),
                            match_conditions=dict(
                                type='list',
                                options=dict(
                                    match_variable=dict(type='str',choices=["RemoteAddr", "SocketAddr", "RequestMethod", "RequestHeader", "RequestUri", "QueryString", "RequestBody", "Cookies", "PostArgs"]),
                                    selector=dict(type='str'),
                                    operator=dict(type='str', choices=["Any", "IPMatch", "GeoMatch", "Equal", "Contains", "LessThan", "GreaterThan", "LessThanOrEqual", "GreaterThanOrEqual", "BeginsWith", "EndsWith", "RegEx"]),
                                    negate_condition=dict(type='bool'),
                                    match_value=dict(type='list'),
                                    transforms=dict(type='list')
                                )
                            ),
                            action=dict(type='str', choices=["Allow", "Block", "Log", "Redirect"]),
                            rate_limit_threshold=dict(type='int'),
                            rate_limit_duration_in_minutes=dict(type='int')
                        )
                    )
                )
            ),
            resource_group=dict(
                type='str',
                required=True
            ),
            resource_state=dict(
                type='str',
                choices=["Enabled", "Disabled"]
            ),
            sku=dict(
                type='str',
                required=True,
                choices=[
                    'Standard_AzureFrontDoor',
                    'Premium_AzureFrontDoor'
                ]
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent'],
                required=False
            )
        )

        self.custom_rules = None
        self.location = None
        self.managed_rules = None
        self.policy_settings = None
        self.resource_state = None
        self.rate_limit_rules = None
        self.sku = None

        self.name = None
        self.origin_group_name = None
        self.profile_name = None
        self.resource_group = None
        self.state = None

        self.wafpolicy_client = None

        self.results = dict(changed=False)

        super(AzureRMWAFPolicy, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                supports_check_mode=True,
                                                supports_tags=True)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        self.wafpolicy_client = self.get_wafpolicy_client()

        to_be_updated = False

        # Get the existing resource
        response = self.get_wafpolicy()

        if self.state == 'present':

            if not response:
                self.log("Need to create the WAF Policy")

                if not self.check_mode:
                    new_results = self.create_wafpolicy()
                    self.results['id'] = new_results['id']
                self.results['changed'] = True

            else:
                self.log('Results : {0}'.format(response))
                
                if response['enabled_state'] != self.enabled_state and self.enabled_state:
                    to_be_updated = True

                if to_be_updated:
                    self.log("Need to update the WAF Policy")

                    if not self.check_mode:
                        new_results = self.update_wafpolicy()
                        self.results['id'] = new_results['id']

                    self.results['changed'] = True

        elif self.state == 'absent':
            if not response:
                self.log("WAF Policy {0} does not exist.".format(self.name))
                self.results['changed'] = False
            else:
                self.log("Need to delete the WAF Policy")
                self.results['changed'] = True

                if not self.check_mode:
                    self.delete_wafpolicy()
                    self.results['id'] = response['id']

        return self.results

    def create_wafpolicy(self):
        '''
        Creates a Azure WAF Policy.

        :return: deserialized Azure WAF Policy instance state dictionary
        '''
        self.log("Creating the Azure WAF Policy instance {0}".format(self.name))
        policy_settings = PolicySettings(
            enabled_state=self.policy_settings['enabled_state'],
            mode=self.policy_settings['mode'],
            default_redirect_url=self.policy_settings['default_redirect_url'],
            default_custom_block_response_status_code=self.policy_settings['default_custom_block_response_status_code'],
            default_custom_block_response_body=self.policy_settings['default_custom_block_response_body']
        )

        rules = []
        for rule in self.rate_limit_rules:
            single_rule = RateLimitRule(
                name=rule.name, # str
                priority=rule.priority, # int
                match_conditions='' # List[MatchCondition]
                # action: str | ActionType, 
                # rate_limit_threshold: int, 
                # rate_limit_duration_in_minutes: int, 
                # enabled_state: str | CustomRuleEnabledState
            )
            rules.append(single_rule)
        rate_limit_rules = RateLimitRuleList(
            rules=rules
        )

        rules = []
        for rule in self.custom_rules:
            single_rule = RateLimitRule(
                name=rule.name, # str
                priority=rule.priority, # int
                match_conditions='' # List[MatchCondition]
                # action: str | ActionType, 
                # rate_limit_threshold: int, 
                # rate_limit_duration_in_minutes: int, 
                # enabled_state: str | CustomRuleEnabledState
            )
            rules.append(single_rule)
        custom_rules = CustomRuleList(
            rules=rules
        )

        rules = []
        for rule in self.managed_rules:
            single_rule = RateLimitRule(
                name=rule.name, # str
                priority=rule.priority, # int
                match_conditions='' # List[MatchCondition]
                # action: str | ActionType, 
                # rate_limit_threshold: int, 
                # rate_limit_duration_in_minutes: int, 
                # enabled_state: str | CustomRuleEnabledState
            )
            rules.append(single_rule)
        managed_rules =  ManagedRuleSetList(
            rules=rules
        )

        extended_properties = {}
        
        parameters = CdnWebApplicationFirewallPolicy(
            location=self.location,
            sku=self.sku,
            tags=self.tags,
            policy_settings=policy_settings,
            rate_limit_rules=rate_limit_rules, 
            custom_rules=custom_rules,
            managed_rules=managed_rules,
            extended_properties=extended_properties
        )
        
        try:
            poller = self.wafpolicy_client.policies.begin_create_or_update(
                resource_group_name=self.resource_group_name,
                policy_name=self.name,
                cdn_web_application_firewall_policy=parameters
            )
            response = self.get_poller_result(poller)
            return wafpolicy_to_dict(response)
        except Exception as exc:
            self.log('Error attempting to create Azure WAF Policy instance.')
            self.fail("Error Creating Azure WAF Policy instance: {0}".format(exc.message))

    def update_wafpolicy(self):
        '''
        Updates an Azure WAF Policy.

        :return: deserialized Azure WAF Policy instance state dictionary
        '''
        self.log("Updating the Azure WAF Policy instance {0}".format(self.name))

        # TODO: Add query_string_caching_behavior: str | AfdQueryStringCachingBehavior | None = None
        parameters = ''

        try:
            poller = self.wafpolicy_client.wafpolicys.begin_update(resource_group_name=self.resource_group, profile_name=self.profile_name, endpoint_name=self.endpoint_name, wafpolicy_name=self.name, wafpolicy_update_properties=parameters)
            response = self.get_poller_result(poller)
            return wafpolicy_to_dict(response)
        except Exception as exc:
            self.log('Error attempting to update Azure WAF Policy instance.')
            self.fail("Error updating Azure WAF Policy instance: {0}".format(exc.message))

    def delete_wafpolicy(self):
        '''
        Deletes the specified Azure WAF Policy in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the WAF Policy {0}".format(self.name))
        try:
            poller = self.wafpolicy_client.wafpolicys.begin_delete(resource_group_name=self.resource_group, profile_name=self.profile_name, endpoint_name=self.endpoint_name, wafpolicy_name=self.name)
            self.get_poller_result(poller)
            return True
        except Exception as e:
            self.log('Error attempting to delete the WAF Policy.')
            self.fail("Error deleting the WAF Policy: {0}".format(e.message))
            return False

    def get_wafpolicy(self):
        '''
        Gets the properties of the specified WAF Policy.

        :return: deserialized WAF Policy state dictionary
        '''
        self.log(
            "Checking if the WAF Policy {0} is present".format(self.name))
        try:
            response = self.wafpolicy_client.policies.get(
                resource_group_name=self.resource_group,
                policy_name=self.name
            )
            self.log("Response : {0}".format(response))
            self.log("WAF Policy : {0} found".format(response.name))
            return wafpolicy_to_dict(response)
        except Exception as err:
            self.log('Did not find the WAF Policy.' + err.args[0])
            return False

    def get_wafpolicy_client(self):
        if not self.wafpolicy_client:
            self.wafpolicy_client = self.get_mgmt_svc_client(CdnManagementClient,
                                                       base_url=self._cloud_environment.endpoints.resource_manager,
                                                       api_version='2023-05-01')
        return self.wafpolicy_client

def main():
    """Main execution"""
    AzureRMWAFPolicy()
    # TODO: Clean this up
    # x = CdnManagementClient()
    # x.policies.get()

if __name__ == '__main__':
    main()
