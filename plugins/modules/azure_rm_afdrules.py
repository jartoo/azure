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
    name:
        description:
            - Name of the delivery rule which is unique within the endpoint.
        required: true
        type: str
    profile_name:
        description:
            - Name of the Azure Front Door Standard or Azure Front Door Premium profile which is unique within the resource group.
        required: true
        type: str
    resource_group:
        description:
            - Name of the Resource group within the Azure subscription.
        required: true
        type: str
    rule:
        description:
            - The delivery rule properties.
        type: dict
        suboptions:
            order:
                description:
                    - The order in which the rules are applied for the endpoint. Possible values {0,1,2,3,.........}. A rule with a lesser order will be applied before a rule with a greater order. Rule with order 0 is a special rule. It does not require any condition and actions listed in it will always be applied.
                type: int
            conditions:
                description:
                    - A list of conditions that must be matched for the actions to be executed.
                type: list
                suboptions:
                    name:
                        description:
                            - The name of the condition for the delivery rule.
                        type: str
                        choices:
                            - ClientPort
                            - Cookies
                            - HostName
                            - HttpVersion
                            - IsDevice
                            - PostArgs
                            - QueryString
                            - RemoteAddress
                            - RequestBody
                            - RequestHeader
                            - RequestMethod
                            - RequestScheme
                            - RequestUri
                            - ServerPort
                            - SocketAddr
                            - SslProtocol
                            - UrlFileExtension
                            - UrlFileName
                            - UrlPath
                    type_name:
                        description:
                            - The name of the condition for the delivery rule.
                        required: True
                        type: str
                        choices:
                            - DeliveryRuleClientPortConditionParameters
                            - DeliveryRuleCookiesConditionParameters
                            - DeliveryRuleHostNameConditionParameters
                            - DeliveryRuleHttpVersionConditionParameters
                            - DeliveryRuleIsDeviceConditionParameters
                            - DeliveryRulePostArgsConditionParameters
                            - DeliveryRuleQueryStringConditionParameters
                            - DeliveryRuleRemoteAddressConditionParameters
                            - DeliveryRuleRequestBodyConditionParameters
                            - DeliveryRuleRequestHeaderConditionParameters
                            - DeliveryRuleRequestMethodConditionParameters
                            - DeliveryRuleRequestSchemeConditionParameters
                            - DeliveryRuleRequestUriConditionParameters
                            - DeliveryRuleServerPortConditionParameters
                            - DeliveryRuleSocketAddrConditionParameters
                            - DeliveryRuleSslProtocolConditionParameters
                            - DeliveryRuleUrlFileExtensionMatchConditionParameters
                            - DeliveryRuleUrlFilenameConditionParameters
                            - DeliveryRuleUrlPathMatchConditionParameters
                    operator:
                        description:
                            - Describes operator to be matched.
                        type: int
                        required: True
                        choices:
                            - Any
                            - Equal
                            - Contains
                            - BeginsWith
                            - EndsWith
                            - LessThan
                            - LessThanOrEqual
                            - GreaterThan
                            - GreaterThanOrEqual
                            - RegEx
                            - IPMatch
                            - GeoMatch
                    negate_condition:
                        description:
                            - Describes if this is a negate condition or not.
                        type: bool
                    match_values:
                        description:
                            - The match value for the condition of the delivery rule.
                        type: list
                    selector:
                        description:
                            - Name of item to be matched.
                        type: str
                    transforms:
                        description:
                            - List of transforms.
                        type: list
                        choices:
                            - Lowercase
                            - RemoveNulls
                            - Trim
                            - Uppercase
                            - URLDecode
                            - URLEncode
            actions:
                description:
                    - A list of actions that are executed when all the conditions of a rule are satisfied.
                required: True
                type: list
                suboptions:
                    name:
                        description:
                            - The name of the action for the delivery rule.
                        type: str
                        choices:
                            - CacheExpiration
                            - CacheKeyQueryString
                            - ModifyRequestHeader
                            - ModifyResponseHeader
                            - OriginGroupOverride
                            - RouteConfigurationOverride
                            - UrlRedirect
                            - UrlRewrite
                            - UrlSigning
                    type_name:
                        description:
                            - The name of the condition for the delivery rule.
                        required: True
                        type: str
                        choices:
                            - DeliveryRuleCacheExpirationActionParameters
                            - DeliveryRuleCacheKeyQueryStringBehaviorActionParameters
                            - DeliveryRuleHeaderActionParameters
                            - DeliveryRuleOriginGroupOverrideActionParameters
                            - DeliveryRuleRouteConfigurationOverrideActionParameters
                            - DeliveryRuleUrlRedirectActionParameters
                            - DeliveryRuleUrlRewriteActionParameters
                            - DeliveryRuleUrlSigningActionParameters
                    cache_behavior:
                        description:
                            - Caching behavior for the requests.
                        type: str
                        choices:
                            - BypassCache
                            - Override
                            - SetIfMissing
                    cache_configuration:
                        description:
                            - The caching configuration for this route. To disable caching, do not provide a cacheConfiguration object.
                        type: dict
                        suboptions:
                            query_string_caching_behavior:
                                description:
                                    - Defines how Frontdoor caches requests that include query strings. You can ignore any query strings when caching, ignore specific query strings, cache every request with a unique URL, or cache specific query strings. 
                                type: str
                            query_parameters:
                                description:
                                    - query parameters to include or exclude (comma separated).
                                type: str
                            compression_settings:
                                description:
                                    - query parameters to include or exclude (comma separated).
                                type: dict
                                suboptions:
                                    content_types_to_compress:
                                        description:
                                            - List of content types (str) on which compression applies. The value should be a valid MIME type.
                                        type: list
                                    is_compression_enabled:
                                        description:
                                            - Indicates whether content compression is enabled on AzureFrontDoor. If compression is enabled, content will be served as compressed if user requests for a compressed version. Content won't be compressed on AzureFrontDoor when requested content is smaller than 1 byte or larger than 1 MB.
                                        type: bool
                    cache_type:
                        description:
                            - The level at which the content needs to be cached.
                        type: str
                        default: all
                    cache_duration:
                        description:
                            - The duration for which the content needs to be cached. Allowed format is [d.]hh:mm:ss.
                        type: str
                    header_action:
                        description:
                            - Action to perform.
                        type: str
                        choices:
                            - Append
                            - Overwrite
                            - Delete
                    header_name:
                        description:
                            - Name of the header to modify.
                        type: str
                    origin_group:
                        description:
                            - defines the OriginGroup that would override the DefaultOriginGroup.
                        type: str
                    origin_group_override:
                        description:
                            - A reference to the origin group override configuration. Leave empty to use the default origin group on route.
                        type: str
                    query_string_behavior:
                        description:
                            - 
                        type: str
                        choices:
                            - Include
                            - IncludeAll
                            - Exclude
                            - ExcludeAll
                    query_parameters:
                        description:
                            - query parameters to include or exclude (comma separated).
                        type: str
                    value:
                        description:
                            - Value for the specified action.
                        type: str
                    redirect_type:
                        description:
                            - The redirect type the rule will use when redirecting traffic.
                        type: str
                        choices:
                            - Moved
                            - Found
                            - TemporaryRedirect
                            - PermanentRedirect
                    destination_protocol:
                        description:
                            - Protocol to use for the redirect.
                        default: MatchRequest
                        type: str
                        choices:
                            - Http
                            - Https
                            - MatchRequest
                    custom_path:
                        description:
                            - The full path to redirect. Path cannot be empty and must start with /. Leave empty to use the incoming path as destination path.
                        type: str
                    custom_hostname:
                        description:
                            - Host to redirect. Leave empty to use the incoming host as the destination host.
                        type: str
                    custom_query_string:
                        description:
                            - The set of query strings to be placed in the redirect URL. Setting this value would replace any existing query string; leave empty to preserve the incoming query string. Query string must be in <key>=:code:<value> format. ? and & will be added automatically so do not include them.
                        type: str
                    custom_fragment:
                        description:
                            - Fragment to add to the redirect URL. Fragment is the part of the URL that comes after #. Do not include the #
                        type: str
                    source_pattern:
                        description:
                            - Define a request URI pattern that identifies the type of requests that may be rewritten. If value is blank, all strings are matched.
                        type: str
                    destination:
                        description:
                            - Define the relative URL to which the above requests will be rewritten by.
                        type: str
                    preserve_unmatched_path:
                        description:
                            - Whether to preserve unmatched path.
                        default: True
                        type: bool
                    algorithm:
                        description:
                            - Algorithm to use for URL signing
                        default: SHA256
                        type: str
                    parameter_name_override:
                        description:
                            - Defines which query string parameters in the url to be considered for expires, key id etc.
                        type: list
                        suboptions:
                            param_indicator:
                                description:
                                    - Indicates the purpose of the parameter.
                                type: str
                                choices:
                                    - Expires
                                    - KeyId
                                    - Signature
                            param_name:
                                description:
                                    - Parameter name
                                type: str
            match_processing_behavior:
                description:
                    - If this rule is a match should the rules engine continue running the remaining rules or stop.
                default: Continue
                type: str
                choices:
                    - Continue
                    - Stop
                
    rule_set_name:
        description:
            - Name of the rule set under the profile.
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
        rule_set_name = rules.rule_set_name,
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
                self.log("Need to create the Rule")

                if not self.check_mode:
                    new_response = self.create_rules()
                    self.results['id'] = new_response['id']

                self.results['changed'] = True

            else:
                self.log('Results : {0}'.format(response))

        elif self.state == 'absent':
            if not response:
                self.fail("Rule {0} does not exist.".format(self.name))
            else:
                self.log("Need to delete the Rule")
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
