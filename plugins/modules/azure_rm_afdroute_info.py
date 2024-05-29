#!/usr/bin/python
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# Python SDK Reference: https://learn.microsoft.com/en-us/python/api/azure-mgmt-cdn/azure.mgmt.cdn.operations.routesoperations?view=azure-python
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_afdroute_info

version_added: ""

short_description: Get Azure Front Door Route facts to be used with Standard or Premium Frontdoor Service

description:
    - Get facts for a specific Azure Front Door (AFD) Route or all AFD Routes.  This differs from the Front Door classic service and only is intended to be used by the Standard or Premium service offering.

options:
    endpoint_name:
        description:
            - Name of the endpoint under the profile which is unique globally.
        required: true
        type: str
    name:
        description:
            - Name of the route.
        type: str
    profile_name:
        description:
            - Name of the Azure Front Door Standard or Azure Front Door Premium profile which is unique within the resource group
        required: true
        type: str
    resource_group:
        description:
            - Name of the Resource group within the Azure subscription.
        required: true
        type: str

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - Jarret Tooley (@jartoo)
'''

EXAMPLES = '''
- name: Get facts for all Routes in the AFD Profile
  azure_rm_afdroute_info:
    endpoint_name: myEndpoint
    profile_name: myProfile
    resource_group: myResourceGroup

- name: Get facts of specific AFD Route
  azure_rm_afdroute_info:
    name: myRoute1
    endpoint_name: myEndpoint
    profile_name: myProfile
    resource_group: myResourceGroup
'''

RETURN = '''
afdroutes:
    description: List of AFD Routes.
    returned: always
    type: complex
    contains:
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
        custom_domains:
            description:
                - Domain id's referenced by this endpoint.
            type: list
        deployment_status:
            description:
                - Current state of the resource.
            type: str
            sample: NotStarted
        enabled_state:
            description:
                - Whether to enable use of this rule. Permitted values are 'Enabled' or 'Disabled'. Known values are: "Enabled" and "Disabled".
            type: str
        endpoint_name:
            description:
                - Name of the endpoint.
            type: str
        forwarding_protocol:
            description:
                - Protocol this rule will use when forwarding traffic to backends. Known values are: "HttpOnly", "HttpsOnly", and "MatchRequest".
            type: str
        https_redirect:
            description:
                - Whether to automatically redirect HTTP traffic to HTTPS traffic. Note that this is a easy way to set up this rule and it will be the first rule that gets executed. Known values are: "Enabled" and "Disabled".
            type: str
        id:
            description:
                - ID of the AFD Route.
            type: str
            sample: "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourcegroups/myResourceGroup/providers/Microsoft.Cdn/profiles/myProfile/routegroups/myrouteGroup1/routes/myroute1"
        link_to_default_domain:
            description:
                - whether this route will be linked to the default endpoint domain. Known values are: "Enabled" and "Disabled".
            type: str
        name:
            description:
                - Name of the AFD Route.
            required: true
            type: str
        origin_group_id:
            description:
                - The origin group id.
            type: str
            sample: /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourcegroups/myResourceGroup/providers/Microsoft.Cdn/profiles/myProfile/origingroups/myOriginGroup
        origin_path:
            description:
                - A directory path on the origin that AzureFrontDoor can use to retrieve content from, e.g. contoso.cloudapp.net/originpath.
            type: str
        patterns_to_match:
            description:
                - The route patterns of the rule.
            type: list
        profile_name:
            description:
                - Name of the AFD Profile where the Route is.
            required: true
            type: str
        provisioning_state:
            description:
                - Provisioning status of the AFD Route.
            type: str
            sample: Succeeded
        resource_group_name:
            description:
                - Name of a resource group where the AFD Route exists.
            required: true
            type: str
        rule_sets:
            description:
                - List of rule set id referenced by this endpoint.
            type: list
        supported_protocols:
            description:
                - List of supported protocols for this route.
            type: list
        type:
            description:
                - Resource type.
            type: str
            sample: Microsoft.Cdn/profiles/afdendpoints/routes
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from azure.mgmt.cdn import CdnManagementClient
except ImportError:
    # handled in azure_rm_common
    pass

import re

AZURE_OBJECT_CLASS = 'AFDRoute'


class AzureRMAFDRouteInfo(AzureRMModuleBase):
    """Utility class to get Azure AFD Route facts"""

    def __init__(self):

        self.module_args = dict(
            name=dict(type='str'),
            endpoint_name=dict(
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
            )
        )

        self.results = dict(
            changed=False,
            afdroutes=[]
        )

        self.name = None
        self.endpoint_name = None
        self.resource_group = None
        self.profile_name = None

        super(AzureRMAFDRouteInfo, self).__init__(
            supports_check_mode=True,
            derived_arg_spec=self.module_args,
            supports_tags=False,
            facts_module=True
        )

    def exec_module(self, **kwargs):

        for key in self.module_args:
            setattr(self, key, kwargs[key])

        self.route_client = self.get_mgmt_svc_client(CdnManagementClient,
                                                   base_url=self._cloud_environment.endpoints.resource_manager,
                                                   api_version='2023-05-01')

        if self.name:
            self.results['afdroutes'] = self.get_item()
        else:
            self.results['afdroutes'] = self.list_by_endpoint()

        return self.results

    def get_item(self):
        """Get a single Azure AFD Route"""

        self.log('Get properties for {0}'.format(self.name))

        item = None
        result = []

        try:
            item = self.route_client.routes.get(
                resource_group_name=self.resource_group, profile_name=self.profile_name, endpoint_name=self.endpoint_name, route_name=self.name)
        except Exception as exc:
            pass

        if item:
            result = [self.serialize_afdroute(item)]

        return result

    def list_by_endpoint(self):
        """Get all Azure AFD Routes within an AFD profile"""

        self.log('List all AFD Routes within an AFD profile')

        try:
            response = self.route_client.routes.list_by_endpoint(
                resource_group_name=self.resource_group, profile_name=self.profile_name, endpoint_name=self.endpoint_name)
        except Exception as exc:
            self.fail('Failed to list all items - {0}'.format(str(exc)))

        results = []
        for item in response:
            results.append(self.serialize_afdroute(item))

        return results

    def serialize_afdroute(self, afdroute):
        '''
        Convert a AFD Route object to dict.
        :param afdroute: AFD Route object
        :return: dict
        '''
        result = self.serialize_obj(afdroute, AZURE_OBJECT_CLASS)

        new_result = {}
        new_result['cache_configuration'] = {}
        new_result['cache_configuration']['query_string_caching_behavior'] = None
        new_result['cache_configuration']['query_parameters'] = None
        new_result['cache_configuration']['compression_settings'] = {}
        new_result['cache_configuration']['compression_settings']['content_types_to_compress'] = None
        new_result['cache_configuration']['compression_settings']['is_compression_enabled'] = None
        if afdroute.cache_configuration:
            new_result['cache_configuration']['query_string_caching_behavior'] = afdroute.cache_configuration['query_string_caching_behavior']
            new_result['cache_configuration']['query_parameters'] = afdroute.cache_configuration['query_parameters']
            if new_result['cache_configuration']['compression_settings']:
                new_result['cache_configuration']['compression_settings']['content_types_to_compress'] = afdroute.cache_configuration['compression_settings']['content_types_to_compress']
                new_result['cache_configuration']['compression_settings']['is_compression_enabled'] = afdroute.cache_configuration['compression_settings']['is_compression_enabled']
        new_result['custom_domains'] = afdroute.custom_domains
        new_result['deployment_status'] = afdroute.deployment_status
        new_result['enabled_state'] = afdroute.enabled_state
        new_result['endpoint_name'] = self.endpoint_name
        new_result['forwarding_protocol'] = afdroute.forwarding_protocol
        new_result['https_redirect'] = afdroute.https_redirect
        new_result['id'] = afdroute.id
        new_result['link_to_default_domain'] = afdroute.link_to_default_domain
        new_result['name'] = afdroute.name
        new_result['origin_group_id'] = afdroute.origin_group.id
        new_result['origin_path'] = afdroute.origin_path
        new_result['patterns_to_match'] = afdroute.patterns_to_match
        new_result['provisioning_state'] = afdroute.provisioning_state
        new_result['rule_sets'] = []
        for rule_set in afdroute.rule_sets:
            new_result['rule_sets'].append(rule_set.id)
        new_result['profile_name'] = re.sub('\\/.*', '', re.sub('.*profiles\\/', '', result['id']))
        new_result['resource_group_name'] = re.sub('\\/.*', '', re.sub('.*resourcegroups\\/', '', result['id']))
        new_result['supported_protocols'] = afdroute.supported_protocols
        new_result['type'] = afdroute.type
        return new_result


def main():
    """Main module execution code path"""
    AzureRMAFDRouteInfo()

if __name__ == '__main__':
    main()
