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
module: azure_rm_afdroute
version_added: "0.1.0"
short_description: Manage an Azure Front Door Route
description:
    - Create, update and delete an Azure Front Door Route to be used by a Front Door Service Profile created using azure_rm_cdnprofile.

options:
    endpoint_name:
        description:
            - Name of the endpoint under the profile which is unique globally.
        required: true
        type: str
    name:
        description:
            - Name of the routing rule.
        required: true
        type: str
    origin_group:
        description:
            - The origin group name.
        type: str
    profile_name:
        description:
            - Name of the Azure Front Door Standard or Azure Front Door Premium profile which is unique within the resource group.
        required: true
        type: str
    resource_group_name:
        description:
            - Name of the Resource group within the Azure subscription.
        required: true
        type: str
    route:
        description:
            - Route properties
        type: dict
        suboptions:
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
            enabled_state:
                description:
                    - Whether to enable use of this rule. Permitted values are 'Enabled' or 'Disabled'. Known values are: "Enabled" and "Disabled".
                type: str
            forwarding_protocol:
                description:
                    - Protocol this rule will use when forwarding traffic to backends. Known values are: "HttpOnly", "HttpsOnly", and "MatchRequest".
                type: str
            https_redirect:
                description:
                    - Whether to automatically redirect HTTP traffic to HTTPS traffic. Note that this is a easy way to set up this rule and it will be the first rule that gets executed. Known values are: "Enabled" and "Disabled".
                type: str
            link_to_default_domain:
                description:
                    - whether this route will be linked to the default endpoint domain. Known values are: "Enabled" and "Disabled".
                type: str
            origin_path:
                description:
                    - A directory path on the origin that AzureFrontDoor can use to retrieve content from, e.g. contoso.cloudapp.net/originpath.
                type: str
            patterns_to_match:
                description:
                    - The route patterns of the rule.
                type: list
            rule_sets:
                description:
                    - List of rule set names referenced by this endpoint.
                type: list
            supported_protocols:
                description:
                    - List of supported protocols for this route.
                type: list
    state:
        description:
            - Assert the state of the Route. Use C(present) to create or update a CDN profile and C(absent) to delete it.
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
- name: Create an AFD Route
  azure_rm_afdroute:
    name: myRoute
    endpoint_name: myEndpoint
    origin_group: myOriginGroup
    profile_name: myProfile
    resource_group_name: myResourceGroup
    state: present
    route:
        enabled_state: Disabled
        forwarding_protocol: HttpsOnly
        https_redirect: Enabled
        patterns_to_match:
            - "/*"
        rule_sets:
            - Security
        supported_protocols:
            - Https
            - Http
        link_to_default_domain: Enabled

- name: Delete an AFD Origin
  azure_rm_afdroute:
    name: myRoute
    endpoint_name: myEndpoint
    origin_group: myOriginGroup
    profile_name: myProfile
    resource_group_name: myResourceGroup
    state: absent
'''
RETURN = '''
id:
    description:
        - ID of the Route.
    returned: always
    type: str
    sample: "id: '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourcegroups/myResourcegroup/providers/Microsoft.Cdn/profiles/myProfile/afdendpoints/myEndPoint/routes/myRoute'"
'''
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from azure.mgmt.cdn.models import Route, RouteProperties, RouteUpdateParameters, CompressionSettings, ResourceReference, CacheConfiguration, AfdRouteCacheConfiguration
    from azure.mgmt.cdn import CdnManagementClient

except ImportError as ec:
    # This is handled in azure_rm_common
    pass

def route_to_dict(route):
    return dict(
        custom_domains=route.custom_domains,
        cache_configuration=route.cache_configuration,
        deployment_status=route.deployment_status,
        enabled_state = route.enabled_state,
        forwarding_protocol = route.forwarding_protocol,
        https_redirect = route.https_redirect,
        id = route.id,
        link_to_default_domain = route.link_to_default_domain,
        name=route.name,
        origin_group_id=route.origin_group.id,
        origin_path=route.origin_path,
        patterns_to_match=route.patterns_to_match,
        provisioning_state=route.provisioning_state,
        rule_sets=route.rule_sets,
        supported_protocols=route.supported_protocols,
        type=route.type
    )

class AzureRMRoute(AzureRMModuleBase):

    def __init__(self):
        self.module_arg_spec = dict(
            endpoint_name=dict(
                type='str',
                required=True
            ),
            name=dict(
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
            origin_group=dict(
                type='str'
            ),
            route=dict(
                type='dict',
                options=dict(
                    custom_domains=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            id=dict(type='str'),
                            is_active=dict(type='bool'),
                            resource_group=dict(type='str')
                        )
                    ),
                    origin_path=dict(
                        type='str'
                    ),
                    rule_sets=dict(
                        type='list',
                        elements='str'
                    ),
                    supported_protocols=dict(
                        type='list',
                        choices=['Http', 'Https']
                    ),
                    patterns_to_match=dict(
                        type='list',
                        elements='raw'
                    ),
                    cache_configuration=dict(
                        type='dict',
                        options=dict(
                            query_string_caching_behavior=dict(type='str', choices=['IGNORE_QUERY_STRING', 'IGNORE_SPECIFIED_QUERY_STRINGS', 'INCLUDE_SPECIFIED_QUERY_STRINGS', 'USE_QUERY_STRING']),
                            query_parameters=dict(type='str'),
                            compression_settings=dict(
                                type='dict',
                                options=dict(
                                    content_types_to_compress=dict(type='list',elements='str',required=False),
                                    is_compression_enabled=dict(type='bool',required=False),
                                )
                            )
                        )
                    ),
                    forwarding_protocol=dict(
                        type='str',
                        choices=['HttpOnly', 'HttpsOnly', 'MatchRequest']
                    ),
                    link_to_default_domain=dict(
                        type='str',
                        choices=['Enabled', 'Disabled'],
                        default='Disabled'
                    ),
                    https_redirect=dict(
                        type='str',
                        choices=['Enabled', 'Disabled'],
                        default='Disabled'
                    ),
                    enabled_state=dict(
                        type='str',
                        choices=['Enabled', 'Disabled']
                    )
                )
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            )
        )

        self.route = None
        self.origin_group_id = None
        
        self.name = None
        self.origin_group = None
        self.endpoint_name = None
        self.profile_name = None
        self.resource_group = None
        self.state = None

        self.route_client = None

        required_if = [
            ('state', 'present', ['origin_group'])
        ]

        self.results = dict(changed=False)

        super(AzureRMRoute, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                supports_check_mode=True,
                                                supports_tags=False,
                                                required_if=required_if)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        self.route_client = self.get_route_client()

        to_be_updated = False

        # Do not need the resource group location
        # resource_group = self.get_resource_group(self.resource_group)
        # if not self.location:
        #     self.location = resource_group.location

        # Get the existing resource
        response = self.get_route()

        

        if self.state == 'present':
            # Get the Origin Group ID
            self.origin_group_id = self.get_origin_group_id()
            if self.origin_group_id is False:
                self.fail("Could not obtain Origin Group ID from {0}".format(self.origin_group))

            # Populate the rule_set_ids
            convert_rules = self.get_rule_set_ids()
            if not convert_rules:
                self.fail("Failed to convert the Rule Set names to IDs")

            if not response:
                self.log("Need to create the Route")

                if not self.check_mode:
                    new_results = self.create_route()
                    self.results['id'] = new_results['id']
                self.results['changed'] = True

            else:
                self.log('Results : {0}'.format(response))
                
                # TODO: Disabling cache_configuration does not currently work with the SDK, see https://github.com/Azure/azure-sdk-for-python/issues/35801
                if response['cache_configuration'] and not self.route['cache_configuration']:
                        to_be_updated = True
                elif not response['cache_configuration'] and self.route['cache_configuration']:
                        to_be_updated = True
                elif response['cache_configuration'] and self.route['cache_configuration']:
                    if response['cache_configuration']['compression_settings'] and not self.route['cache_configuration']['compression_settings']:
                        to_be_updated = True
                    elif not response['cache_configuration']['compression_settings'] and self.route['cache_configuration']['compression_settings']:
                        to_be_updated = True
                    elif response['cache_configuration']['compression_settings'] and self.route['cache_configuration']['compression_settings']:
                        if response['cache_configuration']['compression_settings']['is_compression_enabled'] != self.route['cache_configuration']['compression_settings']['is_compression_enabled']:
                            to_be_updated = True
                        if response['cache_configuration']['compression_settings']['content_types_to_compress'] != self.route['cache_configuration']['compression_settings']['content_types_to_compress']:
                            to_be_updated = True
                    if response['cache_configuration']['query_parameters'] != self.route['cache_configuration']['query_parameters']:
                        to_be_updated = True
                    if response['cache_configuration']['query_string_caching_behavior'] != self.route['cache_configuration']['query_string_caching_behavior']:
                        to_be_updated = True

                if response['custom_domains'] != self.route['custom_domains'] and self.route['custom_domains']:
                    to_be_updated = True
                if response['enabled_state'] != self.route['enabled_state'] and self.route['enabled_state']:
                    to_be_updated = True
                if response['forwarding_protocol'] != self.route['forwarding_protocol'] and self.route['forwarding_protocol']:
                    to_be_updated = True
                if response['https_redirect'] != self.route['https_redirect'] and self.route['https_redirect']:
                    to_be_updated = True
                if response['link_to_default_domain'] != self.route['link_to_default_domain'] and self.route['link_to_default_domain']:
                    to_be_updated = True
                if response['origin_group_id'] != self.origin_group_id and self.origin_group_id:
                    to_be_updated = True
                if response['origin_path'] != self.route['origin_path'] and self.route['origin_path']:
                    to_be_updated = True
                if response['patterns_to_match'] != self.route['patterns_to_match'] and self.route['patterns_to_match']:
                    to_be_updated = True
                if response["rule_sets"] != self.rule_set_ids and self.rule_set_ids:
                    to_be_updated = True
                if response['supported_protocols'] != self.route['supported_protocols'] and self.route['supported_protocols']:
                    to_be_updated = True

                self.results['id'] = response['id']
                if to_be_updated:
                    self.log("Need to update the Route")

                    if not self.check_mode:
                        new_results = self.update_route()
                        self.results['id'] = new_results['id']

                    self.results['changed'] = True

        elif self.state == 'absent':
            if not response:
                self.log("Route {0} does not exist.".format(self.name))
                self.results['id'] = None
                self.results['changed'] = False
            else:
                self.log("Need to delete the Route")
                self.results['changed'] = True

                if not self.check_mode:
                    self.delete_route()
                    self.results['id'] = response['id']
        return self.results

    def create_route(self):
        '''
        Creates a Azure Route.

        :return: deserialized Azure Route instance state dictionary
        '''
        self.log("Creating the Azure Route instance {0}".format(self.name))
        cache_configuration = None
        if self.route['cache_configuration']:
            compression_settings =  None
            if self.route['cache_configuration']['compression_settings']:
                compression_settings = CompressionSettings(
                    content_types_to_compress=self.route['cache_configuration']['content_types_to_compress'],
                    is_compression_enabled=self.route['cache_configuration']['is_compression_enabled']
                )
            cache_configuration = AfdRouteCacheConfiguration(
                query_string_caching_behavior=self.route['cache_configuration']['query_string_caching_behavior'],
                query_parameters=self.route['cache_configuration']['query_parameters'],
                compression_settings=compression_settings
            )


        origin_group = ResourceReference(
            id=self.origin_group_id
        )

        parameters = Route(
            cache_configuration=cache_configuration,
            custom_domains=self.route['custom_domains'],
            enabled_state=self.route['enabled_state'],
            forwarding_protocol=self.route['forwarding_protocol'],
            https_redirect=self.route['https_redirect'],
            link_to_default_domain=self.route['link_to_default_domain'],
            origin_group=origin_group,
            origin_path=self.route['origin_path'],
            patterns_to_match=self.route['patterns_to_match'],
            rule_sets=self.rule_set_ids,
            supported_protocols=self.route['supported_protocols']
        )
            
        try:
            poller = self.route_client.routes.begin_create(resource_group_name=self.resource_group,
                                                           profile_name=self.profile_name,
                                                           endpoint_name=self.endpoint_name,
                                                           route_name=self.name,
                                                           route=parameters)
            response = self.get_poller_result(poller)
            return route_to_dict(response)
        except Exception as exc:
            self.log('Error attempting to create Azure Route instance.')
            self.fail("Error Creating Azure Route instance: {0}".format(exc.message))

    def update_route(self):
        '''
        Updates an Azure Route.

        :return: deserialized Azure Route instance state dictionary
        '''
        self.log("Updating the Azure Route instance {0}".format(self.name))
        origin_group = ResourceReference(
            id=self.origin_group_id
        )

        cache_configuration = None
        if self.route['cache_configuration']:
            compression_settings =  None
            if self.route['cache_configuration']['compression_settings']:
                compression_settings = CompressionSettings(
                    content_types_to_compress=self.route['cache_configuration']['content_types_to_compress'],
                    is_compression_enabled=self.route['cache_configuration']['is_compression_enabled']
                )
            cache_configuration = AfdRouteCacheConfiguration(
                query_string_caching_behavior=self.route['cache_configuration']['query_string_caching_behavior'],
                query_parameters=self.route['cache_configuration']['query_parameters'],
                compression_settings=compression_settings
            )

        parameters = RouteUpdateParameters(
            cache_configuration=cache_configuration,
            custom_domains=self.route['custom_domains'],
            enabled_state=self.route['enabled_state'],
            forwarding_protocol=self.route['forwarding_protocol'],
            https_redirect=self.route['https_redirect'],
            link_to_default_domain=self.route['link_to_default_domain'],
            origin_group=origin_group,
            origin_path=self.route['origin_path'],
            patterns_to_match=self.route['patterns_to_match'],
            rule_sets=self.rule_set_ids,
            supported_protocols=self.route['supported_protocols']
        )

        try:
            poller = self.route_client.routes.begin_update(resource_group_name=self.resource_group, profile_name=self.profile_name, endpoint_name=self.endpoint_name, route_name=self.name, route_update_properties=parameters)
            response = self.get_poller_result(poller)
            return route_to_dict(response)
        except Exception as exc:
            self.log('Error attempting to update Azure Route instance.')
            self.fail("Error updating Azure Route instance: {0}".format(exc.message))

    def delete_route(self):
        '''
        Deletes the specified Azure Route in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the Route {0}".format(self.name))
        try:
            poller = self.route_client.routes.begin_delete(resource_group_name=self.resource_group, profile_name=self.profile_name, endpoint_name=self.endpoint_name, route_name=self.name)
            self.get_poller_result(poller)
            return True
        except Exception as e:
            self.log('Error attempting to delete the Route.')
            self.fail("Error deleting the Route: {0}".format(e.message))
            return False

    def get_route(self):
        '''
        Gets the properties of the specified Route.

        :return: deserialized Route state dictionary
        '''
        self.log(
            "Checking if the Route {0} is present".format(self.name))
        try:
            response = self.route_client.routes.get(
                resource_group_name=self.resource_group,
                profile_name=self.profile_name,
                endpoint_name=self.endpoint_name,
                route_name=self.name,
            )
            self.log("Response : {0}".format(response))
            self.log("Route : {0} found".format(response.name))
            return route_to_dict(response)
        except Exception as err:
            self.log('Did not find the Route.' + err.args[0])
            return False

    def get_origin_group_id(self):
        '''
        Gets the ID of the specified Origin Group.

        :return: ID for the Origin Group.
        '''
        self.log(
            "Obtaining ID for Origin Group {0}".format(self.origin_group))
        try:
            response = self.route_client.afd_origin_groups.get(resource_group_name=self.resource_group, profile_name=self.profile_name, origin_group_name=self.origin_group)
            self.log("Response : {0}".format(response))
            self.log("Origin Group ID found : {0} found".format(response.id))
            return response.id
        except Exception as err:
            self.log('Did not find the Origin Group.' + err.args[0])
            return False

    def get_rule_set_ids(self):
        '''
        Gets the IDs of the specified Rule Sets.

        :return: Boolean if Rule Sets were found and translated.
        '''
        if self.route['rule_sets'] is None or len(self.route['rule_sets']) == 0:
            return True
        
        self.log("Obtaining IDs for Rule Sets")
        self.rule_set_ids = []
        try:
            for rule_name in self.route['rule_sets']:
                response = self.route_client.rule_sets.get(
                    resource_group_name=self.resource_group,
                    profile_name=self.profile_name,
                    rule_set_name=rule_name,
                )
                self.log("Response : {0}".format(response))
                self.log("Rule Set ID found : {0} found".format(response.id))
                self.rule_set_ids.append(ResourceReference(id=response.id))
                return True
        except Exception as err:
            self.log('Error getting the Rule Set IDs.' + err.args[0])
            return False

    def get_route_client(self):
        if not self.route_client:
            self.route_client = self.get_mgmt_svc_client(CdnManagementClient,
                                                       base_url=self._cloud_environment.endpoints.resource_manager,
                                                       api_version='2023-05-01')
        return self.route_client

    # TODO: Use this to create a list of IDs
    def construct_subresource_list(self, raw):
        return [self.route_client.SubResource(id=x) for x in raw] if raw else None


def main():
    """Main execution"""
    AzureRMRoute()
    # x = CdnManagementClient()
    # x.routes.begin_update()

if __name__ == '__main__':
    main()
