#!/usr/bin/python
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

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
    resource_group:
        description:
            - Name of a resource group where the CDN front door route exists or will be created.
        required: true
        type: str
    name:
        description:
            - Name of the Front Door Route.
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
    from azure.mgmt.cdn.models import Route, RouteProperties, RouteUpdateParameters, CompressionSettings, ResourceReference
    from azure.mgmt.cdn import CdnManagementClient
except ImportError as ec:
    # This is handled in azure_rm_common
    pass

def route_to_dict(route):
    return dict(
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
        query_string_caching_behavior=route.query_string_caching_behavior,
        rule_sets=route.rule_sets,
        supported_protocols=route.supported_protocols,
        type=route.type
    )

class AzureRMRoute(AzureRMModuleBase):

    def __init__(self):
        self.module_arg_spec = dict(
            content_types_to_compress=dict(
                type='list',
                elements='raw',
                required=False
            ),
            custom_domains=dict(
                type='list',
                elements='dict',
                options=dict(
                    id=dict(type='str'),
                    is_active=dict(type='bool'),
                    resource_group=dict(type='str')
                ),
                required=False
            ),
            enabled_state=dict(
                type='str',
                required=False
            ),
            endpoint_name=dict(
                type='str',
                required=True
            ),
            forwarding_protocol=dict(
                type='str',
                choices=['HttpOnly', 'HttpsOnly', 'MatchRequest'],
                required=False
            ),
            https_redirect=dict(
                type='str',
                choices=['Enabled', 'Disabled'],
                required=False
            ),
            is_compression_enabled=dict(
                type='bool',
                required=False
            ),
            link_to_default_domain=dict(
                type='str',
                choices=['Enabled', 'Disabled'],
                required=False
            ),
            name=dict(
                type='str',
                required=True
            ),
            origin_group_name=dict(
                type='str',
                required=True
            ),
            origin_path=dict(
                type='str',
                required=False
            ),
            patterns_to_match=dict(
                type='list',
                elements='raw',
                required=False
            ),
            profile_name=dict(
                type='str',
                required=True
            ),
            resource_group=dict(
                type='str',
                required=True
            ),
            rule_sets=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(type='str', required=False)
                ),
                required=False
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent'],
                required=False
            ),
            supported_protocols=dict(
                type='list',
                choices=['Http', 'Https'],
                required=False
            )
        )

        self.content_types_to_compress = None
        self.custom_domains = None
        self.enabled_state = None
        self.endpoint_name = None
        self.forwarding_protocol = None
        self.https_redirect = None
        self.link_to_default_domain = None
        self.is_compression_enabled = None
        self.origin_path = None
        self.patterns_to_match = None
        self.rule_sets = None
        self.rule_set_ids = None
        self.supported_protocols = None

        self.name = None
        self.origin_group_name = None
        self.profile_name = None
        self.resource_group = None
        self.state = None

        self.route_client = None

        required_if = [
            # ('state', 'present', ['host_name']) # TODO: Flesh these out
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

        # Get the Origin Group ID
        self.origin_group_id = self.get_origin_group_id()
        if self.origin_group_id is False:
            self.fail("Could not obtain Origin Group ID from {0}".format(self.origin_group_name))
        
        # Populate the rule_set_ids
        convert_rules = self.get_rule_set_ids()
        if not convert_rules:
            self.fail("Failed to convert the Rule Set names to IDs")

        if self.state == 'present':

            if not response:
                self.log("Need to create the Route")

                if not self.check_mode:
                    new_results = self.create_route()
                    self.results['id'] = new_results['id']
                self.results['changed'] = True

            else:
                self.log('Results : {0}'.format(response))
                
                if response['enabled_state'] != self.enabled_state and self.enabled_state:
                    to_be_updated = True
                if response["forwarding_protocol"] != self.forwarding_protocol and self.forwarding_protocol:
                    to_be_updated = True
                if response["https_redirect"] != self.https_redirect and self.https_redirect:
                    to_be_updated = True
                if response["link_to_default_domain"] != self.link_to_default_domain and self.link_to_default_domain:
                    to_be_updated = True
                if response["origin_group_id"] != self.origin_group_id and self.origin_group_id:
                    to_be_updated = True
                if response["origin_path"] != self.origin_path and self.origin_path:
                    to_be_updated = True
                if response["patterns_to_match"] != self.patterns_to_match and self.patterns_to_match:
                    to_be_updated = True
                if response["rule_sets"] != self.rule_set_ids and self.rule_set_ids:
                    to_be_updated = True
                if response["supported_protocols"] != self.supported_protocols and self.supported_protocols:
                    to_be_updated = True

                if to_be_updated:
                    self.log("Need to update the Route")

                    if not self.check_mode:
                        new_results = self.update_route()
                        self.results['id'] = new_results['id']

                    self.results['changed'] = True

        elif self.state == 'absent':
            if not response:
                self.log("Route {0} does not exist.".format(self.name))
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
        
        compression_settings = CompressionSettings(
            content_types_to_compress=self.content_types_to_compress,
            is_compression_enabled=self.is_compression_enabled
        )

        origin_group = ResourceReference(
            id=self.origin_group_id
        )

        parameters = Route(
            compression_settings=compression_settings,
            custom_domains=self.custom_domains,
            enabled_state=self.enabled_state,
            forwarding_protocol=self.forwarding_protocol,
            https_redirect=self.https_redirect,
            link_to_default_domain=self.link_to_default_domain,
            origin_group=origin_group,
            origin_path=self.origin_path,
            patterns_to_match=self.patterns_to_match,
            rule_sets=self.rule_set_ids,
            supported_protocols=self.supported_protocols
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

        compression_settings = CompressionSettings(
            content_types_to_compress=self.content_types_to_compress,
            is_compression_enabled=self.is_compression_enabled
        )

        # TODO: Add query_string_caching_behavior: str | AfdQueryStringCachingBehavior | None = None
        parameters = RouteUpdateParameters(
            compression_settings=compression_settings,
            custom_domains=self.custom_domains,
            enabled_state=self.enabled_state,
            forwarding_protocol=self.forwarding_protocol,
            https_redirect=self.https_redirect,
            link_to_default_domain=self.link_to_default_domain,
            origin_group=origin_group,
            origin_path=self.origin_path,
            patterns_to_match=self.patterns_to_match,
            rule_sets=self.rule_set_ids,
            supported_protocols=self.supported_protocols
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
            "Obtaining ID for Origin Group {0}".format(self.origin_group_name))
        try:
            response = self.route_client.afd_origin_groups.get(self.resource_group, self.profile_name, self.origin_group_name)
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
        if self.rule_sets is None or len(self.rule_sets) == 0:
            return True
        
        self.log("Obtaining IDs for Rule Sets")
        self.rule_set_ids = []
        try:
            for rule_name in self.rule_sets:
                response = self.route_client.rule_sets.get(
                    resource_group_name=self.resource_group,
                    profile_name=self.profile_name,
                    rule_set_name=rule_name['name'],
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
    # TODO: Clean this up
    x = CdnManagementClient()
    x.routes.begin_delete()

if __name__ == '__main__':
    main()
