#!/usr/bin/python
#
# Copyright (c) 2018 Hai Cao, <t-haicao@microsoft.com>, Yunge Zhu <yungez@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_afdendpoint
version_added: "0.1.0"
short_description: Manage an Azure Front Door Endpoint
description:
    - Create, update and delete an Azure Front Door Endpoint to be used by a Front Door Service Profile created using azure_rm_cdnprofile.

options:
    resource_group:
        description:
            - Name of a resource group where the CDN front door endpoint exists or will be created.
        required: true
        type: str
    name:
        description:
            - Name of the Front Door Endpoint.
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
    - azure.azcollection.azure_tags

author:
    - Jarret Tooley (@jartoo)
'''

EXAMPLES = '''
- name: Create an Endpoint
  azure_rm_afdendpoint:
    resource_group: myResourceGroup
    name: myCDN
    sku: standard_akamai
    tags:
      testing: testing

- name: Delete the CDN profile
  azure_rm_cdnprofile:
    resource_group: myResourceGroup
    name: myCDN
    state: absent
'''
RETURN = '''
id:
    description: Current state of the CDN profile.
    returned: always
    type: dict
    example:
            id: /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourcegroups/myResourceGroup/providers/Microsoft.Cdn/profiles/myCDN
'''
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase
import uuid

try:
    from azure.mgmt.cdn.models import AFDEndpoint, AFDEndpointUpdateParameters
    from azure.mgmt.cdn import CdnManagementClient
except ImportError as ec:
    # This is handled in azure_rm_common
    pass


def endpoint_to_dict(endpoint):
    return dict(
        deployment_status = endpoint.deployment_status,
        enabled_state = endpoint.enabled_state,
        host_name = endpoint.host_name,
        id = endpoint.id,
        location=endpoint.location,
        name=endpoint.name,
        origin_response_timeout_seconds=endpoint.origin_response_timeout_seconds,
        provisioning_state=endpoint.provisioning_state,
        tags=endpoint.tags,
        type=endpoint.type
    )


class AzureRMEndpoint(AzureRMModuleBase):

    def __init__(self):
        self.module_arg_spec = dict(
            name=dict(
                type='str',
                required=True
            ),
            origin_response_timeout_seconds=dict(
                type='int',
                required=False,
                default=60
            ),
            enabled_state=dict(
                type='str',
                required=False,
                choices=['Enabled', 'Disabled'],
                default = 'Enabled'
            ),
            location=dict(
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
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            )
        )

        self.resource_group = None
        self.name = None
        self.location = None
        self.profile_name = None
        self.state = None
        self.tags = None
        self.origin_response_timeout_seconds = None
        self.enabled_state = None

        self.endpoint_client = None

        required_if = [
            # ('state', 'present', ['sku'])
        ]

        self.results = dict(changed=False)

        super(AzureRMEndpoint, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                supports_check_mode=True,
                                                supports_tags=True,
                                                required_if=required_if)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()) + ['tags']:
            setattr(self, key, kwargs[key])

        self.endpoint_client = self.get_endpoint_client()

        to_be_updated = False

        resource_group = self.get_resource_group(self.resource_group)
        if not self.location:
            self.location = resource_group.location

        response = self.get_endpoint()

        # TODO: Need to check if the endpoint name is valid and not already taken

        if self.state == 'present':

            if not response:
                self.log("Need to create the Endpoint")

                if not self.check_mode:
                    new_response = self.create_endpoint()
                    self.results['id'] = new_response['id']

                self.results['changed'] = True

            else:
                self.log('Results : {0}'.format(response))
                update_tags, response['tags'] = self.update_tags(response['tags'])

                if response['provisioning_state'] == "Succeeded":
                    if update_tags:
                        to_be_updated = True
                    if response['enabled_state'] != self.enabled_state:
                        to_be_updated = True
                    if response['origin_response_timeout_seconds'] != self.origin_response_timeout_seconds:
                        to_be_updated = True
                    
                if to_be_updated:
                    self.log("Need to update the Endpoint")

                    if not self.check_mode:
                        new_response = self.update_endpoint()
                        self.results['id'] = new_response['id']

                    self.results['changed'] = True

        elif self.state == 'absent':
            if not response:
                self.fail("Endpoint {0} does not exist.".format(self.name))
            else:
                self.log("Need to delete the Endpoint")
                self.results['changed'] = True

                if not self.check_mode:
                    self.delete_endpoint()
                    self.results['id'] = response['id']

        return self.results

    def create_endpoint(self):
        '''
        Creates a Azure Endpoint.

        :return: deserialized Azure Endpoint instance state dictionary
        '''
        self.log("Creating the Azure Endpoint instance {0}".format(self.name))

        parameters = AFDEndpoint(
            location=self.location,
            tags=self.tags,
            origin_response_timeout_seconds=self.origin_response_timeout_seconds,
            enabled_state=self.enabled_state
        )

        xid = str(uuid.uuid1())

        try:
            poller = self.endpoint_client.afd_endpoints.begin_create(self.resource_group,
                                                           self.profile_name,
                                                           self.name,
                                                           parameters)
            response = self.get_poller_result(poller)
            return endpoint_to_dict(response)
        except Exception as exc:
            self.log('Error attempting to create Azure CDN profile instance.')
            self.fail("Error Creating Azure Endpoint instance: {0}".format(exc.message))

    def update_endpoint(self):
        '''
        Updates an Azure Endpoint.

        :return: deserialized Azure Endpoint instance state dictionary
        '''
        self.log("Updating the Azure Endpoint instance {0}".format(self.name))
        parameters = AFDEndpointUpdateParameters(
            tags=self.tags,
            origin_response_timeout_seconds=self.origin_response_timeout_seconds,
            enabled_state=self.enabled
        )
        
        try:
            poller = self.endpoint_client.afd_endpoints.begin_update(resource_group_name=self.resource_group, profile_name=self.profile_name, endpoint_name=self.name, endpoint_update_properties=parameters)
            response = self.get_poller_result(poller)
            return endpoint_to_dict(response)
        except Exception as exc:
            self.log('Error attempting to update Azure Endpoint instance.')
            self.fail("Error updating Azure Endpoint instance: {0}".format(exc.message))

    def delete_endpoint(self):
        '''
        Deletes the specified Azure Endpoint in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the Endpoint {0}".format(self.name))
        try:
            poller = self.endpoint_client.afd_endpoints.begin_delete(
                self.resource_group, self.profile_name, self.name)
            self.get_poller_result(poller)
            return True
        except Exception as e:
            self.log('Error attempting to delete the Endpoint.')
            self.fail("Error deleting the Endpoint: {0}".format(e.message))
            return False

    def get_endpoint(self):
        '''
        Gets the properties of the specified Endpoint.

        :return: deserialized Endpoint state dictionary
        '''
        self.log(
            "Checking if the Endpoint {0} is present".format(self.name))
        try:
            response = self.endpoint_client.afd_endpoints.get(self.resource_group, self.profile_name, self.name)
            self.log("Response : {0}".format(response))
            self.log("Endpoint : {0} found".format(response.name))
            return endpoint_to_dict(response)
        except Exception as err:
            self.log('Did not find the Endpoint.' + err.args[0])
            return False

    def get_endpoint_client(self):
        if not self.endpoint_client:
            self.endpoint_client = self.get_mgmt_svc_client(CdnManagementClient,
                                                       base_url=self._cloud_environment.endpoints.resource_manager,
                                                       api_version='2017-04-02') # TODO: Update the API Version
        return self.endpoint_client


def main():
    """Main execution"""
    AzureRMEndpoint()
    # x = CdnManagementClient()
    # x.afd_endpoints.
    
if __name__ == '__main__':
    main()
