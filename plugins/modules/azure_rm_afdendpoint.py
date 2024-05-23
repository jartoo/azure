#!/usr/bin/python
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# Python SDK Reference: https://learn.microsoft.com/en-us/python/api/azure-mgmt-cdn/azure.mgmt.cdn.operations.afdendpointsoperations?view=azure-python
# TODO: Add host_name to the returned results
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_afdendpoint

version_added: ""

short_description: Manage an Azure Front Door Endpoint to be used with Standard or Premium Frontdoor

description:
    - Create, update and delete an Azure Front Door (AFD) Endpoint to be used by a Front Door Service Profile created using azure_rm_cdnprofile.  This differs from the Front Door classic service and only is intended to be used by the Standard or Premium service offering.

options:
    resource_group:
        description:
            - Name of a resource group where the Azure Front Door Endpoint exists or will be created.
        required: true
        type: str
    name:
        description:
            - Name of the AFD Endpoint.
        required: true
        type: str
    location:
        description:
            - Valid Azure location. Defaults to location of the resource group.
        required: true
        type: str
    profile_name:
        description:
            - Name of the AFD Profile where the Endpoint will be attached to.
        required: true
        type: str
    state:
        description:
            - Assert the state of the AFD Endpoint. Use C(present) to create or update an AFD Endpoint and C(absent) to delete it.
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
- name: Create an AFD Endpoint
  azure_rm_afdendpoint:
    name: myEndpoint
    profile_name: myProfile
    resource_group: myResourceGroup
    state: present
    tags:
      testing: testing

- name: Delete the AFD Endpoint
  azure_rm_afdendpoint:
    name: myCDN
    profile_name: myProfile
    resource_group: myResourceGroup
    state: absent
'''
RETURN = '''
id:
    description:
        - ID of the AFD Endpoint.
    returned: always
    type: str
    sample: "id: /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourcegroups/myResourceGroup/providers/Microsoft.Cdn/profiles/myProfile/endpoints/myEndpoint"
host_name:
    description:
        - Host name of the AFD Endpoint.
    returned: always
    type: str
    sample: "myendpoint.azurefd.net"
state:
    description: Current state of the AFD Endpoint.
    returned: always
    type: str

'''
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

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
                default=60
            ),
            enabled_state=dict(
                type='str',
                default = 'Enabled',
                choices=['Enabled', 'Disabled']
            ),
            location=dict(
                type='str'
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

        self.results = dict(changed=False)

        super(AzureRMEndpoint, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                supports_check_mode=True,
                                                supports_tags=True)

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
                self.log("Need to create the AFD Endpoint")

                if not self.check_mode:
                    new_response = self.create_endpoint()
                    self.results['id'] = new_response['id']
                    self.results['host_name'] = new_response['host_name']
                    self.log("AFD Endpoint creation done")

                self.results['changed'] = True
                return self.results
            
            else:
                self.log('Results : {0}'.format(response))
                self.results['id'] = response['id']                
                self.results['host_name'] = response['host_name']
                
                update_tags, response['tags'] = self.update_tags(response['tags'])

                if update_tags:
                    to_be_updated = True

                if response['provisioning_state'] == "Succeeded":
                    if response['enabled_state'] != self.enabled_state:
                        to_be_updated = True
                    if response['origin_response_timeout_seconds'] != self.origin_response_timeout_seconds:
                        to_be_updated = True
                    
                    if to_be_updated:
                        self.log("Need to update the AFD Endpoint")
                        self.results['changed'] = True

                        if not self.check_mode:
                            result = self.update_endpoint()
                            self.results['host_name'] = result['host_name']
                            self.log("AFD Endpoint update done")    

        elif self.state == 'absent':
            if not response:
                self.log("AFD Endpoint {0} does not exist.".format(self.name))
            else:
                self.log("Need to delete the AFD Endpoint")
                self.results['changed'] = True

                if not self.check_mode:
                    self.delete_endpoint()
                    self.results['id'] = response['id']
                    self.log("Azure AFD Endpoint deleted")

        return self.results

    def create_endpoint(self):
        '''
        Creates an AFD Endpoint.

        :return: deserialized AFD Endpoint instance state dictionary
        '''
        self.log("Creating the AFD Endpoint instance {0}".format(self.name))

        parameters = AFDEndpoint(
            location=self.location,
            tags=self.tags,
            origin_response_timeout_seconds=self.origin_response_timeout_seconds,
            enabled_state=self.enabled_state
        )

        try:
            poller = self.endpoint_client.afd_endpoints.begin_create(self.resource_group,
                                                           self.profile_name,
                                                           self.name,
                                                           parameters)
            response = self.get_poller_result(poller)
            return endpoint_to_dict(response)
        except Exception as exc:
            self.log('Error attempting to create AFD Endpoint instance.')
            self.fail("Error Creating AFD Endpoint instance: {0}".format(exc.message))

    def update_endpoint(self):
        '''
        Updates an AFD Endpoint.

        :return: deserialized AFD Endpoint instance state dictionary
        '''
        self.log("Updating the AFD Endpoint instance {0}".format(self.name))

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
            self.log('Error attempting to update AFD Endpoint instance.')
            self.fail("Error updating AFD Endpoint instance: {0}".format(exc.message))

    def delete_endpoint(self):
        '''
        Deletes the specified AFD Endpoint in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the AFD Endpoint {0}".format(self.name))
        try:
            poller = self.endpoint_client.afd_endpoints.begin_delete(
                resource_group_name=self.resource_group, profile_name=self.profile_name, endpoint_name=self.name)
            self.get_poller_result(poller)
            return True
        except Exception as e:
            self.log('Error attempting to delete the AFD Endpoint.')
            self.fail("Error deleting the AFD Endpoint: {0}".format(e.message))
            return False

    def get_endpoint(self):
        '''
        Gets the properties of the specified AFD Endpoint.

        :return: deserialized AFD Endpoint state dictionary
        '''
        self.log(
            "Checking if the AFD Endpoint {0} is present".format(self.name))
        try:
            response = self.endpoint_client.afd_endpoints.get(resource_group_name=self.resource_group, profile_name=self.profile_name, endpoint_name=self.name)
            self.log("Response : {0}".format(response))
            self.log("AFD Endpoint : {0} found".format(response.name))
            return endpoint_to_dict(response)
        except Exception as err:
            self.log('Did not find the AFD Endpoint.')
            return False

    def get_endpoint_client(self):
        if not self.endpoint_client:
            self.endpoint_client = self.get_mgmt_svc_client(CdnManagementClient,
                                                       base_url=self._cloud_environment.endpoints.resource_manager,
                                                       api_version='2023-05-01')
        return self.endpoint_client


def main():
    """Main execution"""
    AzureRMEndpoint()
    
if __name__ == '__main__':
    main()
