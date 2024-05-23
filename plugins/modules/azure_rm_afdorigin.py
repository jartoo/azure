#!/usr/bin/python
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_afdorigin
version_added: "0.1.0"
short_description: Manage an Azure Front Door Origin
description:
    - Create, update and delete an Azure Front Door Origin to be used by a Front Door Service Profile created using azure_rm_cdnprofile.

options:
    resource_group:
        description:
            - Name of a resource group where the CDN front door origin exists or will be created.
        required: true
        type: str
    name:
        description:
            - Name of the Front Door Origin.
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
    from azure.mgmt.cdn.models import AFDOrigin, AFDOriginUpdateParameters 
    from azure.mgmt.cdn import CdnManagementClient
except ImportError as ec:
    # This is handled in azure_rm_common
    pass

def origin_to_dict(origin):
    return dict(
        deployment_status=origin.deployment_status,
        enabled_state = origin.enabled_state,
        host_name = origin.host_name,
        http_port = origin.http_port,
        https_port = origin.https_port,
        id = origin.id,
        name=origin.name,
        origin_host_header=origin.origin_host_header,
        priority=origin.priority,
        provisioning_state=origin.provisioning_state,
        shared_private_link_resource=origin.shared_private_link_resource,
        type=origin.type,
        weight=origin.weight
    )


class AzureRMOrigin(AzureRMModuleBase):

    def __init__(self):
        self.module_arg_spec = dict(
            enabled_state=dict(
                type='str',
                required=False
            ),
            group_id=dict(
                type='str',
                required=False
            ),
            host_name=dict(
                type='str',
                required=False
            ),
            http_port=dict(
                type='int',
                default=80,
                required=False
            ),
            https_port=dict(
                type='int',
                default=443,
                required=False
            ),
            name=dict(
                type='str',
                required=True
            ),
            private_link_id=dict(
                type='str',
                required=False
            ),
            private_link_location=dict( # TODO: Test the private link setup and connection
                type='str',
                required=False
            ),
            origin_group_name=dict(
                type='str',
                required=True
            ),
            origin_host_header=dict(
                type='str',
                required=False
            ),
            priority=dict(
                type='int',
                required=False
            ),
            profile_name=dict(
                type='str',
                required=False
            ),
            request_message=dict(
                type='str',
                required=False
            ),
            resource_group=dict(
                type='str',
                required=True
            ),
            resource_reference_id=dict(
                type='str',
                required=False
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent'],
                required=False
            ),
            status=dict(
                type='str',
                default='Approved',
                choices=["Pending", "Approved", "Rejected", "Disconnected", "Timeout"],
                required=False
            ),
            weight=dict(
                type='int',
                required=False
            )
        )
        self.resource_reference_id = None
        self.private_link_id = None
        self.private_link_location = None
        self.host_name = None
        self.http_port = None
        self.https_port = None
        self.origin_host_header = None
        self.priority = None
        self.weight = None
        self.enabled_state = None
        self.group_id = None
        self.request_message = None
        self.status = None

        self.resource_group = None
        self.origin_group_name = None
        self.name = None
        self.profile_name = None
        self.state = None

        self.origin_client = None

        required_if = [
            ('state', 'present', ['host_name']) # TODO: Flesh these out
        ]

        self.results = dict(changed=False)

        super(AzureRMOrigin, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                supports_check_mode=True,
                                                supports_tags=False,
                                                required_if=required_if)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        self.origin_client = self.get_origin_client()

        to_be_updated = False

        # Do not need the resource group location
        # resource_group = self.get_resource_group(self.resource_group)
        # if not self.location:
        #     self.location = resource_group.location

        response = self.get_origin()

        if self.state == 'present':

            if not response:
                self.log("Need to create the Origin")

                if not self.check_mode:
                    new_response = self.create_origin()
                    self.results['id'] = new_response['id']

                self.results['changed'] = True

            else:
                self.log('Results : {0}'.format(response))
                
                if response['host_name'] != self.host_name and self.host_name:
                    to_be_updated = True
                if response['http_port'] != self.http_port and self.http_port:
                    to_be_updated = True
                if response['https_port'] != self.https_port and self.https_port:
                    to_be_updated = True
                if response['origin_host_header'] != self.origin_host_header and self.origin_host_header:
                    to_be_updated = True
                if response['priority'] != self.priority and self.priority:
                    to_be_updated = True
                if response['weight'] != self.weight and self.weight:
                    to_be_updated = True
                if response['enabled_state'] != self.enabled_state and self.enabled_state:
                    to_be_updated = True
                if response['enabled_state'] != self.enabled_state and self.enabled_state:
                    to_be_updated = True
                    
                if to_be_updated:
                    self.log("Need to update the Origin")

                    if not self.check_mode:
                        new_response = self.update_origin()
                        self.results['id'] = new_response['id']

                    self.results['changed'] = True

        elif self.state == 'absent':
            if not response:
                self.fail("Origin {0} does not exist.".format(self.name))
            else:
                self.log("Need to delete the Origin")
                self.results['changed'] = True

                if not self.check_mode:
                    self.delete_origin()
                    self.results['id'] = response['id']

        return self.results

    def create_origin(self):
        '''
        Creates a Azure Origin.

        :return: deserialized Azure Origin instance state dictionary
        '''
        self.log("Creating the Azure Origin instance {0}".format(self.name))

        parameters = AFDOrigin(
            host_name=self.host_name,
            http_port=self.http_port,
            https_port=self.https_port,
            origin_host_header=self.origin_host_header,
            priority=self.priority,
            weight=self.weight,
            enabled_state=self.enabled_state
        )

        try:
            poller = self.origin_client.afd_origins.begin_create(self.resource_group,
                                                           self.profile_name,
                                                           self.origin_group_name,
                                                           self.name,
                                                           parameters)
            response = self.get_poller_result(poller)
            return origin_to_dict(response)
        except Exception as exc:
            self.log('Error attempting to create Azure Origin instance.')
            self.fail("Error Creating Azure Origin instance: {0}".format(exc.message))

    def update_origin(self):
        '''
        Updates an Azure Origin.

        :return: deserialized Azure Origin instance state dictionary
        '''
        self.log("Updating the Azure Origin instance {0}".format(self.name))

        parameters = AFDOriginUpdateParameters(
            host_name=self.host_name,
            http_port=self.http_port,
            https_port=self.https_port,
            origin_host_header=self.origin_host_header,
            priority=self.priority,
            weight=self.weight,
            enabled_state=self.enabled_state
        )
        
        try:
            poller = self.origin_client.afd_origins.begin_update(resource_group_name=self.resource_group, profile_name=self.profile_name, origin_group_name=self.origin_group_name, origin_name=self.name, origin_update_properties=parameters)
            response = self.get_poller_result(poller)
            return origin_to_dict(response)
        except Exception as exc:
            self.log('Error attempting to update Azure Origin instance.')
            self.fail("Error updating Azure Origin instance: {0}".format(exc.message))

    def delete_origin(self):
        '''
        Deletes the specified Azure Origin in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the Origin {0}".format(self.name))
        try:
            poller = self.origin_client.afd_origins.begin_delete(self.resource_group, self.profile_name, self.origin_group_name, self.name)
            self.get_poller_result(poller)
            return True
        except Exception as e:
            self.log('Error attempting to delete the Origin.')
            self.fail("Error deleting the Origin: {0}".format(e.message))
            return False

    def get_origin(self):
        '''
        Gets the properties of the specified Origin.

        :return: deserialized Origin state dictionary
        '''
        self.log(
            "Checking if the Origin {0} is present".format(self.name))
        try:
            response = self.origin_client.afd_origins.get(self.resource_group, self.profile_name, self.origin_group_name, self.name)
            self.log("Response : {0}".format(response))
            self.log("Origin : {0} found".format(response.name))
            return origin_to_dict(response)
        except Exception as err:
            self.log('Did not find the Origin.' + err.args[0])
            return False

    def get_origin_client(self):
        if not self.origin_client:
            self.origin_client = self.get_mgmt_svc_client(CdnManagementClient,
                                                       base_url=self._cloud_environment.endpoints.resource_manager,
                                                       api_version='2023-05-01')
        return self.origin_client


def main():
    """Main execution"""
    AzureRMOrigin()
    # x = CdnManagementClient()
    # x.afd_origins.begin_create()
    # y = AFDOrigin()

if __name__ == '__main__':
    main()
