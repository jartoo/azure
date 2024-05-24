#!/usr/bin/python
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Python SDK Reference: https://learn.microsoft.com/en-us/python/api/azure-mgmt-cdn/azure.mgmt.cdn.operations.afdoriginsoperations?view=azure-python
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_afdorigin
version_added: ""
short_description: Manage an Azure Front Door Origin to be used with Standard or Premium Frontdoor.
description:
    - Create, update and delete an Azure Front Door (AFD) Origin to be used by a Front Door Service Profile created using azure_rm_cdnprofile.

options:
    name:
        description:
            - Name of the origin that is unique within the AFD Profile.
        required: true
        type: str
    origin:
        description:
            - AFD Origin properties
        type: dict
        suboptions:
            azure_origin:
                description:
                    - Resource reference to the AFD origin resource.
                type: str
            enabled_state:
                description:
                    - Whether to enable health probes to be made against backends defined under backend pools. Health probes can only be disabled if there is a single enabled backend in single enabled backend pool.
                type: str
                choices:
                    - Enabled
                    - Disabled
            host_name:
                description:
                    - The address of the origin. Domain names, IPv4 addresses, and IPv6 addresses are supported. This should be unique across all origins in an endpoint.
                type: str
            http_port:
                description:
                    - The value of the HTTP port. Must be between 1 and 65535.
                default: 80
                type: int
            https_port:
                description:
                    - The value of the HTTPS port. Must be between 1 and 65535.
                default: 443
                type: int
            origin_host_header:
                description:
                    - The host header value sent to the origin with each request. If you leave this blank, the request hostname determines this value. Azure Front Door origins, such as Web Apps, Blob Storage, and Cloud Services require this host header value to match the origin hostname by default. This overrides the host header defined at the AFD Endpoint.
                type: str
            priority:
                description:
                    - Priority of origin in given origin group for load balancing. Higher priorities will not be used for load balancing if any lower priority origin is healthy. Must be between 1 and 5.
                type: int
            shared_private_link_resource:
                description:
                    - The number of samples within the sample period that must succeed.
                type: dict
                suboptions:
                    group_id:
                        description:
                            - The group id from the provider of resource the shared private link resource is for.
                        type: str
                    private_link:
                        description:
                            - The resource id of the resource the shared private link resource is for.
                        type: str
                    private_link_location:
                        description:
                            - The location of the shared private link resource.
                        type: str
                    request_message:
                        description:
                            - The request message for requesting approval of the shared private link resource.
                        type: str
                    status:
                        description:
                            - Status of the shared private link resource. Can be Pending, Approved, Rejected, Disconnected, or Timeout.
                        type: str
                        choices:
                            - Approved
                            - Disconnected
                            - Pending
                            - Rejected
                            - Timeout
            weight:
                description:
                    - Weight of the origin in given origin group for load balancing. Must be between 1 and 1000.
                type: int
    origin_group_name:
        description:
            - Name of the origin group which is unique within the profile.
        required: true
        type: str
    profile_name:
        description:
            - Name of the AFD Profile.
        required: true
        type: str
    resource_group_name:
        description:
            - Name of a resource group where the AFD Origin exists or will be created.
        required: true
        type: str
    state:
        description:
            - Assert the state of the AFD Profile. Use C(present) to create or update an AFD profile and C(absent) to delete it.
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
        - ID of the AFD Origin.
    returned: always
    type: str
    sample: "id: /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourcegroups/myResourceGroup/providers/Microsoft.Cdn/profiles/myProfile/origingroups/myOriginGroup/origins/myOrigin"
host_name:
    description:
        - Host name of the AFD Origin.
    returned: always
    type: str
    sample: "myorigin.azurefd.net"

'''
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from azure.mgmt.cdn.models import AFDOrigin, AFDOriginUpdateParameters, SharedPrivateLinkResourceProperties
    from azure.mgmt.cdn import CdnManagementClient
except ImportError as ec:
    # This is handled in azure_rm_common
    pass

def origin_to_dict(origin):
    return dict(
        azure_origin=origin.azure_origin,
        deployment_status=origin.deployment_status,
        enabled_state = origin.enabled_state,
        # enforce_certificate_check = origin.enforce_certificate_check, # Not fully implemented yet
        host_name = origin.host_name,
        http_port = origin.http_port,
        https_port = origin.https_port,
        id = origin.id,
        name=origin.name,
        origin_group_name=origin.origin_group_name,
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
            name=dict(
                type='str',
                required=True
            ),
            origin=dict(
                type='dict',
                options=dict(
                    azure_origin=dict(type='str'),
                    enabled_state=dict(type='str'),
                    enforce_certification_name_check=dict(type='bool'),
                    host_name=dict(type='str'),
                    http_port=dict(type='int',default=80),
                    https_port=dict(type='int',default=443),
                    origin_host_header=dict(type='str'),
                    priority=dict(type='int'),
                    shared_private_link_resource=dict(
                        type='dict',
                        options=dict(
                            group_id=dict(type='str'),
                            private_link=dict(type='str'),
                            private_link_location=dict(type='str'),
                            request_message=dict(type='str'),
                            status=dict(type='str',default='Approved',choices=["Pending", "Approved", "Rejected", "Disconnected", "Timeout"])
                        )
                    ),
                    weight=dict(type='int')
                )
            ),
            origin_group_name=dict(
                type='str',
                required=True
            ),
            profile_name=dict(
                type='str',
                required=True
            ),
            resource_group_name=dict(
                type='str',
                required=True
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            )
        )
        self.origin = None

        self.origin_group_name = None
        self.name = None
        self.profile_name = None
        self.resource_group_name = None
        self.state = None

        self.origin_client = None

        required_if = [
            # ('state', 'present', ['host_name']) # TODO: Flesh these out
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

        response = self.get_origin()

        if self.state == 'present':

            if not response:
                self.log("Need to create the Origin")

                if not self.check_mode:
                    new_response = self.create_origin()
                    self.results['id'] = new_response['id']
                    self.results['host_name'] = new_response['host_name']

                self.results['changed'] = True

            else:
                self.log('Results : {0}'.format(response))
                self.results['id'] = response['id']
                self.results['host_name'] = response['host_name']

                if response['host_name'] != self.origin['host_name'] and self.origin['host_name']:
                    to_be_updated = True
                if response['http_port'] != self.origin['http_port'] and self.origin['http_port']:
                    to_be_updated = True
                if response['https_port'] != self.origin['https_port'] and self.origin['https_port']:
                    to_be_updated = True
                if response['origin_host_header'] != self.origin['origin_host_header'] and self.origin['origin_host_header']:
                    to_be_updated = True
                if response['priority'] != self.origin['priority'] and self.origin['priority']:
                    to_be_updated = True
                if response['weight'] != self.origin['weight'] and self.origin['weight']:
                    to_be_updated = True
                if response['enabled_state'] != self.origin['enabled_state'] and self.origin['enabled_state']:
                    to_be_updated = True
                # if response['enforce_certificate_name_check'] != self.origin['enforce_certificate_name_check'] and self.origin['enforce_certificate_name_check']:
                #     to_be_updated = True
                if response['shared_private_link_resource']:
                    if response['shared_private_link_resource']['group_id'] != self.origin['shared_private_link_resource']['group_id'] and self.origin['shared_private_link_resource']['group_id']:
                        to_be_updated = True
                    if response['shared_private_link_resource']['private_link'] != self.origin['shared_private_link_resource']['private_link'] and self.origin['shared_private_link_resource']['private_link']:
                        to_be_updated = True
                    if response['shared_private_link_resource']['private_link_location'] != self.origin['shared_private_link_resource']['private_link_location'] and self.origin['shared_private_link_resource']['private_link_location']:
                        to_be_updated = True
                    if response['shared_private_link_resource']['request_message'] != self.origin['shared_private_link_resource']['request_message'] and self.origin['shared_private_link_resource']['request_message']:
                        to_be_updated = True
                    if response['shared_private_link_resource']['status'] != self.origin['shared_private_link_resource']['status'] and self.origin['shared_private_link_resource']['status']:
                        to_be_updated = True
                    
                if to_be_updated:
                    self.log("Need to update the Origin")

                    if not self.check_mode:
                        new_response = self.update_origin()
                        self.results['id'] = new_response['id']
                        self.results['host_name'] = new_response['host_name']

                    self.results['changed'] = True

        elif self.state == 'absent':
            if not response:
                self.log("Origin {0} does not exist.".format(self.name))
                self.results['id'] = ""
                self.results['host_name'] = ""
            else:
                self.log("Need to delete the Origin")
                self.results['changed'] = True
                self.results['id'] = response['id']
                self.results['host_name'] = response['host_name']

                if not self.check_mode:
                    self.delete_origin()

        return self.results

    def create_origin(self):
        '''
        Creates a Azure Origin.

        :return: deserialized Azure Origin instance state dictionary
        '''
        self.log("Creating the Azure Origin instance {0}".format(self.name))

        shared_private_link_resource = None
        if self.origin['shared_private_link_resource']:
            shared_private_link_resource = SharedPrivateLinkResourceProperties(
                group_id=self.origin['shared_private_link_resource']['group_id'],
                private_link=self.origin['shared_private_link_resource']['private_link'],
                private_link_location=self.origin['shared_private_link_resource']['private_link_location'],
                request_message=self.origin['shared_private_link_resource']['request_message'],
                status=self.origin['shared_private_link_resource']['status']
            )

        parameters = AFDOrigin(
            azure_origin=self.origin['azure_origin'],
            host_name=self.origin['host_name'],
            http_port=self.origin['http_port'],
            https_port=self.origin['https_port'],
            origin_host_header=self.origin['origin_host_header'],
            priority=self.origin['priority'],
            weight=self.origin['weight'],
            enabled_state=self.origin['enabled_state'],
            shared_private_link_resource=shared_private_link_resource
        )

        try:
            poller = self.origin_client.afd_origins.begin_create(resource_group_name=self.resource_group_name,
                profile_name=self.profile_name,
                origin_group_name=self.origin_group_name,
                origin_name=self.name,
                origin=parameters)
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

        shared_private_link_resource = None
        if self.origin['shared_private_link_resource']:
            shared_private_link_resource = SharedPrivateLinkResourceProperties(
                group_id=self.origin['shared_private_link_resource']['group_id'],
                private_link=self.origin['shared_private_link_resource']['private_link'],
                private_link_location=self.origin['shared_private_link_resource']['private_link_location'],
                request_message=self.origin['shared_private_link_resource']['request_message'],
                status=self.origin['shared_private_link_resource']['status']
            )

        parameters = AFDOriginUpdateParameters(
            azure_origin=self.origin['azure_origin'],
            host_name=self.origin['host_name'],
            http_port=self.origin['http_port'],
            https_port=self.origin['https_port'],
            origin_host_header=self.origin['origin_host_header'],
            priority=self.origin['priority'],
            weight=self.origin['weight'],
            enabled_state=self.origin['enabled_state'],
            shared_private_link_resource=shared_private_link_resource
        )
# enforce_certificate_name_check
        
        try:
            poller = self.origin_client.afd_origins.begin_update(resource_group_name=self.resource_group_name,
                profile_name=self.profile_name,
                origin_group_name=self.origin_group_name,
                origin_name=self.name,
                origin_update_properties=parameters)
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
            poller = self.origin_client.afd_origins.begin_delete(resource_group_name=self.resource_group_name,
                profile_name=self.profile_name,
                origin_group_name=self.origin_group_name,
                origin_name=self.name)
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
            response = self.origin_client.afd_origins.get(resource_group_name=self.resource_group_name,
                profile_name=self.profile_name,
                origin_group_name=self.origin_group_name,
                origin_name=self.name)
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
