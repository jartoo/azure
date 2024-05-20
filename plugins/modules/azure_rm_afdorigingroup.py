#!/usr/bin/python
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_afdorigingroup
version_added: "0.1.0"
short_description: Manage an Azure Front Door OriginGroup
description:
    - Create, update and delete an Azure Front Door OriginGroup to be used by a Front Door Service Profile created using azure_rm_cdnprofile.

options:
    resource_group:
        description:
            - Name of a resource group where the CDN front door origingroup exists or will be created.
        required: true
        type: str
    name:
        description:
            - Name of the Front Door OriginGroup.
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
    from azure.mgmt.cdn.models import AFDOriginGroup, LoadBalancingSettingsParameters, HealthProbeParameters #, ResponseBasedOriginErrorDetectionParameters, ResponseBasedDetectedErrorTypes
    from azure.mgmt.cdn import CdnManagementClient
except ImportError as ec:
    # This is handled in azure_rm_common
    pass


def origingroup_to_dict(origingroup):
    return dict(
        additional_latency_in_milliseconds = origingroup.load_balancing_settings.additional_latency_in_milliseconds,
        deployment_status = origingroup.deployment_status,
        id = origingroup.id,
        name=origingroup.name,
        probe_interval_in_seconds = origingroup.health_probe_settings.probe_interval_in_seconds,
        probe_path = origingroup.health_probe_settings.probe_path,
        probe_protocol = origingroup.health_probe_settings.probe_protocol,
        probe_request_type = origingroup.health_probe_settings.probe_request_type,
        provisioning_state=origingroup.provisioning_state,
        sample_size = origingroup.load_balancing_settings.sample_size,
        session_affinity_state=origingroup.session_affinity_state,
        successful_samples_required = origingroup.load_balancing_settings.successful_samples_required,
        traffic_restoration_time_to_healed_or_new_endpoints_in_minutes = origingroup.traffic_restoration_time_to_healed_or_new_endpoints_in_minutes,
        type=origingroup.type
    )


class AzureRMOriginGroup(AzureRMModuleBase):

    def __init__(self):
        self.module_arg_spec = dict(
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
            sample_size=dict(
                type='int',
                required=False
            ),
            successful_samples_required=dict(
                type='int',
                required=False
            ),
            additional_latency_in_milliseconds=dict(
                type='int',
                required=False
            ),
            probe_path=dict(
                type='str',
                required=False
            ),
            probe_request_type=dict(
                type='str',
                required=False,
                choices=['GET', 'HEAD', 'NOT_SET']
            ),
            probe_protocol=dict(
                type='str',
                required=False,
                choices=['Http', 'Https', 'NotSet']
            ),
            probe_interval_in_seconds=dict(
                type='int',
                required=False
            ),
            session_affinity_state=dict(
                type='str',
                required=False,
                choices=['Enabled', 'Disabled']
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            ),
            traffic_restoration_time_to_healed_or_new_endpoints_in_minutes=dict(
                type='int',
                required=False
            )
        )
        self.sample_size = None
        self.successful_samples_required = None
        self.additional_latency_in_milliseconds = None
        self.probe_path = None
        self.probe_request_type = None
        self.probe_protocol = None
        self.probe_interval_in_seconds = None
        self.traffic_restoration_time_to_healed_or_new_endpoints_in_minutes = None
        self.session_affinity_state = None

        self.resource_group = None
        self.name = None
        self.profile_name = None
        self.state = None

        self.origingroup_client = None

        required_if = [
            # ('state', 'present', ['sku']) # TODO: Flesh these out
        ]

        self.results = dict(changed=False)

        super(AzureRMOriginGroup, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                supports_check_mode=True,
                                                supports_tags=False,
                                                required_if=required_if)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        self.origingroup_client = self.get_origingroup_client()

        to_be_updated = False

        # Do not need the resource group location
        # resource_group = self.get_resource_group(self.resource_group)
        # if not self.location:
        #     self.location = resource_group.location

        response = self.get_origingroup()

        if self.state == 'present':

            if not response:
                self.log("Need to create the OriginGroup")

                if not self.check_mode:
                    new_response = self.create_origingroup()
                    self.results['id'] = new_response['id']

                self.results['changed'] = True

            else:
                self.log('Results : {0}'.format(response))
                
                if response['probe_path'] != self.probe_path and self.probe_path:
                    to_be_updated = True
                if response['sample_size'] != self.sample_size and self.sample_size:
                    to_be_updated = True
                if response['successful_samples_required'] != self.successful_samples_required and self.successful_samples_required:
                    to_be_updated = True
                if response['additional_latency_in_milliseconds'] != self.additional_latency_in_milliseconds and self.additional_latency_in_milliseconds:
                    to_be_updated = True
                if response['probe_request_type'] != self.probe_request_type and self.probe_request_type:
                    to_be_updated = True
                if response['probe_protocol'] != self.probe_protocol and self.probe_protocol:
                    to_be_updated = True
                if response['probe_interval_in_seconds'] != self.probe_interval_in_seconds and self.probe_interval_in_seconds:
                    to_be_updated = True
                if response['traffic_restoration_time_to_healed_or_new_endpoints_in_minutes'] != self.traffic_restoration_time_to_healed_or_new_endpoints_in_minutes and self.traffic_restoration_time_to_healed_or_new_endpoints_in_minutes:
                    to_be_updated = True
                if response['session_affinity_state'] != self.session_affinity_state and self.session_affinity_state:
                    to_be_updated = True
                    
                if to_be_updated:
                    self.log("Need to update the OriginGroup")

                    if not self.check_mode:
                        new_response = self.update_origingroup()
                        self.results['id'] = new_response['id']

                    self.results['changed'] = True

        elif self.state == 'absent':
            if not response:
                self.fail("OriginGroup {0} does not exist.".format(self.name))
            else:
                self.log("Need to delete the OriginGroup")
                self.results['changed'] = True

                if not self.check_mode:
                    self.delete_origingroup()
                    self.results['id'] = response['id']

        return self.results

    def create_origingroup(self):
        '''
        Creates a Azure OriginGroup.

        :return: deserialized Azure OriginGroup instance state dictionary
        '''
        self.log("Creating the Azure OriginGroup instance {0}".format(self.name))

        loadbalancingsettings = LoadBalancingSettingsParameters(
            sample_size = self.sample_size,
            successful_samples_required = self.successful_samples_required,
            additional_latency_in_milliseconds = self.additional_latency_in_milliseconds
        )

        # responsebaseddetectionerrortypes = 
        # responsebasedfailoverthresholdpercentage = ''

        # responsebasedoriginerrordetectionparameter = ResponseBasedOriginErrorDetectionParameters(
        #     response_based_detected_error_types=responsebaseddetectionerrortypes,
        #     response_based_failover_threshold_percentage=responsebasedfailoverthresholdpercentage,
        #     http_error_ranges=self.http_error_ranges
        # )

        healthprobesettings = HealthProbeParameters(
            probe_path=self.probe_path,
            probe_request_type=self.probe_request_type,
            probe_protocol=self.probe_protocol,
            probe_interval_in_seconds=self.probe_interval_in_seconds
        )

        parameters = AFDOriginGroup(
            load_balancing_settings=loadbalancingsettings,
            health_probe_settings=healthprobesettings
            # traffic_restoration_time_to_healed_or_new_endpoints_in_minutes=self.traffic_restoration_time_to_healed_or_new_endpoints_in_minutes,
            # response_based_afd_origin_error_detection_settings=responsebasedoriginerrordetectionparameter
        )

        try:
            poller = self.origingroup_client.afd_origin_groups.begin_create(self.resource_group,
                                                           self.profile_name,
                                                           self.name,
                                                           parameters)
            response = self.get_poller_result(poller)
            return origingroup_to_dict(response)
        except Exception as exc:
            self.log('Error attempting to create Azure OriginGroup instance.')
            self.fail("Error Creating Azure OriginGroup instance: {0}".format(exc.message))

    def update_origingroup(self):
        '''
        Updates an Azure OriginGroup.

        :return: deserialized Azure OriginGroup instance state dictionary
        '''
        self.log("Updating the Azure OriginGroup instance {0}".format(self.name))

        loadbalancingsettings = LoadBalancingSettingsParameters(
            sample_size = self.sample_size,
            successful_samples_required = self.successful_samples_required,
            additional_latency_in_milliseconds = self.additional_latency_in_milliseconds
        )

        healthprobesettings = HealthProbeParameters(
            probe_path=self.probe_path,
            probe_request_type=self.probe_request_type,
            probe_protocol=self.probe_protocol,
            probe_interval_in_seconds=self.probe_interval_in_seconds
        )

        parameters = AFDOriginGroup(
            load_balancing_settings=loadbalancingsettings,
            health_probe_settings=healthprobesettings
            # traffic_restoration_time_to_healed_or_new_endpoints_in_minutes=self.traffic_restoration_time_to_healed_or_new_endpoints_in_minutes,
            # response_based_afd_origin_error_detection_settings=responsebasedoriginerrordetectionparameter
        )
        
        try:
            poller = self.origingroup_client.afd_origin_groups.begin_update(resource_group_name=self.resource_group, profile_name=self.profile_name, origin_group_name=self.name, origin_group_update_properties=parameters)
            response = self.get_poller_result(poller)
            return origingroup_to_dict(response)
        except Exception as exc:
            self.log('Error attempting to update Azure OriginGroup instance.')
            self.fail("Error updating Azure OriginGroup instance: {0}".format(exc.message))

    def delete_origingroup(self):
        '''
        Deletes the specified Azure OriginGroup in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the OriginGroup {0}".format(self.name))
        try:
            poller = self.origingroup_client.afd_origin_groups.begin_delete(
                self.resource_group, self.profile_name, self.name)
            self.get_poller_result(poller)
            return True
        except Exception as e:
            self.log('Error attempting to delete the OriginGroup.')
            self.fail("Error deleting the OriginGroup: {0}".format(e.message))
            return False

    def get_origingroup(self):
        '''
        Gets the properties of the specified OriginGroup.

        :return: deserialized OriginGroup state dictionary
        '''
        self.log(
            "Checking if the OriginGroup {0} is present".format(self.name))
        try:
            response = self.origingroup_client.afd_origin_groups.get(self.resource_group, self.profile_name, self.name)
            self.log("Response : {0}".format(response))
            self.log("OriginGroup : {0} found".format(response.name))
            return origingroup_to_dict(response)
        except Exception as err:
            self.log('Did not find the OriginGroup.' + err.args[0])
            return False

    def get_origingroup_client(self):
        if not self.origingroup_client:
            self.origingroup_client = self.get_mgmt_svc_client(CdnManagementClient,
                                                       base_url=self._cloud_environment.endpoints.resource_manager,
                                                       api_version='2023-05-01')
        return self.origingroup_client


def main():
    """Main execution"""
    AzureRMOriginGroup()
    # x = CdnManagementClient()
    # x.afd_origin_groups.
    # y = AFDOriginGroup()

if __name__ == '__main__':
    main()
