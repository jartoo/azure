#!/usr/bin/python
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: azure_rm_afdruleset
version_added: "0.1.0"
short_description: Manage an Azure Front Door Rule Set
description:
    - Create, update and delete an Azure Front Door Rule Set to be used by a Front Door Service Profile created using azure_rm_cdnprofile.

options:
    resource_group:
        description:
            - Name of a resource group where the CDN front door ruleset exists or will be created.
        required: true
        type: str
    name:
        description:
            - Name of the Front Door Rule Set.
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
    from azure.mgmt.cdn.models import RuleSet
    from azure.mgmt.cdn import CdnManagementClient
except ImportError as ec:
    # This is handled in azure_rm_common
    pass

def ruleset_to_dict(ruleset):
    return dict(
        deployment_status = ruleset.deployment_status,
        id = ruleset.id,
        name = ruleset.name,
        provisioning_state = ruleset.provisioning_state,
        type=ruleset.type
    )


class AzureRMRuleSet(AzureRMModuleBase):

    def __init__(self):
        self.module_arg_spec = dict(
            name=dict(
                type='str',
                required=True
            ),
            profile_name=dict(
                type='str',
                required=False
            ),
            resource_group=dict(
                type='str',
                required=True
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent'],
                required=False
            )
        )

        self.resource_group = None
        self.name = None
        self.profile_name = None
        self.state = None

        self.ruleset_client = None

        required_if = [
            # ('state', 'present', ['host_name']) # TODO: Flesh these out
        ]

        self.results = dict(changed=False)

        super(AzureRMRuleSet, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                supports_check_mode=True,
                                                supports_tags=False,
                                                required_if=required_if)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            setattr(self, key, kwargs[key])

        self.ruleset_client = self.get_ruleset_client()

        response = self.get_ruleset()

        if self.state == 'present':

            if not response:
                self.log("Need to create the Rule Set")

                if not self.check_mode:
                    new_response = self.create_ruleset()
                    self.results['id'] = new_response['id']

                self.results['changed'] = True

            else:
                self.log('Results : {0}'.format(response))

        elif self.state == 'absent':
            if not response:
                self.fail("Rule Set {0} does not exist.".format(self.name))
            else:
                self.log("Need to delete the Rule Set")
                self.results['changed'] = True

                if not self.check_mode:
                    self.delete_ruleset()
                    self.results['id'] = response['id']

        return self.results

    def create_ruleset(self):
        '''
        Creates a Azure Rule Set.

        :return: deserialized Azure Rule Set instance state dictionary
        '''
        self.log("Creating the Azure Rule Set instance {0}".format(self.name))

        try:
            poller = self.ruleset_client.rule_sets.begin_create(
                resource_group_name=self.resource_group,
                profile_name=self.profile_name,
                rule_set_name=self.name
            )
            response = self.get_poller_result(poller)
            return ruleset_to_dict(response)
        except Exception as exc:
            self.log('Error attempting to create Azure Rule Set instance.')
            self.fail("Error Creating Azure Rule Set instance: {0}".format(exc.message))

    def delete_ruleset(self):
        '''
        Deletes the specified Azure Rule Set in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the Rule Set {0}".format(self.name))
        try:
            poller = self.ruleset_client.rule_sets.begin_delete(resource_group_name=self.resource_group, profile_name=self.profile_name, rule_set_name=self.name)
            self.get_poller_result(poller)
            return True
        except Exception as e:
            self.log('Error attempting to delete the Rule Set.')
            self.fail("Error deleting the Rule Set: {0}".format(e.message))
            return False

    def get_ruleset(self):
        '''
        Gets the properties of the specified Rule Set.

        :return: deserialized Rule Set state dictionary
        '''
        self.log(
            "Checking if the Rule Set {0} is present".format(self.name))
        try:
            response = self.ruleset_client.rule_sets.get(
                resource_group_name=self.resource_group,
                profile_name=self.profile_name,
                rule_set_name=self.name,
            )
            self.log("Response : {0}".format(response))
            self.log("Rule Set : {0} found".format(response.name))
            return ruleset_to_dict(response)
        except Exception as err:
            self.log('Did not find the Rule Set.' + err.args[0])
            return False

    def get_ruleset_client(self):
        if not self.ruleset_client:
            self.ruleset_client = self.get_mgmt_svc_client(CdnManagementClient,
                                                       base_url=self._cloud_environment.endpoints.resource_manager,
                                                       api_version='2023-05-01')
        return self.ruleset_client


def main():
    """Main execution"""
    AzureRMRuleSet()
    # x = CdnManagementClient()
    # x.rule_sets.begin_create()
    # y = AFDRuleSet()

if __name__ == '__main__':
    main()
