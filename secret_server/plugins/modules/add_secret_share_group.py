#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: add_secret_share_group

short_description: Add a group to a secret's permission to share it with the supplied group(s)

version_added: "2.1.0"

description: |
    Update a secret's permissions from Delineas Secret Server using the Secret Servers API as a backend.
    Supply a group, what their role with the secret will be, and optionally the group's domain.

options:
    secret_server_host:
        description: The hostname of your Secret Server instance
        required: true
        type: str
    secret_server_username_domain:
        description: The domain pertaining to your username. This is prepended to your username (mutually exclusive with SDK authentication)
        required: false
        type: str
    secret_server_username:
        description: The username of the user that will be used to contact the Secret Server API (mutually exclusive with SDK authentication)
        required: false
        type: str
    secret_server_password:
        description: The password of the user that will be used to contact the Secret Server API (mutually exclusive with SDK authentication)
        required: false
        type: str
    use_sdk:
        description: If the module should use the SDK to authenticate with Secret Server (mutually exclusive with username/password authentication)
        required: false
        type: str
    sdk_config_directory:
        description: Directory where the SDK .config files are located (mutually exclusive with username/password authentication)
        required: false
        type: str
    secret_name:
        description: The name of the secret you want to retreive from Secret Server (must be verbatim/exact match)
        required: true
        type: str
    secret_share_groups:
        description: The group's name, role, and (optionally) domain
        required: true
        type: list

author:
    - Zachary Plencner (@zachary-plencner)
'''

EXAMPLES = r'''
# Retrieve a secret with local login
- name: Share a secret named "Administrator Login" with groups named "Accounting" permission to view the secret, and "Human Resources" permission to edit the secret
    add_secret_share_group:
      secret_server_host: 'https://example.secretservercloud.com'
      secret_server_username: "john.doe"
      secret_server_password: "password123"
      secret_name: "Administrator Login"
      secret_share_groups:
      - name: Accounting
        role: View
      - name: Human Resources
        role: Edit

# Retrieve a secret with a non-local login with domain name
- name: Share a secret named "Administrator Login" with groups named "Office Space 1 Employees" (from the Contoso domain) and a local group named "TSS Admins"
    add_secret_share_group:
      secret_server_host: 'https://example.secretservercloud.com'
      use_sdk: yes
      sdk_config_directory: /etc/secret-server-sdk
      secret_name: "Administrator Login"
      secret_share_groups:
      - name: Office Space 1 Employees
        role: List
        domain: Contoso
      - name: TSS Admins
        role: Owner
'''

RETURN = r'''
# This module does not return any data
'''

from ansible.module_utils.basic import AnsibleModule
import requests
import subprocess
import os

valid_roles = ['owner', 'edit', 'view', 'list']


class LogOn:
    def __init__(self, secret_server_host, secret_server_username, secret_server_password, use_sdk, sdk_config_directory):
        self.secret_server_host = secret_server_host
        self.secret_server_logon_uri = secret_server_host + '/oauth2/token'
        self.secret_server_base_url = secret_server_host + '/api/v1'

        if not use_sdk:
            self.secret_server_grant_type = 'password'
            self.secret_server_username = secret_server_username
            self.secret_server_password = secret_server_password

            # Create dictionary with login data
            self.secret_server_logon_data = {
                                            'username': secret_server_username,
                                            'password': secret_server_password,
                                            'grant_type': self.secret_server_grant_type
                                        }

            # Login to Secret Server
            secret_server_r = requests.post(self.secret_server_logon_uri, data=self.secret_server_logon_data)

            if secret_server_r.status_code != 200:
                print("Login failed")
                exit()

            self.secret_server_jar = secret_server_r.cookies

            # Create bearer token variable
            secret_server_token = secret_server_r.json()['access_token']
        else:
            secret_server_token = (subprocess.check_output(["tss","-cd",sdk_config_directory,"token"],stderr=subprocess.STDOUT, universal_newlines=True)).replace('\n', '')
            self.secret_server_jar = None

        # Create header variable for Secret Server. Includes bearer token for authorization
        self.secret_server_headers = {
                                    'Content-Type': 'application/json',
                                    'Accept': 'application/json',
                                    'Authorization': "Bearer " + secret_server_token
                                }


# API get method
def get(secret_server_logon, endpoint):
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.get(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar)
    return r.json()


# API post method (with payload)
def post(secret_server_logon, endpoint, payload):
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.post(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar, json=payload)

    return r.json()


# API put method (with payload)
def put(secret_server_logon, endpoint, payload):
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.put(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar, json=payload)

    return r.json()


# API patch method (with payload)
def patch(secret_server_logon, endpoint, payload):
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.patch(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar, json=payload)

    return r.json()


# Get a secret
def get_secret(secret_server_logon, search_term):
    endpoint = '/secrets?filter.includeRestricted=true&filter.isExactMatch=true&filter.searchtext=' + search_term
    secret = get(secret_server_logon, endpoint)
    if not secret['records']:
        return None

    secret_id = secret['records'][0]['id']
    endpoint = '/secrets/' + str(secret_id)
    secret = get(secret_server_logon, endpoint)

    return secret


# Enable or disable a secret's sharing inheritance setting (inheriting permissions from folder)
# To disable inheritance, inheritance_bool = False
def change_secret_sharing_inheritance(secret_server_logon, secret_id, inheritance_bool):
    endpoint = '/secrets/' + str(secret_id) + '/share'
    payload = dict(data=dict(inheritPermissions=dict(dirty=True,
                                                     value=inheritance_bool
                                                     )
                             )
                   )
    patch(secret_server_logon, endpoint, payload)
    return None


# Add a group to a secret's sharing permissions
def add_secret_share_group(secret_server_logon, secret, domain, group, role):
    secret_id = secret['id']

    endpoint = '/secret-permissions?filter.secretId=' + str(secret_id)
    secret_permission_search = get(secret_server_logon, endpoint)   # get secret's current permissions

    endpoint = '/groups?filter.searchText=' + group
    secret_groups_search = get(secret_server_logon, endpoint)   # search for groups with supplied name

    if not secret_groups_search['records']:
        print('No group with name: \"' + group + '\" found.')
        exit()

    # Select group with same domainName
    target_secret_group = None
    if domain:
        for record in secret_groups_search['records']:
            if domain == record['domainName']:
                target_secret_group = record
                break
        if not target_secret_group:
            print('No group with name: \"' + domain + '\\' + group + '\" found.')
            exit()
    else:
        target_secret_group = secret_groups_search['records'][0]

    # check that a valid role name was supplied
    role = role.lower()
    if role not in valid_roles:
        print('No role with name: \"' + role + '\" exists. Valid role names are:', valid_roles)
        exit()

    # check if group is already in the secret's permission
    for permission in secret_permission_search['records']:
        if target_secret_group['id'] == permission['groupId']:
            # if the group is already in the secret's permission, compare current role to supplied role
            if permission['secretAccessRoleName'].lower() == role:
                return None
            else:
                payload = dict(id=permission['id'],
                               secretAccessRoleName=role,
                               secretId=secret_id
                               )
                endpoint = '/secret-permissions/' + str(permission['id'])
                r = put(secret_server_logon, endpoint, payload)
                return r

    # base case if group is not already in the secret's permission: add the group with supplied information

    # ensure permission inheritance is disabled (required to be able to change permissions manually)
    if secret['enableInheritPermissions']:
        change_secret_sharing_inheritance(secret_server_logon, secret_id, False)

    payload = dict(domainName=target_secret_group['domainName'],
                   groupId=target_secret_group['id'],
                   groupName=target_secret_group['name'],
                   secretAccessRoleName=role,
                   secretId=secret_id,
                   userId=None,
                   userName=None
                   )

    endpoint = '/secret-permissions'
    r = post(secret_server_logon, endpoint, payload)
    return r


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        secret_server_host=dict(type='str', required=True),
        secret_server_username_domain=dict(type='str', required=False),
        secret_server_username=dict(type='str', no_log=True, required=False),
        secret_server_password=dict(type='str', no_log=True, required=False),
        use_sdk=dict(type='bool', no_log=False, required=False, default=False),
        sdk_config_directory=dict(type='str', required=False),
        secret_name=dict(type='str', required=True),
        secret_share_groups=dict(type='list', required=True)
    )

    # seed the result dict in the object
    result = dict(
        changed=False
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if module.params['use_sdk']:
        try:
            subprocess.check_output("tss", stderr=subprocess.STDOUT, universal_newlines=True)
        except subprocess.CalledProcessError as e:
            print("tss SDK is not available or encountered an error:")
        except FileNotFoundError:
            print("tss SDK binary not present or is not included in PATH")
        if None == module.params['sdk_config_directory']:
            print("use_sdk=True but sdk_config_directory was not provided")
            exit()
        else:
            if not os.path.exists(module.params['sdk_config_directory'] + "/credentials.config"):
                print("Could not find SDK config " + module.params['sdk_config_directory'] + "/credentials.config")
                exit()
    else:
        if None == module.params['secret_server_username']:
            print("No username was provided")
            exit()
        if None == module.params['secret_server_password']:
            print("No password was provided")
            exit()    

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    for i, secret_share_group in enumerate(module.params['secret_share_groups']):
        if 'domain' not in secret_share_group:
            secret_share_group['domain'] = None
        if 'name' not in secret_share_group:
            module.fail_json(msg='missing required arguments in secret_share_groups[{}]: name'.format(i))
        if 'role' not in secret_share_group:
            module.fail_json(msg='missing required arguments in secret_share_groups[{}]: role'.format(i))

    # if user specified a domain, append it to username
    if module.params['secret_server_username_domain']:
        secret_server_username = "{}\\{}".format(module.params['secret_server_username_domain'], module.params['secret_server_username'])
    # else username defaults to standalone
    else:
        secret_server_username = module.params['secret_server_username']

    secret_server_logon = LogOn(module.params['secret_server_host'],
                                secret_server_username,
                                module.params['secret_server_password'],
                                module.params['use_sdk'],
                                module.params['sdk_config_directory']
                                )

    secret = get_secret(secret_server_logon,
                        module.params['secret_name']
                        )

    if not secret:
        print('No secret with name: \"' + module.params['secret_name'] + "\" found.")
        exit()

    for secret_share_group in module.params['secret_share_groups']:
        module_result = add_secret_share_group(secret_server_logon,
                                               secret,
                                               secret_share_group['domain'],
                                               secret_share_group['name'],
                                               secret_share_group['role']
                                               )
        if module_result:
            result['changed'] = True

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
