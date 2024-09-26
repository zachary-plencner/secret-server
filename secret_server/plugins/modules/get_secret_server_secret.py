#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: get_secret_server_secret

short_description: Retreives a secret from Delineas Secret Server

version_added: "1.0.0"

description: |
    Retreive a secret from Delineas Secret Server using the Secret Servers API as a backend.
    Returns a secret variable that contains the secrets username and password.

options:
    secret_server_host:
        description: The hostname of your Secret Server instance
        required: true
        type: str
    secret_server_username_domain:
        description: The domain pertaining to your username. This is prepend to your username
        required: false
        type: str
    secret_server_username:
        description: The username of the user that will be used to contact the Secret Server API
        required: true
        type: str
    secret_server_password:
        description: The password of the user that will be used to contact the Secret Server API
        required: true
        type: str
    use_sdk:
        description: If the module should use the SDK to authenticate with Secret Server
        required: false
        type: str
    sdk_config_directory:
        description: Directory where the SDK .config files are located
        required: false
        type: str
    secret_name:
        description: The name of the secret you want to retreive from Secret Server (must be verbatim/exact match)
        required: true
        type: str
    sha512_encrypt_password:
        description: Output for password parameter will be sha512 encrypted for security purposes
        required: False
        type: bool

author:
    - Zachary Plencner (@zachary-plencner)
'''

EXAMPLES = r'''
# Retrieve a secret with local login
- name: Get a secret named "Administrator Login"
    get_secret_server_secret:
      secret_server_host: 'https://example.secretservercloud.com'
      secret_server_username: "john.doe"
      secret_server_password: "password123"
      secret_name: "Administrator Login"

# Retrieve a secret with non-local login
- name: Get a secret named "Administrator Login"
    get_secret_server_secret:
      secret_server_host: 'https://example.secretservercloud.com'
      secret_server_username: "john.doe"
      secret_server_password: "password123"
      secret_server_username_domain: "Contoso"
      secret_name: "Administrator Login"

# Retrieve a secret using the SDK
- name: Get a secret named "Administrator Login"
    get_secret_server_secret:
      secret_server_host: 'https://example.secretservercloud.com'
      use_sdk: yes
      sdk_config_directory: /etc/secret-server-sdk
      secret_name: "Administrator Login"
'''

RETURN = r'''
secret:
    description: The username and password of the secret
    type: str
    returned: always
    sample: {
        "secret_password": "password123",
        "secret_username": "username1"
    }
'''

from ansible.module_utils.basic import AnsibleModule
import requests
import subprocess
import os
from passlib.hash import sha512_crypt


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


def get(secret_server_logon, endpoint):
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.get(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar)
    return r.json()


def get_secret(secret_server_logon, search_term):
    endpoint = '/secrets?filter.includeRestricted=true&filter.isExactMatch=true&filter.searchtext=' + search_term
    secret = get(secret_server_logon, endpoint)
    if not secret['records']:
        return None

    secret_id = secret['records'][0]['id']
    endpoint = '/secrets/' + str(secret_id)
    secret = get(secret_server_logon, endpoint)

    return secret


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
        sha512_encrypt_password=dict(type='bool', no_log=False, required=False, default=False)
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

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

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

    module_result = get_secret(secret_server_logon,
                               module.params['secret_name']
                               )
    if module_result:
        for item in module_result['items']:
            module_result[str(item['fieldName'])[0].lower() + str(item['fieldName'])[1:]] = item['itemValue']

        del module_result['items']

        # Encrypt the secret_password result if sha512_encrypt_password is True
        if module.params['sha512_encrypt_password']:
            module_result['password'] = sha512_crypt.using(rounds=5000).hash(module_result['password'])

        result['secret'] = module_result

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
