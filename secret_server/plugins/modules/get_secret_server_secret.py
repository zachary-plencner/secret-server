#!/usr/bin/python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: get_secret_server_secret

short_description: Retreives a secret from Delinea's Secret Server

version_added: "1.0.0"

description: |
    Retreive a secret from Delinea's Secret Server using the Secret Server's API as a backend. Returns a 'secret' variable that
    contains the secret's username and password.

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
    secret_name:
        description: The name of the secret you want to retreive from Secret Server (must be verbatim/exact match)
        required: true
        type: str

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

# Retrieve a secret with a non-local login with domain name
- name: Get a secret named "Administrator Login"
    get_secret_server_secret:
      secret_server_host: 'https://example.secretservercloud.com'
      secret_server_username_domain: "Contoso"
      secret_server_username: "john.doe"
      secret_server_password: "password123"
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


class LogOn:
    def __init__(self, secret_server_host, secret_server_username, secret_server_password):
        self.secret_server_host = secret_server_host
        self.secret_server_username = secret_server_username
        self.secret_server_password = secret_server_password

        self.secret_server_logon_uri = secret_server_host + '/oauth2/token'
        self.secret_server_base_url = secret_server_host + '/api/v1'
        self.secret_server_grant_type = 'password'

        # Create dictionarie with login data
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
        secret_server_username=dict(type='str', no_log=True, required=True),
        secret_server_password=dict(type='str', no_log=True, required=True),
        secret_name=dict(type='str', required=True)
    )

    # seed the result dict in the object
    result = dict(
        changed=False,
        secret=dict()
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

    # if user specified a domain, append it to username
    if module.params['secret_server_username_domain']:
        secret_server_username = "{}\\{}".format(module.params['secret_server_username_domain'], module.params['secret_server_username'])
    # else username defaults to standalone
    else:
        secret_server_username = module.params['secret_server_username']

    secret_server_logon = LogOn(module.params['secret_server_host'],
                                secret_server_username,
                                module.params['secret_server_password']
                                )

    module_result = get_secret(secret_server_logon,
                               module.params['secret_name']
                               )

    # use whatever logic you need to determine whether or not this module
    # made any modifications to your target
    # result['changed'] = True

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    # if module.params['name'] == 'fail me':
    #     module.fail_json(msg='You requested this to fail', **result)

    if not module_result:
        module.fail_json(msg='Secret does not exist. \'secret_name\' must be verbatim.', **result)

    for item in module_result['items']:
        if item['fieldName'] == 'Username':
            secret_username = item['itemValue']
        if item['fieldName'] == 'Password':
            secret_password = item['itemValue']

    if not secret_username:
        module.fail_json(msg='Secret does not have a username', **result)

    if not secret_password:
        module.fail_json(msg='Secret does not have a password', **result)

    result['secret'] = dict(secret_username=secret_username,
                            secret_password=secret_password)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
