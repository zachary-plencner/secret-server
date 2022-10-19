#!/usr/bin/python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: create_secret_server_secret

short_description: Create a secret in Delinea's Secret Server

version_added: "1.0.0"

description: |
    Create a secret in Delinea's Secret Server using the Secret Server's API as a backend. Returns a 'secret' variable that
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
    secret_folder:
        description: The name of the folder the secret will be placed in
        required: True
        type: str
    secret_template:
        description: The type of secret you want to create
        required: True
        type: str
    secret_name:
        description: The display name of the secret
        required: True
        type: str
    secret_machine_name:
        description: The name of the machine the secret is associated with
        required: False
        type: str
    secret_username:
        description: The username of the secret
        required: True
        type: str
    secret_password:
        description: The password of the secret
        required: True
        type: str
    secret_notes:
        description: Additional notes to attach to the secret
        required: False
        type: str
    secret_overwrite:
        description: Flag to enable overwriting of an existing secret
        required: False
        type: bool

author:
    - Zachary Plencner (@zachary-plencner)
'''

EXAMPLES = r'''
# Create a 'Windows Account' Secret
- name: Create a new secret
    create_windows_secret_server_secret:
      secret_server_host: 'https://contoso.secretservercloud.com'
      secret_server_username_domain: "contoso"
      secret_server_username: "john.doe"
      secret_server_password: "password123"
      secret_folder: "My Secrets"
      secret_template: "Windows Account"
      secret_name: "My Workstation"
      secret_machine_name: "DESKTOP-Q66XZA5"
      secret_username: "jdoe"
      secret_password: "anotherpassword123"

# Create a 'Password' Secret w/ note and overwrite
- name: Create Secret
    create_windows_secret_server_secret:
      secret_server_host: 'https://contoso.secretservercloud.com'
      secret_server_username_domain: "contoso"
      secret_server_username: "jane.doe"
      secret_server_password: "password123"
      secret_folder: "Linux Secrets"
      secret_template: "Password"
      secret_name: "database-1"
      secret_username: "root"
      secret_password: "Q1am9a!aSl"
      secret_notes: "Root login for database-1"
      secret_overwrite: True
'''

RETURN = r'''
secret:
    description: The username and password of the secret
    type: str
    returned: always
    sample: {
        "secret_password": "anotherpassword123",
        "secret_username": "jdoe"
    }
'''

from ansible.module_utils.basic import AnsibleModule
import requests
import copy


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


def get(secret_server_host, secret_server_username, secret_server_password, endpoint):
    secret_server_logon = LogOn(secret_server_host, secret_server_username, secret_server_password)
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.get(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar)
    return r.json()


def post(secret_server_host, secret_server_username, secret_server_password, endpoint, payload):
    secret_server_logon = LogOn(secret_server_host, secret_server_username, secret_server_password)
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.post(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar, json=payload)
    return r.json()


def put(secret_server_host, secret_server_username, secret_server_password, endpoint, payload):
    secret_server_logon = LogOn(secret_server_host, secret_server_username, secret_server_password)
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.put(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar, json=payload)
    return r.json()


def get_secret(secret_server_host, secret_server_username, secret_server_password, search_term):
    endpoint = '/secrets?filter.includeRestricted=true&filter.isExactMatch=true&filter.searchtext=' + search_term
    secret = get(secret_server_host, secret_server_username, secret_server_password, endpoint)
    if not secret['records']:
        return None

    secret_id = secret['records'][0]['id']
    endpoint = '/secrets/' + str(secret_id)
    secret = get(secret_server_host, secret_server_username, secret_server_password, endpoint)

    return secret


def get_folder_id(secret_server_host, secret_server_username, secret_server_password, folder_name):
    endpoint = '/folders?filter.searchtext=' + folder_name
    folder = get(secret_server_host, secret_server_username, secret_server_password, endpoint)
    if not folder['records']:
        print("Folder does not exist")
        exit()
    folder_exists = 0
    for record in folder['records']:
        if folder_name == record['folderName']:
            folder_exists = 1
            break
    if not folder_exists:
        print("Folder does not exist")
        exit()

    return folder['records'][0]['id']


def get_template_id(secret_server_host, secret_server_username, secret_server_password, template_name):
    endpoint = '/templates'
    templates = get(secret_server_host, secret_server_username, secret_server_password, endpoint)
    for template in templates:
        if template['name'] == template_name:
            templateID = template['id']

    if not templateID:
        print("Template does not exist")
        exit()

    return templateID


def get_template_name(secret_server_host, secret_server_username, secret_server_password, template_id):
    endpoint = '/templates'
    templates = get(secret_server_host, secret_server_username, secret_server_password, endpoint)
    for template in templates:
        if template['id'] == template_id:
            templateName = template['name']

    return templateName


def create_windows_secret(secret_server_host, secret_server_username, secret_server_password, secret_folder, secret_template, secret_name, secret_machine_name,
                          secret_username, secret_password, secret_notes
                          ):
    folder_id = get_folder_id(secret_server_host, secret_server_username, secret_server_password, secret_folder)
    template_id = get_template_id(secret_server_host, secret_server_username, secret_server_password, secret_template)

    endpoint = '/secrets/stub?filter.secrettemplateid=' + str(template_id)
    secret_stub = get(secret_server_host, secret_server_username, secret_server_password, endpoint)

    secret_stub['name'] = secret_name
    secret_stub['secretTemplateId'] = template_id
    secret_stub['AutoChangeEnabled'] = False
    secret_stub['autoChangeNextPassword'] = ""
    secret_stub['SiteId'] = 1
    secret_stub['folderId'] = folder_id
    secret_stub['active'] = True
    secret_stub['IsDoubleLock'] = False
    for item in secret_stub['items']:
        if item['fieldName'] == "Machine":
            item['itemValue'] = secret_machine_name
        if item['fieldName'] == "Username":
            item['itemValue'] = secret_username
        if item['fieldName'] == "Password":
            item['itemValue'] = secret_password
        if item['fieldName'] == "Notes":
            item['itemValue'] = secret_notes

    endpoint = '/secrets'
    secret = post(secret_server_host, secret_server_username, secret_server_password, endpoint, secret_stub)
    return secret


def change_windows_secret(secret_server_host, secret_server_username, secret_server_password, existing_secret, secret_folder, secret_template, secret_name,
                          secret_machine_name, secret_username, secret_password, secret_notes
                          ):
    folder_id = get_folder_id(secret_server_host, secret_server_username, secret_server_password, secret_folder)
    template_id = get_template_id(secret_server_host, secret_server_username, secret_server_password, secret_template)

    endpoint = '/secrets/stub?filter.secrettemplateid=' + str(template_id)
    secret_stub = copy.deepcopy(existing_secret)

    secret_stub['name'] = secret_name
    secret_stub['secretTemplateId'] = template_id
    secret_stub['folderId'] = folder_id
    for item in secret_stub['items']:
        if item['fieldName'] == "Machine":
            item['itemValue'] = secret_machine_name
        if item['fieldName'] == "Username":
            item['itemValue'] = secret_username
        if item['fieldName'] == "Password":
            item['itemValue'] = secret_password
        if item['fieldName'] == "Notes":
            item['itemValue'] = secret_notes
    if secret_stub != existing_secret:
        endpoint = '/secrets/' + str(existing_secret['id'])
        secret = put(secret_server_host, secret_server_username, secret_server_password, endpoint, secret_stub)
        return secret
    else:
        return None


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        secret_server_host=dict(type='str', required=True),
        secret_server_username_domain=dict(type='str', required=False),
        secret_server_username=dict(type='str', no_log=True, required=True),
        secret_server_password=dict(type='str', no_log=True, required=True),
        secret_folder=dict(type='str', required=True),
        secret_template=dict(type='str', required=True),
        secret_name=dict(type='str', required=True),
        secret_machine_name=dict(type='str', required=True),
        secret_username=dict(type='str', required=True),
        secret_password=dict(type='str', no_log=False, required=True),
        secret_notes=dict(type='str', required=False),
        secret_overwrite=dict(type='bool', required=False, default=False)
    )

    supported_templates = ['password',
                           'windows account'
                           ]

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

    if str(module.params['secret_template']).lower() not in supported_templates:
        print(str(module.params['secret_template']) + ' is not a supported template type.')
        exit()

    # if user specified a domain, append it to username
    if module.params['secret_server_username_domain']:
        secret_server_username = "{}\\{}".format(module.params['secret_server_username_domain'], module.params['secret_server_username'])
    # else username defaults to standalone
    else:
        secret_server_username = module.params['secret_server_username']

    existing_secret = get_secret(module.params['secret_server_host'],
                                 secret_server_username,
                                 module.params['secret_server_password'],
                                 module.params['secret_name']
                                 )

    if existing_secret and module.params['secret_overwrite']:
        if existing_secret['secretTemplateId'] != get_template_id(module.params['secret_server_host'],
                                                                  secret_server_username,
                                                                  module.params['secret_server_password'],
                                                                  module.params['secret_template']
                                                                  ):
            print('Cannot convert from \'{}\' template type to \'{}\' template type'.format(get_template_name(module.params['secret_server_host'],
                                                                                                              secret_server_username,
                                                                                                              module.params['secret_server_password'],
                                                                                                              existing_secret['secretTemplateId']
                                                                                                              ),
                                                                                            module.params['secret_template']
                                                                                            )
                  )
            exit()
        else:
            if module.params['secret_template'] == 'Windows Account':
                module_result = change_windows_secret(module.params['secret_server_host'],
                                                      secret_server_username,
                                                      module.params['secret_server_password'],
                                                      existing_secret,
                                                      module.params['secret_folder'],
                                                      module.params['secret_template'],
                                                      module.params['secret_name'],
                                                      module.params['secret_machine_name'],
                                                      module.params['secret_username'],
                                                      module.params['secret_password'],
                                                      module.params['secret_notes']
                                                      )
                if not module_result:
                    result['changed'] = False
                    module_result = existing_secret
                else:
                    result['changed'] = True
            else:
                print('Unsupported password change')
                exit()
    elif existing_secret and not module.params['secret_overwrite']:
        module_result = existing_secret
        result['changed'] = False
    else:
        module_result = create_windows_secret(module.params['secret_server_host'],
                                              secret_server_username,
                                              module.params['secret_server_password'],
                                              module.params['secret_folder'],
                                              module.params['secret_template'],
                                              module.params['secret_name'],
                                              module.params['secret_machine_name'],
                                              module.params['secret_username'],
                                              module.params['secret_password'],
                                              module.params['secret_notes']
                                              )
        result['changed'] = True

    if not module_result['items']:
        module.fail_json(msg='Secret could not be created', **result)

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
