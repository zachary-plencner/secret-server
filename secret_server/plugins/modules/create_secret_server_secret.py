#!/usr/bin/python

from __future__ import (absolute_import, division, print_function)
from logging import raiseExceptions
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
import random
from passlib.hash import sha512_crypt

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
            raise Exception("Login failed")

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


def post(secret_server_logon, endpoint, payload):
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.post(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar, json=payload)
    return r.json()


def put(secret_server_logon, endpoint, payload):
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.put(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar, json=payload)
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


def get_folder_id(secret_server_logon, folder_name):
    endpoint = '/folders?filter.searchtext=' + folder_name
    folder = get(secret_server_logon, endpoint)
    if not folder['records']:
        raise Exception(msg="Folder does not exist")
    folder_exists = 0
    for record in folder['records']:
        if folder_name == record['folderName']:
            folder_exists = 1
            break
    if not folder_exists:
        raise Exception(msg="Folder does not exist")

    return folder['records'][0]['id']


def get_template_id(secret_server_logon, template_name):
    endpoint = '/templates'
    templates = get(secret_server_logon, endpoint)
    for template in templates:
        if template['name'] == template_name:
            templateID = template['id']

    if not templateID:
        raise Exception(msg="Template does not exist")

    return templateID


def get_template_name(secret_server_logon, template_id):
    endpoint = '/templates'
    templates = get(secret_server_logon, endpoint)
    for template in templates:
        if template['id'] == template_id:
            templateName = template['name']

    return templateName


def create_password_secret(secret_server_logon, secret_folder, secret_template, secret_name, secret_resource,
                           secret_username, secret_password, secret_notes
                           ):
    folder_id = get_folder_id(secret_server_logon, secret_folder)
    template_id = get_template_id(secret_server_logon, secret_template)
    endpoint = '/secrets/stub?filter.secrettemplateid=' + str(template_id)
    secret_stub = get(secret_server_logon, endpoint)
    secret_stub['name'] = secret_name
    secret_stub['secretTemplateId'] = template_id
    secret_stub['AutoChangeEnabled'] = False
    secret_stub['autoChangeNextPassword'] = ""
    secret_stub['SiteId'] = 1
    secret_stub['folderId'] = folder_id
    secret_stub['active'] = True
    secret_stub['IsDoubleLock'] = False
    for item in secret_stub['items']:
        if item['fieldName'] == "Resource":
            item['itemValue'] = secret_resource
        if item['fieldName'] == "Username":
            item['itemValue'] = secret_username
        if item['fieldName'] == "Password":
            item['itemValue'] = secret_password
        if item['fieldName'] == "Notes":
            item['itemValue'] = secret_notes
    endpoint = '/secrets'
    secret = post(secret_server_logon, endpoint, secret_stub)
    return secret


def create_windows_secret(secret_server_logon, secret_folder, secret_template, secret_name, secret_machine_name,
                          secret_username, secret_password, secret_notes
                          ):
    folder_id = get_folder_id(secret_server_logon, secret_folder)
    template_id = get_template_id(secret_server_logon, secret_template)

    endpoint = '/secrets/stub?filter.secrettemplateid=' + str(template_id)
    secret_stub = get(secret_server_logon, endpoint)

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
    secret = post(secret_server_logon, endpoint, secret_stub)
    return secret


def change_windows_secret(secret_server_logon, existing_secret, secret_folder, secret_template, secret_name,
                          secret_machine_name, secret_username, secret_password, secret_notes
                          ):
    folder_id = get_folder_id(secret_server_logon, secret_folder)
    template_id = get_template_id(secret_server_logon, secret_template)

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
        secret = put(secret_server_logon, endpoint, secret_stub)
        return secret
    else:
        return None


def change_password_secret(secret_server_logon, existing_secret, secret_folder, secret_template, secret_name,
                           secret_resource, secret_username, secret_password, secret_notes
                           ):
    folder_id = get_folder_id(secret_server_logon, secret_folder)
    template_id = get_template_id(secret_server_logon, secret_template)
    endpoint = '/secrets/stub?filter.secrettemplateid=' + str(template_id)
    secret_stub = copy.deepcopy(existing_secret)
    secret_stub['name'] = secret_name
    secret_stub['secretTemplateId'] = template_id
    secret_stub['folderId'] = folder_id
    for item in secret_stub['items']:
        if item['fieldName'] == "Resource":
            item['itemValue'] = secret_resource
        if item['fieldName'] == "Username":
            item['itemValue'] = secret_username
        if item['fieldName'] == "Password":
            item['itemValue'] = secret_password
        if item['fieldName'] == "Notes":
            item['itemValue'] = secret_notes
    if secret_stub != existing_secret:
        endpoint = '/secrets/' + str(existing_secret['id'])
        secret = put(secret_server_logon, endpoint, secret_stub)
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
        secret_machine_name=dict(type='str', required=False),
        secret_resource=dict(type='str', required=False),
        secret_username=dict(type='str', required=True),
        secret_password=dict(type='str', no_log=False, required=False),
        use_random_password=dict(type='bool', no_log=False, required=False, default=False),
        random_password_length=dict(type='int', no_log=False, required=False),
        random_password_alphabet=dict(type='str', no_log=False, required=False),
        random_password_lowercase_requirement=dict(type='int', no_log=False, required=False),
        random_password_uppercase_requirement=dict(type='int', no_log=False, required=False),
        random_password_digit_requirement=dict(type='int', no_log=False, required=False),
        random_password_special_requirement=dict(type='int', no_log=False, required=False),
        secret_notes=dict(type='str', required=False),
        secret_overwrite=dict(type='bool', required=False, default=False),
        sha512_encrypt_password=dict(type='bool', required=False, default=False)
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

    supported_templates = ['password',
                           'windows account'
                           ]

    if module.params['use_random_password'] and module.params['secret_password']:
        module.fail_json(msg='use_random_password and secret_password arguments are mutually exclusive')
    if module.params['use_random_password']:
        random_password_length =  module.params['random_password_length'] if module.params['random_password_length'] else 8
        random_password_alphabet = module.params['random_password_alphabet'] if module.params['random_password_alphabet'] else 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()'
        random_password_lowercase_requirement = module.params['random_password_lowercase_requirement'] if module.params['random_password_lowercase_requirement'] else 0
        random_password_uppercase_requirement = module.params['random_password_uppercase_requirement'] if module.params['random_password_uppercase_requirement'] else 0
        random_password_digit_requirement = module.params['random_password_digit_requirement'] if module.params['random_password_digit_requirement'] else 0
        random_password_special_requirement = module.params['random_password_special_requirement'] if module.params['random_password_special_requirement'] else 0
        random_password_requirements_sum = random_password_lowercase_requirement + random_password_uppercase_requirement + random_password_digit_requirement + random_password_special_requirement

        if random_password_length < random_password_requirements_sum:
            module.fail_json(msg='random_password_length: {}, cannot be less than random_password_<char_type>_requirements sum: {}'.format(random_password_length,random_password_requirements_sum))
        if random_password_uppercase_requirement and not any(c.isupper() for c in random_password_alphabet):
            module.fail_json(msg='random_password_uppercase_requirement is >0 but random_password_alphabet does not contain any uppercase characters')
        if random_password_lowercase_requirement and not any(c.islower() for c in random_password_alphabet):
            module.fail_json(msg='random_password_lowercase_requirement is >0 but random_password_alphabet does not contain any lowercase characters')
        if random_password_digit_requirement and not any(c.isdigit() for c in random_password_alphabet):
            module.fail_json(msg='random_password_digit_requirement is >0 but random_password_alphabet does not contain any digit characters')
        if random_password_special_requirement and not any(not c.isalnum() for c in random_password_alphabet):
            module.fail_json(msg='random_password_special_requirement is >0 but random_password_alphabet does not contain any special characters')
        random_password_alphabet_uppercase = ''
        random_password_alphabet_lowercase = ''
        random_password_alphabet_digit = ''
        random_password_alphabet_special = ''
        for c in random_password_alphabet: 
            if c.isupper():
                random_password_alphabet_uppercase += c
        for c in random_password_alphabet: 
            if c.islower():
                random_password_alphabet_lowercase += c
        for c in random_password_alphabet: 
            if c.isdigit():
                random_password_alphabet_digit += c
        for c in random_password_alphabet: 
            if not c.isalnum():
                random_password_alphabet_special += c

        secret_password = ''
        for i in range(random_password_uppercase_requirement):
            secret_password += random.choice(random_password_alphabet_uppercase)
        for i in range(random_password_lowercase_requirement):
            secret_password += random.choice(random_password_alphabet_lowercase)
        for i in range(random_password_digit_requirement):
            secret_password += random.choice(random_password_alphabet_digit)
        for i in range(random_password_special_requirement):
            secret_password += random.choice(random_password_alphabet_special)
        for i in range(random_password_length - random_password_requirements_sum):
            secret_password += random.choice(random_password_alphabet)
            
        secret_password_list = list(secret_password)
        random.SystemRandom().shuffle(secret_password_list)
        secret_password = ''.join(secret_password_list)
        
    elif module.params['secret_password']:
        secret_password = module.params['secret_password']
    else:
        module.fail_json(msg='missing required arguments: secret_password')

    # Error checking for parameter dependencies
    match str(module.params['secret_template']).lower():
        case 'windows account':
            if not module.params['secret_machine_name']:
                module.fail_json(msg='missing required arguments: secret_machine_name')

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    if str(module.params['secret_template']).lower() not in supported_templates:
        module.fail_json(msg=str(module.params['secret_template']) + ' is not a supported template type.')

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

    existing_secret = get_secret(secret_server_logon,
                                 module.params['secret_name']
                                 )

    if existing_secret and module.params['secret_overwrite']:
        if existing_secret['secretTemplateId'] != get_template_id(secret_server_logon,
                                                                  module.params['secret_template']
                                                                  ):
            module.fail_json(msg='Cannot convert from \'{}\' template type to \'{}\' template type'.format(get_template_name(secret_server_logon,
                                                                                                                        existing_secret['secretTemplateId']
                                                                                                                        ),
                                                                                                      module.params['secret_template']
                                                                                                      )
                            )
        else:
            match str(module.params['secret_template']).lower():
                case 'windows account':
                    module_result = change_windows_secret(secret_server_logon,
                                                          existing_secret,
                                                          module.params['secret_folder'],
                                                          module.params['secret_template'],
                                                          module.params['secret_name'],
                                                          module.params['secret_machine_name'],
                                                          module.params['secret_username'],
                                                          secret_password,
                                                          module.params['secret_notes']
                                                          )
                    if not module_result:
                        result['changed'] = False
                        module_result = existing_secret
                    else:
                        result['changed'] = True
                case 'password':
                    module_result = change_password_secret(secret_server_logon,
                                                           existing_secret,
                                                           module.params['secret_folder'],
                                                           module.params['secret_template'],
                                                           module.params['secret_name'],
                                                           module.params['secret_resource'],
                                                           module.params['secret_username'],
                                                           secret_password,
                                                           module.params['secret_notes']
                                                           )
                    if not module_result:
                        result['changed'] = False
                        module_result = existing_secret
                    else:
                        result['changed'] = True
                case _:
                    module.fail_json(msg='Unsupported password change')
    elif existing_secret and not module.params['secret_overwrite']:
        module_result = existing_secret
        result['changed'] = False
    else:
        if module.params['secret_template'] == "Windows Account":
            if not module.params['secret_machine_name']:
                module.fail_json(msg="secret_machine_name not provided")
            module_result = create_windows_secret(secret_server_logon,
                                                  module.params['secret_folder'],
                                                  module.params['secret_template'],
                                                  module.params['secret_name'],
                                                  module.params['secret_machine_name'],
                                                  module.params['secret_username'],
                                                  secret_password,
                                                  module.params['secret_notes']
                                                  )
        if (module.params['secret_template']).lower() == "password":
            module_result = create_password_secret(secret_server_logon,
                                                   module.params['secret_folder'],
                                                   module.params['secret_template'],
                                                   module.params['secret_name'],
                                                   module.params['secret_resource'],
                                                   module.params['secret_username'],
                                                   secret_password,
                                                   module.params['secret_notes']
                                                   )
        result['changed'] = True

    if not module_result['items']:
        module.fail_json(msg='Secret could not be created')

    for item in module_result['items']:
        if item['fieldName'] == 'Username':
            secret_username = item['itemValue']
        if item['fieldName'] == 'Password':
            secret_password = item['itemValue']

    if not secret_username:
        module.fail_json(msg='Secret does not have a username')

    if not secret_password:
        module.fail_json(msg='Secret does not have a password')

    if module.params['sha512_encrypt_password']:
        secret_password = sha512_crypt.using(rounds=5000).hash(secret_password)

    result['secret'] = dict(secret_username=secret_username,
                            secret_password=secret_password)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
