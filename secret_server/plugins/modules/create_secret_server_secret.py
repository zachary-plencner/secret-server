#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: create_secret_server_secret

short_description: Create a secret in Delineas Secret Server

version_added: "1.0.0"

description: |
    Create a secret in Delineas Secret Server using the Secret Servers API as a backend.
    Returns a secret variable that contains information about the secret and it's fields.

options:
    secret_server_host:
        description: The hostname of your Secret Server instance
        required: true
        type: str
    secret_server_username_domain:
        description: The domain pertaining to your username. This is prepend to your username (mutually exclusive with SDK authentication)
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
    secret_items:
        description: Additional parameters for the chosen secret template
        required: False
        type: dict
    use_random_password:
        description: When true will generate a random password with requirements for secret_items.Password
        required: False
        type: bool
    random_password_alphabet:
        description: String containing all allowed characters for random password generation
        required: False
        type: str
    random_password_length:
        description: Number of characters the random password will contains
        required: False
        type: int
    random_password_uppercase_requirement:
        description: Minimum number of uppercase characters the random password will contain
        required: False
        type: int
    random_password_lowercase_requirement:
        description: Minimum number of lowercase characters the random password will contain
        required: False
        type: int
    random_password_digit_requirement:
        description: Minimum number of digit characters the random password will contain
        required: False
        type: int
    random_password_special_requirement:
        description: Minimum number of special characters the random password will contain
        required: False
        type: int
    sha512_encrypt_password:
        description: Output for password parameter will be sha512 encrypted for security purposes
        required: False
        type: bool
    secret_overwrite:
        description: Flag to enable overwriting of an existing secret. If true, everytime this module runs the secret password will be changed to the specified password or a new random password if use_random_password is true.
        required: False
        type: bool

author:
    - Zachary Plencner (@zachary-plencner)
'''

EXAMPLES = r'''
# Create a 'Windows Account' Secret
- name: Create a new static secret "My Workstation" from the "Windows Account" secret template, using a local Secret Server account
    create_windows_secret_server_secret:
      secret_server_host: 'https://contoso.secretservercloud.com'
      secret_server_username_domain: "contoso"
      secret_server_username: "john.doe"
      secret_server_password: "password123"
      secret_folder: "/My Secrets"
      secret_name: "My Workstation"
      secret_template: "Windows Account"
      secret_items:
        Machine: "DESKTOP-Q66XZA5"
        Username: "jdoe"
        Password: "password123"

# Create a 'Active Directory Account" Secret with random password
- name: Create a new randmomly generated secret "jdoe1 AD password" from the "Active Directory Account" template, allowing for regeneration with secret_overwrite on subsequent runs, using the SDK
    create_windows_secret_server_secret:
      secret_server_host: 'https://contoso.secretservercloud.com'
      secret_server_username_domain: "contoso"
      use_sdk: yes
      sdk_config_directory: /home/ansible/secret-server-sdk
      secret_folder: "/My Secrets/Active Directory Secrets/jdoe1"
      secret_name: "jdoe1 AD password"
      secret_template: "Active Directory Account"
      secret_items:
        Username: "jdoe1"
        Domain: "contoso"
        Notes: "My AD Secret"
    use_random_password: yes
    random_password_length: 12
    random_password_alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzy0123456789!@$%^&'
    random_password_uppercase_requirement: 1
    random_password_lowercase_requirement: 1
    random_password_digit_requirement: 1
    random_password_special_requirement: 1
    secret_overwrite: True

# Create a 'Password' Secret with the SDK
- name: Create secret and sha512_encrypt_password for use with other modules (e.g. Linux system account creation)
    create_windows_secret_server_secret:
      secret_server_host: 'https://contoso.secretservercloud.com'
      use_sdk: yes
      sdk_config_directory: /etc/secret-server-sdk
      secret_folder: "/My Secrets/Linux Secrets"
      secret_name: "database-1 secret"
      secret_template: "Password"
      secret_items:
        Username: "root"
        Password: "Q1am9a!aSl"
        Resource: "database-1"
        Notes: "Root login for database-1"
    sha512_encrypt_password: yes
    secret_overwrite: True
'''

RETURN = r'''
secret:
    description: The retrieved secret
    type: dict
    returned: always
    sample: {
        secret: {
            "password": "password123",
            "username": "username1",
            "exmaple_field_1": "exmaple_field_value_1",
            "exmaple_field_2": "exmaple_field_value_2",
            "exmaple_field_n": "exmaple_field_value_n",
        }
    }
'''www

from ansible.module_utils.basic import AnsibleModule
import requests
import subprocess
import os
import copy
import random
from passlib.hash import sha512_crypt

# Conversion mappings for the convert_secret function
supported_conversions = {
    'windows account': {'password': {'mapping': [['Machine', 'Resource'], ['Username', 'Username'], ['Password', 'Password'], ['Notes', 'Notes']]},
                        'unix account (ssh)': {'mapping': [['Machine', 'Machine'], ['Username', 'Username'], ['Password', 'Password'], ['Notes', 'Notes']]}
                        },
    'password': {'windows account': {'mapping': [['Resource', 'Machine'], ['Username', 'Username'], ['Password', 'Password'], ['Notes', 'Notes']]},
                 'unix account (ssh)': {'mapping': [['Resource', 'Machine'], ['Username', 'Username'], ['Password', 'Password'], ['Notes', 'Notes']]}
                 },
    'unix account (ssh)': {'windows account': {'mapping': [['Machine', 'Machine'], ['Username', 'Username'], ['Password', 'Password'], ['Notes', 'Notes']]},
                           'password': {'mapping': [['Machine', 'Resource'], ['Username', 'Username'], ['Password', 'Password'], ['Notes', 'Notes']]}
                           }
}


# Transform a dictionary to index by specific key in each dict
def json_index_transform(dictionary, key):
    transformed_dictionary = {}
    for sub_dictionary in dictionary:
        transformed_dictionary[sub_dictionary[key]] = sub_dictionary

    return transformed_dictionary


# object for maintaining session to Secret Server
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


# API delete method
def delete(secret_server_logon, endpoint):
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.delete(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar)

    return r.json()


def get_folder(secret_server_logon, folder_path):
    if folder_path[0] != '/':
        folder_path = '/' + folder_path
    endpoint = '/folders/0?folderPath=' + folder_path
    folder = get(secret_server_logon, endpoint)
    if 'id' not in folder:
        print('Unable to locate a folder with path \'{}\''.format(folder_path))
        exit()

    return folder


# Get a template's ID using its name
def get_template_id(secret_server_logon, template_name):
    endpoint = '/templates'
    templates = get(secret_server_logon, endpoint)

    templateID = None
    for template in templates:
        if template['name'] == template_name:
            templateID = template['id']

    if templateID is None:
        print("Template with name: \'{}\', does not exist".format(template_name))
        exit()

    return templateID


# Get a template's name using its ID
def get_template_name(secret_server_logon, template_id):
    endpoint = '/templates'
    templates = get(secret_server_logon, endpoint)
    templateName = None
    for template in templates:
        if template['id'] == template_id:
            templateName = template['name']

    if templateName is None:
        print("Template with id: \'{}\', does not exist".format(template_id))
        exit()

    return templateName


# Create a new secret
def create_secret(secret_server_logon, secret_folder, secret_template, secret_name, items):
    folder_id = get_folder(secret_server_logon, secret_folder)['id']
    template_id = get_template_id(secret_server_logon, secret_template)

    endpoint = '/secrets/stub?filter.secrettemplateid=' + str(template_id)
    secret_stub = get(secret_server_logon, endpoint)

    endpoint = '/secret-templates/' + str(template_id)
    template = get(secret_server_logon, endpoint)

    missingParameters = []
    for field in template['fields']:
        if field['isRequired']:
            if field['displayName'] not in items:
                missingParameters.append(field['displayName'])

    if len(missingParameters):
        print("Missing required secret_items: {}".format(missingParameters))
        exit()

    template_fieldNames = json_index_transform(template['fields'], 'displayName')
    for item_fieldName in items:
        if item_fieldName not in template_fieldNames:
            print('Could not find an item with name: \'{}\' in the \'{}\' template'.format(item_fieldName, template['name']))
            exit()

    for field in template['fields']:
        if field['displayName'] in items:
            if field['isFile']:
                print('Unsupported field (isFile=True): {}'.format(field['displayName']))
                exit()
            for item in secret_stub['items']:
                if item['fieldName'] == field['displayName']:
                    item['itemValue'] = items[field['displayName']]

    secret_stub['name'] = secret_name
    secret_stub['secretTemplateId'] = template_id
    secret_stub['AutoChangeEnabled'] = False
    secret_stub['autoChangeNextPassword'] = ""
    secret_stub['SiteId'] = 1
    secret_stub['folderId'] = folder_id
    secret_stub['active'] = True
    secret_stub['IsDoubleLock'] = False

    endpoint = '/secrets'
    secret = post(secret_server_logon, endpoint, secret_stub)

    return secret


# Retreive a secret
def get_secret(secret_server_logon, search_term):
    endpoint = '/secrets?filter.includeRestricted=true&filter.isExactMatch=true&filter.searchtext=' + search_term
    secret = get(secret_server_logon, endpoint)
    if not secret['records']:
        return None

    secret_id = secret['records'][0]['id']
    endpoint = '/secrets/' + str(secret_id)
    secret = get(secret_server_logon, endpoint)

    return secret


# Change a secret's items
def change_secret(secret_server_logon, existing_secret, secret_folder, secret_template, secret_name, items):
    folder_id = get_folder(secret_server_logon, secret_folder)['id']
    template_id = get_template_id(secret_server_logon, secret_template)

    secret_stub = copy.deepcopy(existing_secret)

    endpoint = '/secret-templates/' + str(template_id)
    template = get(secret_server_logon, endpoint)

    missingParameters = []
    for field in template['fields']:
        if field['isRequired']:
            if field['displayName'] not in items:
                missingParameters.append(field['displayName'])

    if len(missingParameters):
        print("Missing required secret_items: {}".format(missingParameters))
        exit()

    template_fieldNames = json_index_transform(template['fields'], 'displayName')
    for item_fieldName in items:
        if item_fieldName not in template_fieldNames:
            print('Could not find an item with name: \'{}\' in the \'{}\' template'.format(item_fieldName, template['name']))
            exit()

    for field in template['fields']:
        if field['displayName'] in items:
            if field['isFile']:
                print('Unsupported field (isFile=True): {}'.format(field['displayName']))
                exit()
            for item in secret_stub['items']:
                if item['fieldName'] == field['displayName']:
                    item['itemValue'] = items[field['displayName']]

    secret_stub['name'] = secret_name
    secret_stub['folderId'] = folder_id

    if secret_stub != existing_secret:
        endpoint = '/secrets/' + str(existing_secret['id'])
        secret = put(secret_server_logon, endpoint, secret_stub)
        return secret
    else:
        return None


# Convert a secret using defined mappings
def convert_secret(secret_server_logon, existing_secret, destination_template_id):
    endpoint = '/secrets/get-convert-info'
    body = dict(
        data=dict(secretIds=[existing_secret['id']],
                  destinationTemplateId=destination_template_id
                  )
    )
    template_convert_info = post(secret_server_logon, endpoint, body)
    source_template_fields = json_index_transform(existing_secret['items'], 'fieldName')
    destination_template_fields = json_index_transform(template_convert_info['destination']['fields'], 'name')

    source_template_name = template_convert_info['source']['templateName'].lower()
    destination_template_name = get_template_name(secret_server_logon, destination_template_id).lower()

    fieldMapping = []
    if source_template_name in supported_conversions and \
            supported_conversions[source_template_name][destination_template_name] in supported_conversions[source_template_name]:
        for convert_field in supported_conversions[source_template_name][destination_template_name]['mapping']:
            fieldMapping.append({'destinationFieldId': destination_template_fields[convert_field[1]]['id'],
                                 'sourceFieldId': source_template_fields[convert_field[0]]['fieldId'],
                                 'sourceFieldValue': source_template_fields[convert_field[0]]['itemValue']
                                 })
    else:
        print('No supported mapping to convert from \'{}\' to \'{}\''.format(source_template_name, destination_template_name))
        exit()

    endpoint = '/secrets/convert-template'
    body = dict(
        data=dict(secretIds=[existing_secret['id']],
                  secretTemplateId=destination_template_id,
                  newSecretName=existing_secret['name'],
                  fieldMapping=fieldMapping
                  )
                )
    r = post(secret_server_logon, endpoint, body)

    endpoint = '/secrets/' + str(r['secretId'])

    existing_secret = get(secret_server_logon, endpoint)
    return existing_secret


# Deactivate a secret with its ID
def deactivate_secret(secret_server_logon, secret_id):
    endpoint = '/secrets/' + str(secret_id)
    r = delete(secret_server_logon, endpoint)
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
        secret_folder=dict(type='str', required=True),
        secret_template=dict(type='str', required=True),
        secret_name=dict(type='str', required=True),
        secret_username=dict(type='str', required=False),
        secret_password=dict(type='str', no_log=False, required=False),
        use_random_password=dict(type='bool', no_log=False, required=False, default=False),
        random_password_length=dict(type='int', no_log=False, required=False),
        random_password_alphabet=dict(type='str', no_log=False, required=False),
        random_password_lowercase_requirement=dict(type='int', no_log=False, required=False),
        random_password_uppercase_requirement=dict(type='int', no_log=False, required=False),
        random_password_digit_requirement=dict(type='int', no_log=False, required=False),
        random_password_special_requirement=dict(type='int', no_log=False, required=False),
        secret_overwrite=dict(type='bool', required=False, default=False),
        sha512_encrypt_password=dict(type='bool', no_log=False, required=False, default=False),
        secret_items=dict(type='dict', required=False, default={})
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

    # Generate a random password with requirements
    if module.params['use_random_password']:
        random_password_length = module.params['random_password_length'] if module.params['random_password_length'] else 8
        random_password_alphabet = module.params['random_password_alphabet'] if module.params['random_password_alphabet'] \
            else 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()'
        random_password_lowercase_requirement = module.params['random_password_lowercase_requirement'] if \
            module.params['random_password_lowercase_requirement'] else 0
        random_password_uppercase_requirement = module.params['random_password_uppercase_requirement'] if \
            module.params['random_password_uppercase_requirement'] else 0
        random_password_digit_requirement = module.params['random_password_digit_requirement'] if \
            module.params['random_password_digit_requirement'] else 0
        random_password_special_requirement = module.params['random_password_special_requirement'] if \
            module.params['random_password_special_requirement'] else 0
        random_password_requirements_sum = random_password_lowercase_requirement + random_password_uppercase_requirement \
            + random_password_digit_requirement + random_password_special_requirement

        if random_password_length < random_password_requirements_sum:
            module.fail_json(msg='random_password_length: {}, \
                cannot be less than random_password_<char_type>_requirements sum: {}'.format(random_password_length, random_password_requirements_sum))
        if random_password_uppercase_requirement and not any(c.isupper() for c in random_password_alphabet):
            module.fail_json(msg='random_password_uppercase_requirement > 0, but \
                random_password_alphabet does not contain any uppercase characters to choose from')
        if random_password_lowercase_requirement and not any(c.islower() for c in random_password_alphabet):
            module.fail_json(msg='random_password_lowercase_requirement > 0, but \
                random_password_alphabet does not contain any lowercase characters to choose from')
        if random_password_digit_requirement and not any(c.isdigit() for c in random_password_alphabet):
            module.fail_json(msg='random_password_digit_requirement > 0, but \
                random_password_alphabet does not contain any digit characters to choose from')
        if random_password_special_requirement and not any(not c.isalnum() for c in random_password_alphabet):
            module.fail_json(msg='random_password_special_requirement > 0, but \
                random_password_alphabet does not contain any special characters to choose from')
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

        module.params['secret_items']['Password'] = secret_password

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # if user specified a domain, append it to username
    if module.params['secret_server_username_domain']:
        secret_server_username = "{}\\{}".format(module.params['secret_server_username_domain'], module.params['secret_server_username'])
    else:
        secret_server_username = module.params['secret_server_username']

    # Create LogOn session object for rest of module
    secret_server_logon = LogOn(module.params['secret_server_host'],
                                secret_server_username,
                                module.params['secret_server_password'],
                                module.params['use_sdk'],
                                module.params['sdk_config_directory']
                                )

    # Try to find existing secret
    existing_secret = get_secret(secret_server_logon,
                                 module.params['secret_name']
                                 )

    # Overwrite secret if one already exists and secret_overwrite is True
    if existing_secret and module.params['secret_overwrite']:
        # Recreate the secret if the template is different
        if existing_secret['secretTemplateId'] != get_template_id(secret_server_logon,
                                                                  module.params['secret_template']
                                                                  ):
            module_result = create_secret(secret_server_logon,
                                          module.params['secret_folder'],
                                          module.params['secret_template'],
                                          module.params['secret_name'],
                                          module.params['secret_items']
                                          )

            # Deactivate the existing secret using the old template
            deactivate_secret(secret_server_logon, existing_secret['id'])
            result['changed'] = True
        else:
            # Change a secret's parameters if it already exists
            module_result = change_secret(secret_server_logon,
                                          existing_secret,
                                          module.params['secret_folder'],
                                          module.params['secret_template'],
                                          module.params['secret_name'],
                                          module.params['secret_items']
                                          )
            if not module_result:
                module_result = existing_secret
            else:
                result['changed'] = True

    # Return existing secret if it already exists and overwrite is false
    elif existing_secret and not module.params['secret_overwrite']:
        module_result = existing_secret
        result['changed'] = False

    # If the secret doesn't exist, create a new one
    else:
        module_result = create_secret(secret_server_logon,
                                      module.params['secret_folder'],
                                      module.params['secret_template'],
                                      module.params['secret_name'],
                                      module.params['secret_items']
                                      )
        result['changed'] = True

    # No secret was returned => error
    if not module_result['items']:
        module.fail_json(msg='Unhandled error: secret was not created')

    for item in module_result['items']:
        module_result[str(item['fieldName'])[0].lower() + str(item['fieldName'])[1:]] = item['itemValue']

    # module_result_items = json_index_transform(module_result['items'], 'fieldName')
    # Populate result variable for Ansible
    # module_result |= module_result_items
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
