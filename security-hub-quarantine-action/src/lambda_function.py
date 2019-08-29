#   Copyright 2019 Illumio, Inc.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import json
import os
from botocore.vendored import requests


# PCE API request call using requests module
def pce_request(pce, org_id, key, secret, verb, path, params=None,
                data=None, json=None, extra_headers=None):
    base_url = os.path.join(pce, 'orgs', org_id)
    print(base_url)
    headers = {
              'user-agent': 'aws-lambda-quarantine',
              'accept': 'application/json',
            }
    # PCE URL
    print(os.path.join(base_url, path))
    # Request Payload
    print(json)
    response = requests.request(verb,
                                os.path.join(base_url, path),
                                auth=(key, secret),
                                headers=headers,
                                params=params,
                                json=json,
                                data=data)
    return response


def lambda_handler(event, context):
    # Getting the data from environment variables for the PCE API request
    pce_api = int(os.environ['ILO_API_VERSION'])
    pce = os.path.join('https://' + os.environ['ILLUMIO_SERVER'] + ':' + os.environ['ILO_PORT'], 'api', 'v%d' % pce_api)
    org_id = os.environ['ILO_ORG_ID']
    key = 'api_' + os.environ['ILO_API_KEY_ID']
    secret = os.environ['ILO_API_KEY_SECRET']
    app_label = os.environ['APP_LABEL']
    env_label = os.environ['ENV_LABEL']
    loc_label = os.environ['LOC_LABEL']
    print('Illumio Quarantine Action using Lambda Function')
    print(event)
    # Verifying if the event is received from Security Hub
    if event.get('source') == 'aws.securityhub':
        if 'findings' in event['detail']:
            for finding in event['detail']['findings']:
                # Getting the workload href and label information from the AWS finding
                instance_href = finding.get('ProductFields', {}).get('Illumio/888888888888/SourceWorkloadHref', None)
                instance_labels = json.loads(finding.get('ProductFields', {}).get('Illumio/888888888888/SourceWorkloadLabels', None))
                print(instance_href, instance_labels)
                # Checking if the workload is not Quarantined already
                if instance_labels is not None and instance_labels.get('app') != 'Quarantine':
                    data = {'workloads':
                            [
                                {
                                    'href': instance_href
                                }
                            ],
                            'label_keys': ['role']
                            }
                    # PCE API request to Remove existing role label
                    response = pce_request(pce, org_id, key, secret, 'PUT', 'workloads/remove_labels', json=data)
                    print(response)
                    label_data = {'workloads':
                                  [
                                      {
                                          'href': instance_href
                                      }
                                  ],
                                  'labels':
                                  [
                                      {
                                          'href':  app_label  # Quarantine App label
                                      },
                                      {
                                          'href':  env_label  # Production Environment Label
                                      },
                                      {
                                          'href':  loc_label  # Quarantine Location Label
                                      }
                                  ],
                                  'delete_existing': False
                                  }
                    # PCE API request to set Quarantine Labels according to the Quarantine policy scope
                    set_response = pce_request(pce, org_id, key, secret, 'PUT', 'workloads/set_labels', json=label_data)
                    print(set_response)
    return {
        'statusCode': 200,
        'greeting': json.dumps('Hello from Lambda!'),
        'body': json.dumps(event)
    }
