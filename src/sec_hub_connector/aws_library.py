
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
import config
import requests
import boto3
import datetime
import uuid
import ilo_library


# Getting AWS session to make AWS API calls
def get_sec_hub_session(region):
    session = boto3.Session()
    credentials = session.get_credentials()
    credentials = credentials.get_frozen_credentials()
    sec_hub_client = session.client('securityhub',
                                    aws_session_token=credentials.token,
                                    aws_access_key_id=credentials.access_key,
                                    aws_secret_access_key=credentials.secret_key,
                                    region_name=region)
    return sec_hub_client


# Getting AWS session credentials
def get_aws_credentials():
    session = boto3.Session()
    credentials = session.get_credentials()
    # credentials = credentials.get_frozen_credentials()
    return credentials


# Getting the EC2 region for the SHC instance
def get_ec2_instance_region():
    r = requests.get("http://169.254.169.254/latest/dynamic/instance-identity/document")
    response_json = r.json()
    region = response_json.get('region')
    # instance_id = response_json.get('instanceId')
    return region


# Getting the accountId for the SHC instance
def get_shc_instance_account_id():
    r = requests.get("http://169.254.169.254/latest/dynamic/instance-identity/document")
    response_json = r.json()
    account_id = response_json.get('accountId')
    return account_id


# Getting the private IP for the SHC instance
def get_instance_private_ip():
    r = requests.get("http://169.254.169.254/latest/dynamic/instance-identity/document")
    response_json = r.json()
    private_ip = response_json.get('privateIp')
    return private_ip


# Getting insights from AWS security hub
def get_sec_hub_insights(sec_hub_client):
    response = sec_hub_client.get_insights()
    return response


# Getting findings from AWS security hub
def get_sec_hub_findings(sec_hub_client):
    response = sec_hub_client.get_findings()
    return response


# Getting Illumio generated findings from AWS security hub
def get_illumio_sec_hub_findings(sec_hub_client):
    return sec_hub_client.get_findings(
           Filters={
                       'CompanyName': [{
                                        'Value': 'Personal',
                                        'Comparison': 'EQUALS'
                                       }, ]
                    }
                  )


# Function to generate an AWS ARN for a specific instance
def get_aws_instance_arn(instance_id):
    return "arn:aws:ec2:" + get_ec2_instance_region() + ":" + get_shc_instance_account_id() + ":instance/" + instance_id


# Getting EC2 session client to get metadata from AWS EC2
def get_ec2_session_client(region):
    session = boto3.Session()
    credentials = session.get_credentials()
    credentials = credentials.get_frozen_credentials()
    ec2_client = session.client('ec2', aws_session_token=credentials.token,
                                aws_access_key_id=credentials.access_key,
                                aws_secret_access_key=credentials.secret_key,
                                region_name=region)
    return ec2_client


# Gather instance metadata for EC2 instance deployed in this particular region
# Required metadata is defined by Amazon Security Finding Format
def get_ec2_instance_metadata(instance_id, region):
    instance_metadata = {}
    ec2 = boto3.resource('ec2', region)
    instance = ec2.Instance(instance_id)
    instance_metadata = {
                      'Details': {
                             'AwsEc2Instance': {
                                                'ImageId': instance.image_id,
                                                'IpV4Addresses': [instance.private_ip_address, instance.public_ip_address],
                                                'KeyName': str(instance.key_name),
                                                'LaunchedAt': str(instance.launch_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'),
                                                'SubnetId': instance.subnet_id,
                                                'Type':  instance.instance_type,
                                                'VpcId': instance.vpc_id,
                                               },
                                 },
                      'Id': get_aws_instance_arn(instance.instance_id),
                      'Region': get_ec2_instance_region(),
                      # Hardcoded to aws assuming no CN or Gov deployments
                      'Partition': 'aws',
                      'Tags':  instance.tags[0],
                      # Hardcoded to instance for the initial release
                      'Type': 'AwsEc2Instance'
                        }
    return instance_metadata


def get_network_info(input):
    if input == 'O' or input == 'outbound':
        return 'OUT'
    elif input == 'I' or input == 'inbound':
        return 'IN'
    elif input == 17:
        return 'UDP'
    elif input == 6:
        return 'TCP'
    elif input == 1:
        return 'ICMP'
    else:
        return 'IN'


# Function used to create a finding object based on the workload and event info
# received from Illumio PCE and instance metadata retrieved from EC2
# Findings adhere to ASFF defined here: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
def populate_sec_hub_finding(workload_event, workload_info, workload_metadata):
    finding = {
             'SchemaVersion': "2018-10-08",
             'Id': "{}/{}/{}/{}".format(get_ec2_instance_region(), get_shc_instance_account_id(), workload_info['href'], str(uuid.uuid1())),
             'ProductArn': 'arn:aws:securityhub:{}:{}:product/{}/default'.format(get_ec2_instance_region(), get_shc_instance_account_id(), get_shc_instance_account_id()),
             'GeneratorId': 'illumio-ven-{}'.format(workload_info['agent']['status']['instance_id']),
             'AwsAccountId': get_shc_instance_account_id(),
             'UpdatedAt': "{}Z".format(datetime.datetime.utcnow().isoformat()),
             'CreatedAt': "{}Z".format(datetime.datetime.utcnow().isoformat()),
             'Confidence': 100,
             'Resources': [workload_metadata]
              }
    if 'policy_decision' in workload_event:
        finding.update({
               'Types': ['Unusual Behavior/Network flows'],
               'FirstObservedAt': workload_event['timestamp_range']['first_detected'],
               'LastObservedAt': workload_event['timestamp_range']['last_detected'],
               'Severity': {
                          'Product': 5,
                          'Normalized': 54
                         },
               'Title': 'Blocked Traffic Event for Workload {} generated by Illumio PCE'.format(workload_info['agent']['status']['instance_id']),
               'Description': 'This is a blocked traffic event for workload with aws id {} and has the labels as {} in Illumio ASP'.format(workload_info['agent']['status']['instance_id'],
                                                                                                                                           ilo_library.get_workload_labels(workload_event)),
               'Network': {
                          'Direction': get_network_info(workload_event['flow_direction']),
                          'Protocol':  get_network_info(workload_event['service']['proto']),
                          'SourceIpV4': workload_event.get('src', {}).get('ip'),
                          'SourcePort': 0,
                          'DestinationIpV4': workload_event.get('dst', {}).get('ip'),
                          'DestinationPort': workload_event.get('service', {}).get('port', 0)
                         },
               'ProductFields': {
                          'Illumio/888888888888/WorkloadHref': str(workload_event.get('dst', {}).get('workload', {}).get('href')),
                          'Illumio/888888888888/PCE': config.PCE,
                          'Illumio/888888888888/OsId': workload_info['os_id'],
                          'Illumio/888888888888/PolicyMode': workload_info.get('agent', {}).get('config', {}).get('mode'),
                          'Illumio/888888888888/PolicyDecision': workload_event['policy_decision'],
                          'Illumio/888888888888/FlowCount': str(workload_event['num_connections']),
                          'Illumio/888888888888/SourceWorkloadHref': str(workload_event.get('src', {}).get('workload', {}).get('href')),
                          'Illumio/888888888888/SourceWorkloadLabels': json.dumps(ilo_library.get_workload_labels(workload_event, None, 'src')),
                          'Illumio/888888888888/DestWorkloadLabels': json.dumps(ilo_library.get_workload_labels(workload_event, None, 'dst'))
                      }
                })
    else:
        finding.update({
             'Types': ['Unusual Behaviors/Process'],
             'FirstObservedAt': workload_event['timestamp'],
             'LastObservedAt': workload_event['timestamp'],
             'Severity': {
                          'Product': 6,
                          'Normalized': 63
                         },
             'Confidence': 100,
             'Title': 'Agent Tampering Event for Workload {} generated by Illumio PCE'.format(workload_info['agent']['status']['instance_id']),
             'Description': 'This is a agent tampering event for workload with aws id {} and has the labels as {} in Illumio ASP'.format(workload_info['agent']['status']['instance_id'],
                                                                                                                                         ilo_library.get_workload_labels(None, workload_info)),
             'Network': {
                          'SourceIpV4': workload_event['action']['src_ip']
                      },
             'ProductFields': {
                          'Illumio/888888888888/WorkloadHref': workload_info['href'],
                          'Illumio/888888888888/WorkloadLabels': json.dumps(ilo_library.get_workload_labels(None, workload_info)),
                          'Illumio/888888888888/PCE': config.PCE,
                          'Illumio/888888888888/OsId': workload_info['os_id'],
                          'Illumio/888888888888/PolicyMode': workload_info.get('agent', {}).get('config', {}).get('mode'),
                          'Illumio/888888888888/EventStatus': workload_event['status'],
                          'Illumio/888888888888/NumOfReverts': str(workload_event['notifications'][0]['info']['num_reverts']),
                          'Illumio/888888888888/RevertSuccessful': str(workload_event['notifications'][0]['info']['tampering_revert_succeeded'])
                      }
               })
    return finding


# Wrapper function to invoke creation of finding objects and then
# calling the Batch import findings to post the findings to Security Hub
def post_sec_hub_findings(eventsTime, workload_dict, workload_href, eventType, logger):
    findings = []
    workload_info = workload_dict['workloads'][workload_href]
    workload_metadata = workload_dict[workload_info['agent']['status']['instance_id']]
    logger.info({'workload_info': workload_info})
    logger.info({'workload_metadata': workload_metadata})
    region = get_ec2_instance_region()
    findings = create_sec_hub_finding(eventsTime, workload_info, workload_metadata, eventType, logger)
    region = get_ec2_instance_region()
    sec_hub_client = get_sec_hub_session(region)
    RelatedFindings = []
    for finding in findings:
        finding_dict = {}
        finding_dict['ProductArn'] = finding['ProductArn']
        finding_dict['Id'] = finding['Id']
    for finding in findings:
        # Only 10 related findings are allowed by ASFF
        if len(RelatedFindings) > 0:
            if len(RelatedFindings) > 10:
                finding['RelatedFindings'] = RelatedFindings[:10]
        logger.info({'finding': finding})
    response = {"error": "no response"}
    if len(findings) > 0:
        response = batch_import_sec_hub_findings(sec_hub_client, findings)
    return response


# Invoke creation of Security Hub finding object based on the event type
# configured in the SHC config - currently in the config.yml
def create_sec_hub_finding(eventsTime, workload_info, workload_metadata, eventType, logger):
    status = {}
    status['time'] = str(datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z')
    if eventType == 'blockedTraffic':
        workload_events = ilo_library.workload_blocked_traffic_events(eventsTime, workload_info['href'], logger)
    elif eventType == 'venTampering':
        logger.info('The workload hostname is ' + str(workload_info['hostname']))
        workload_events = ilo_library.get_workload_tampering_events(eventsTime, workload_info['agent']['href'], logger)
    elif eventType == 'all':
        workload_events = ilo_library.workload_blocked_traffic_events(eventsTime, workload_info['href'], logger)
        response = ilo_library.get_workload_tampering_events(eventsTime, workload_info['agent']['href'], logger)
        logger.info({'tampering_events': response})
        workload_events = workload_events + response
        # workload_events += ilo_library.get_workload_tampering_events(eventsTime, workload_info['agent']['href'], logger)
    else:
        # Fall back to Blocked Traffic events
        workload_events = ilo_library.workload_blocked_traffic_events(eventsTime, workload_info['href'], logger)
    findings = []
    count = 0
    for event in workload_events:
        logger.info({'event': event})
        count += 1
        sec_hub_finding = populate_sec_hub_finding(event, workload_info, workload_metadata)
        findings.append(sec_hub_finding)
        logger.info({'count': count})
    status['count'] = len(findings)
    return findings


# Wrapper for AWS batch_import_findings
def batch_import_sec_hub_findings(sec_hub_client, findings):
    resp = sec_hub_client.batch_import_findings(Findings=findings)
    print(resp)
    return resp
