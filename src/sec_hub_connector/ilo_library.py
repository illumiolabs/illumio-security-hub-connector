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

import os
import config
import requests
import aws_library


# Wrapper interface between python requests module and
# PCE API request parameters
def pce_request(verb, path, params=None, data=None, json=None,
                extra_headers=None):
    base_url = os.path.join(config.PCE, 'orgs', config.ORG_ID)
    headers = {
              'user-agent': 'aws-sec-hub-bridge',
              'accept': 'application/json',
    }
    # headers.update(extra_headers)
    response = requests.request(verb,
                                os.path.join(base_url, path),
                                auth=(config.KEY, config.SECRET),
                                headers=headers,
                                params=params,
                                json=json,
                                data=data)
    return response


# Getting Blocked Traffic events from the PCE for a particular workload
# within a particular time range
def workload_blocked_traffic_events(eventsTime, workload_href, logger):
    json = {
            'destinations': {
                             'include': [[{
                                           'workload': {
                                                        'href': workload_href
                                                       }
                                        }]],
                             'exclude': []
                            },
            'end_date': str(eventsTime['endTime'].strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'),
            'services': {
                         'include': [],
                         'exclude': []
            },
            'max_results': 1000,
            'policy_decisions': ['potentially_blocked', 'blocked'],
            'sources': {
                        'include': [[{
                                      'workload': {
                                                   'href': workload_href}}]],
                        'exclude': []
            },
            'start_date': str(eventsTime['startTime'].strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'),
            'sources_destinations_query_op': 'or'
           }
    logger.info({'request': json})
    return pce_request('POST',
                       'traffic_flows/traffic_analysis_queries',
                       json=json).json()


# Blocked Traffic events to test
def ilo_blocked_traffic_events():
    return pce_request('GET',
                       'blocked_traffic',
                       params={'max_results': 1}).json()


# Getting Agent Tampering events from the PCE for all workloads
# within a particular time range
def ilo_agent_tampering_events(eventsTime):
    return pce_request('GET',
                       'events',
                       params={'event_type': 'agent.tampering',
                               'severity': 'err',
                               'timestamp[gte]': str(eventsTime['startTime'].strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'),
                               'timestamp[lte]': str(eventsTime['endTime'].strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'),
                               'max_results': 1000}).json()


def ilo_agent_process_failure_events():
    return pce_request('GET',
                       'events',
                       params={'event_type': 'agent.process_failure',
                               'max_results': 100}).json()


# Get all workloads from the PCE
def ilo_get_workloads():
    return pce_request('GET',
                       'workloads',
                       params={'deleted': 'false',
                               'representation': 'workload_labels',
                               'max_results': 1000}).json()


# Get particular workload info from the PCE
def ilo_get_instance(id):
    return pce_request('GET',
                       str('workloads/' + id),
                       params={'deleted': 'false'}).json()


# Get tampering events for a particular workload
def get_workload_tampering_events(eventsTime, agent_href, logger):
    response = ilo_agent_tampering_events(eventsTime)
    tampering_events = {}
    tampering_events[agent_href] = []
    for event in response:
        if event['created_by']['agent']['href'] == agent_href:
            tampering_events[agent_href].append(event)
    return tampering_events[agent_href]


# Get labels for the workload received in the event
def get_workload_labels(workload_blocked_traffic=None, workload_info=None,
                        wl=None):
    labels = {}
    if wl == 'src' and workload_blocked_traffic is not None and 'workload' in workload_blocked_traffic['src']:
        label_source = workload_blocked_traffic['src']['workload']['labels']
    elif wl == 'dst' and workload_blocked_traffic is not None and 'workload' in workload_blocked_traffic['dst']:
        label_source = workload_blocked_traffic['dst']['workload']['labels']
    elif wl is None and workload_blocked_traffic is not None and 'workload' in workload_blocked_traffic['dst']:
        label_source = workload_blocked_traffic['dst']['workload']['labels']
    elif wl is None and workload_blocked_traffic is not None and 'workload' in workload_blocked_traffic['src']:
        label_source = workload_blocked_traffic['src']['workload']['labels']
    elif workload_info is not None and 'labels' in workload_info:
        label_source = workload_info['labels']
    else:
        return labels
    for label in label_source:
        if label['key'] == 'app':
            labels['app'] = label['value']
        elif label['key'] == 'env':
            labels['env'] = label['value']
        elif label['key'] == 'loc':
            labels['loc'] = label['value']
        elif label['key'] == 'role':
            labels['role'] = label['value']
        return labels


# Create a dictionary structure with workload info
# mapping to their instance IDs and HREFs
def get_workloads_dict(region):
    workloads = ilo_get_workloads()
    workload_dict = {}
    workload_dict['workloads'] = {}
    workload_dict['instance_id'] = {}
    workload_dict['href'] = []
    for workload in workloads:
        # Only add the workloads which have an AWS instance ID and
        # belong to the region of the SHC
        # Unmanaged workloads will not have status
        if workload['agent'].get('status', {}).get('instance_id', {}) and workload['data_center'].split('.')[0] == region:
            workload_dict['href'].append(workload['href'])
            workload_dict['workloads'][workload['href']] = workload
            workload_dict[workload['agent']['status']['instance_id']] = aws_library.get_ec2_instance_metadata(
                                                                    workload['agent']['status']['instance_id'], region)
            workload_dict['instance_id'][workload['agent']['status']['instance_id']] = workload['href']
    return workload_dict
