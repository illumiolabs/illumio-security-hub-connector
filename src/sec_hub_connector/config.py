
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

"""
Configuration for running the illumio integration with AWS security hub

"""
import os

PCE_API = int(os.getenv('ILO_API_VERSION', '2'))
PCE = os.path.join('https://' + os.getenv('ILLUMIO_SERVER') + ':' + os.getenv('ILO_PORT'), 'api', 'v%d' % PCE_API)
ORG_ID = os.getenv('ILO_ORG_ID', '3')
KEY = 'api_' + os.getenv('ILO_API_KEY_ID')
SECRET = os.getenv('ILO_API_KEY_SECRET')
timer = 600
eventType = 'all'
