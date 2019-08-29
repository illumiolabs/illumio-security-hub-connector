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
import aws_library
import ilo_library
import logging
from logging.handlers import RotatingFileHandler
import datetime
import time


# Main function invoking PCE API wrapper and AWS API wrappers
def main():
    # Loop to continuously poll and get events from the PCE
    # every config.timer interval
    while(True):
        # ILO events API wrapper
        workload_dict = ilo_library.get_workloads_dict(
                        aws_library.get_ec2_instance_region()
                                                      )
        eventsTime = {
                'startTime': datetime.datetime.now() - datetime.timedelta(seconds=config.timer),
                'endTime': datetime.datetime.now()
                     }
        response = {'Error': 'No response'}
        for workload in workload_dict['href']:
            workload_href = workload
            logger.info('The workload href is ' + str(workload_href))
            # AWS API wrapper
            response = aws_library.post_sec_hub_findings(
                       eventsTime, workload_dict, workload_href, config.eventType, logger
                                                        )
            logger.info({'post_response': json.dumps(response, indent=4)})
        time.sleep(config.timer)


if __name__ == '__main__':
    formatter = logging.Formatter(
                "[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s"
                                 )
    # Logging to log file
    handler = RotatingFileHandler('app.log', maxBytes=10000000, backupCount=15)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.addHandler(handler)
    StreamHandler = logging.StreamHandler()
    StreamHandler.setFormatter(formatter)
    log = logging.getLogger()
    log.setLevel(logging.INFO)
    log.addHandler(StreamHandler)
    main()
