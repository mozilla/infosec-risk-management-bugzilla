import boto3
import json
import os
import logging


class AWSParameterstoreProvider(object):
    """Support loading secure strings from AWS parameter store."""

    def __init__(self, region):
        self.region_name = region
        self.boto_session = boto3.session.Session(region_name=self.region_name)
        self.ssm_client = self.boto_session.client('ssm')

    def key(self, key_name):
        ssm_response = self.ssm_client.get_parameter(
            Name='{}'.format(key_name),
            WithDecryption=True
        )

        result = ssm_response.get('Parameter')
        return result.get('Value')
