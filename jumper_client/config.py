#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
# Time: 2:01:21 PM
# Desc:
# Author: sendal
# Email: <schangech@gmail.com>
# Version: 0.0.1
"""

import os
import yaml
import socket
import urllib3
import requests
try:
    import json
except ImportError:
    import simplejson as json

requests.packages.urllib3.disable_warnings()
urllib3.disable_warnings()
socket.setdefaulttimeout(2)


class Config(object):

    def __init__(self, config_path='/rc/conf/rc-jumpser.yaml'):
        """
        读取配置
        """
        if not os.path.isfile(config_path):
            raise Exception('Config file "%s" not exist!' % config_path)

        with open(config_path, 'rt') as f:
            config = yaml.safe_load(f.read())

        self.metadata_url = config['metadata']['metadata_url']
        self.metadata_client_id = config['metadata']['metadata_client_id']
        self.metadata_secret = config['metadata']['metadata_secret']

        self.rdp_domain = config['rdp']['rdp_domain']
        self.rdp_port = config['rdp']['rdp_port']
        self.rdp_script = config['rdp']['rdp_script']
        self.rdp_key = config['rdp']['rdp_key']
        self.rdp_crt = config['rdp']['rdp_crt']

        self.log_dir = config['log']['log_dir']

        if not os.path.isfile(self.rdp_key):
            raise Exception('RDP key file "%s" not exist!' % self.rdp_key)
        if not os.path.isfile(self.rdp_crt):
            raise Exception('RDP crt file "%s" not exist!' % self.rdp_crt)

        self.rdp_port = [int(p) for p in self.rdp_port]
