from __future__ import annotations
from typing import Any, Dict, List
from typing_extensions import Literal, NotRequired, TypedDict
from model import *

import inspect
import os
import json
import requests
import socket
import sys
import time

# serve per hack
from requests.models import PreparedRequest, Response

##
# a simple class to abstract MetaDefender API calls
class API:
    url = "http://localhost:8008/"
    my_ip= (([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0]
    callback_url = "http://" + my_ip + ":8081/listenback"
    sanitized_url = "http://" + my_ip + ":8081/listensanitizedfile/"
    download_from = "http://" + my_ip + ":8081/downloadfrom/"
    user_logged= ''
    session_id = ''
    authorized=False
    home=os.getcwd()
    hack=True

    def __init__(self) ->None:
        pass
  
    ##
    # userLogin: login
    # https://docs.opswat.com/mdcore/metadefender-core#userlogin
    def userLogin(self, user = "", passwd = ""):
        UserLogin=TypedDict('UserLogin', {'user': str, 'password': str})
        UserLogin['user'] = user
        UserLogin['password'] = passwd
        url = self.url + "login"
        headers = {"Content-Type": "application/json"}
        response = requests.request("POST", url, headers=headers, data=json.dumps(UserLogin))
        #payload  = {
        #    "user": user,
        #    "password": passwd
        #}
        #response = requests.request("POST", url, headers=headers, data=json.dumps(payload))
        self.authorized = False
        if response.status_code == 200:
            data = json.loads(response.text)
            self.user_logged=user
            self.session_id = data["session_id"]
            self.authorized = True
        return self.authorized
    
    ##
    # userLogout: logout
    # https://docs.opswat.com/mdcore/metadefender-core#userlogout
    def userLogout(self)->None:
        url = self.url + "logout"
        headers = {"apikey": self.session_id}
        response = requests.request("POST", url, headers=headers)
        self.user_logged=''
        self.session_id=''
        self.authorized=False
        return

    ##
    # userChangePass: Change Password
    # https://docs.opswat.com/mdcore/metadefender-core#userchangepass
    def userChangePass(self, old="", new="")-> bool:
        url = self.url + "user/changepassword"
        headers = {
            "Content-Type": "application/json",
            "apikey": self.session_id
        }
        payload = {
            "old_password": old,
            "new_password": new
        }
        response = requests.request("POST", 
                                    url, 
                                    headers=headers, 
                                    data=json.dumps(payload))
        success = False
        if response.status_code == 200:
            success = True
        elif response.status_code == 400:
            print("bad request, eg invalid apikey")
        elif response.status_code == 405:
            print("the user has not right for this operation")
        elif response.status_code == 500:
            print("unaspected event on server")

        return success

    ##
    # ANALYSYS (complete)
    ##

    ##
    # -> str: data_id
    # https://docs.opswat.com/mdcore/metadefender-core#fileanalysispost
    # asynchronously
    def fileAnalysisPost(self, 
                         file_name="", 
                         file_path="", 
                         workflow="myworkflow") -> str:

        url: str = self.url + "file"
        # dovrei usare un TypedDict
        # AnalysisResult=TypedDict('AnalysisResult', {'data_id': str, 'file_info': FileInfo, 'scan_results': ScanResults})
        headers: dict = {
            "Content-Type": "application/octet-stream",
            "apikey": self.session_id,
            "filename": file_name,
            #"filepath": file_path,
            #"user_agent": "{user_agent}",
            #"rule": rule,
            "workflow": workflow,
            #"batch": "{batch}",
            #"archivepwd": "{archivepwd}",
            #"metadata": "{metadata}",
            #"engines-metadata": "{\n  \"charset\": \"ISO-2022-JP\",\n  \"content-type\": \"text/html\",\n  \"content-transfer-encoding\": \"quoted-printable\"\n}\n",
            "callback_url": self.callback_url,
            "sanitized_url": self.sanitized_url,
            #"downloadfrom": "{downloadfrom}",
            #"global-timeout": "{global-timeout}"
        }
        rawBytes = open(file_path + "/" + file_name, "rb")
        response = requests.request("POST", url, headers=headers, data=rawBytes)
        data = json.loads(response.text)
        data_id = data["data_id"]
        #printBlock(response)
        return data_id
   
    ##
    # -> str: data_id
    # https://docs.opswat.com/mdcore/metadefender-core#fileanalysissyncpost
    def fileAnalysisSyncPost(self, 
                             file_name="", 
                             file_path="", 
                             workflow="myworkflow") -> str:

        if self.hack:
            return "hack-data-id"

        url = self.url + "file/sync"
        headers = {
            "Content-Type": "application/octet-stream",
            "apikey": self.session_id,
            "filename": file_name,
            #"filepath": file_path,
            #"user_agent": "{user_agent}",
            #"rule": rule,
            "workflow": workflow,
            #"batch": "{batch}",
            #"archivepwd": "{archivepwd}",
            #"metadata": "{metadata}",
            #"engines-metadata": "{\n  \"charset\": \"ISO-2022-JP\",\n  \"content-type\": \"text/html\",\n  \"content-transfer-encoding\": \"quoted-printable\"\n}\n",
            #"callback_url": self.callback_url,
            #"sanitized_url": self.sanitized_url,
            #"downloadfrom": "{downloadfrom}",
            #"global-timeout": "{global-timeout}"
        }
        #payload = "\"<Payload in raw bytes>\""
        # payload = "\"{payload}\""

        rawBytes = open(file_path + "/" + file_name, "rb")
        response = requests.request("POST", url, headers=headers, data=rawBytes)
        data = json.loads(response.text)
        print("response.text: ", response.text )
        data_id = data["data_id"]
        #printBlock(response)
        return data_id

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#fileanalysisget
    def fileAnalysisGet(self, data_id=""):
        AnalysisResult=TypedDict('AnalysisResult', {'data_id': str, 'file_info': FileInfo, 'scan_results': ScanResults})
        url = self.url + "/file/" + data_id
        headers = {"apikey": self.session_id}
        response = requests.request("GET", url, headers=headers)
        data = json.loads(response.text)
        analysis_result = AnalysisResult(data_id=data_id, 
                                         file_info=data["file_info"], 
                                         scan_results=data["scan_results"])

        print("analysis_result: ", analysis_result)
        return analysis_result
        
        # precedente versione
        headers = {
            "apikey": self.session_id
            # "user_agent": string
        }
        # querystring = {"first":"{first}","size":"{size}"}
        querystring = {}
        response = requests.request("GET", url, headers=headers, params=querystring)
        #printBlock(response)
        return response


    ##
    # https://docs.opswat.com/mdcore/metadefender-core#retrieveblockedleaffile
    def retrieveBlockedLeafFile(self, data_id):
        url = self.url + "file/" + data_id +"/blocked-leaves"
        headers = {"apikey": self.session_id}
        response = requests.request("GET", url, headers=headers)
        #printBlock(response)
        return 0

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#fileanalysisgetallchildfiles
    def fileAnalysisGetAllChildFiles(self, data_id):
        url = self.url + "archive/" + data_id
        headers = {"apikey": self.session_id}
        response = requests.request("GET", url, headers=headers)
        #printBlock(response)
        return response

    ## 
    # https://docs.opswat.com/mdcore/metadefender-core#hashget
    def hashGet(self, hash):
        url = self.url + "/hash/" + hash # {md5|sha1|sha256}
        headers = {
            "apikey": self.session_id,
            #"rule": "{rule}",
            #"selfonly": "{selfonly}",
            #"timerange": "{timerange}",
            #"include-inprogress": "{include-inprogress}"
        }
        #querystring = {"first":"{first}","size":"{size}"}
        querystring = {}
        response = requests.request("GET", url, headers=headers, params=querystring)
        #printBlock(response)
        return

    # https://docs.opswat.com/mdcore/metadefender-core#webhookstatus
    def webHookStatus(self, data_id):
        url = self.url + "file/webhook/" + data_id
        headers = {"apikey": self.session_id}
        response = requests.request("GET", url, headers=headers)
        #printBlock(response)
        return
    ##
    # https://docs.opswat.com/mdcore/metadefender-core#analysisrules
    def analysisRules(self):
        url = self.url + "/file/rules"
        headers = {
        "apikey": self.session_id,
        #"user_agent": "{user_agent}"
        }

        response = requests.request("GET", url, headers=headers)
        #printBlock(response)
        return

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#sanitizedfile
    def sanitizedFile(self, data_id):
        url = self.url + "/file/converted/" + data_id
        headers = {"apikey": self.session_id}
        response = requests.request("GET", url, headers=headers)
        #printBlock(response)
        return
    
    ##
    # https://docs.opswat.com/mdcore/metadefender-core#downloadfile
    def downloadFile(self, data_id):
        url = self.url + "file/download/" + data_id
        print("URL:", url)

        headers = {"apikey": self.session_id}
        print("headers: ", headers)

        response = requests.request("GET", url, headers=headers)
        success=False
        if response.status_code == 200:
            success=True
            # Qua in effetti dovremmo riportare il vero nome
            file_name= "downloadFile_" + data_id + ".zip"
            with open(f'/tmp/{file_name}', 'wb') as file:
                file.write(response.content)
        else:
            if response.status_code == 404:
                print("File could not be found")
            elif response.status_code == 405:
                print("The user has no rights for this operation.")
            elif response.status_code == 500:
                print("Unexpected event on server")
            printBlock(response)

        return success

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#resultexportedfile
    def resultExportedFile(self, data_id):
        url = self.url + "file/" + data_id + "/export"
        headers = {"apikey": self.session_id}
        response = requests.request("GET", url, headers=headers)
        success=False
        if response.status_code == 200:
            success=True
            file_name= "scan_result_" + data_id + ".pdf"
            with open(f'/tmp/{file_name}', 'wb') as file:
                file.write(response.content)
        else:
            if response.status_code == 403:
                print("Invalid user information or Not Allowed")
            elif response.status_code == 404:
                print("Requests resource was not found.")
            elif response.status_code == 500:
                print("Unexpected event on server")
            printBlock(response)
        return success

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#downloadquarantinedfile
    def downloadQuarantinedFile(self, sha256):
        url = self.url + "quarantine/" + sha256 + "/download"
        print("URL:", url)

        headers = {"apikey": self.session_id}
        print("headers: ", headers)

        response = requests.request("GET", url, headers=headers)
        success=False

        if response.status_code == 200:
            success=True
            file_name= "downloadQuarantinedFile" + sha256
            with open(f'/tmp/{file_name}', 'wb') as file:
                file.write(response.content)
        else:
            if response.status_code == 403:
                print("Invalid user information or Not Allowed")
            elif response.status_code == 404:
                print("Requests resource was not found")
            elif response.status_code == 500:
                print("Unexpected event on server")

            printBlock(response)

        return success

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#fileanalysiscancel
    def fileAnalysisCancel(self, data_id):
        url = self.url + "file/" + data_id +"/cancel"
        headers = {"apikey": self.session_id}
        response = requests.request("POST", url, headers=headers)
        #printBlock(response)
        return


    ##
    # BATCH (completed)
    ## 

    ##
    # batchCreate: initiate batch
    # https://docs.opswat.com/mdcore/metadefender-core#batchcreate
    def batchCreate(self, rule="",  user_agent="",  user_data=""):
        url = self.url + "/file/batch"
        headers = {
        "apikey": self.session_id,
        "rule": rule,
        "user_agent": user_agent,
        "user-data": user_data
        }

        response = requests.request("POST", url, headers=headers)
        #printBlock(response)
        batch_id = ""
        if response.status_code == 200:
            data = json.loads(response.text)
            batch_id = data["batch_id"]
        elif response.status_code == 400:
            pass
        elif response.status_code == 403:
            pass
        elif response.status_code == 500:
            pass

        return batch_id

    ##
    # batchClose: close batch
    # https://docs.opswat.com/mdcore/metadefender-core#batchclose
    def batchClose(self, batch_id):
        url = self.url + "/file/batch/" + batch_id + "/close"
        headers = {"apikey": self.session_id}
        response = requests.request("POST", url, headers=headers)
        #printBlock(response)

        success = False
        if response == 200:
            success = True
        elif response == 400:
            pass
        elif response == 403:
            pass
        elif response == 404:
            pass
        elif response == 500: 
            pass

        return success

    ##
    # batchCloseCallback: Close Batch with webhook
    #
    # The batch will be closed and files can no longer 
    # be added to the current batch.
    #
    # https://docs.opswat.com/mdcore/metadefender-core#batchclosecallback
    # 
    def batchCloseCallback(self, batch_id, callback_url):
        url = self.url + "file/batch/" + batch_id +"/close/callback"
        headers = {
            "apikey": self.session_id,
            "callback_url": callback_url
        }

        response = requests.request("POST", url, headers=headers)
        #printBlock(response)

        success = False
        if response == 200:
            success = True
        elif response == 400:
            pass
        elif response == 403:
            pass
        elif response == 404:
            pass
        elif response == 500: 
            pass

        return success

    ##
    # status of batch analisys
    # https://docs.opswat.com/mdcore/metadefender-core#batchstatus
    def batchStatus(self, batch_id):
        url = self.url + "batch/" + batch_id
        headers = {"apikey": "{apikey}"}
        # querystring = {"first":"{first}","size":"{size}"}
        querystring = {}
        response = requests.request("GET", url, headers=headers, params=querystring)
        #printBlock(response)

        success = False
        if response == 200:
            success = True
        elif response == 400:
            pass
        elif response == 403:
            pass
        elif response == 404:
            pass
        elif response == 500: 
            pass

        return success

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#batchsignedresult
    # batchSignedResult
    def batchSignedResult(self, batch_id):
        url = self.url + "/file/batch/" + batch_id + "/certificate"
        headers = {"apikey": self.session_id}
        response = requests.request("GET", url, headers=headers)
        #printBlock(response)

        success = False
        if response == 200:
            success = True

        elif response == 400:
            pass
        elif response == 403:
            pass
        elif response == 404:
            pass
        elif response == 500: 
            pass

        return success

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#batchcancel
    def batchCancel(self, batch_id):
        url = self.url + "file/batch/" + batch_id + "/cancel"
        headers = {"apikey": "{apikey}"}
        response = requests.request("POST", url, headers=headers)
        #printBlock(response)

        success = False
        if response == 200:
            success = True

        elif response == 400:
            pass
        elif response == 403:
            pass
        elif response == 404:
            pass
        elif response == 500: 
            pass

        return success

    ##
    # ADMIN SECTION - not complete
    ##

    # adminExport: Export configuration from file.
    # https://docs.opswat.com/mdcore/metadefender-core#adminexport
    def adminExport(self): 
        url = self.url + "admin/export"
        headers = {"apikey": self.session_id}
        response = requests.request("GET", url, headers=headers)
        #printBlock(response)
        return
    
    ## 
    # https://docs.opswat.com/mdcore/metadefender-core#adminexportv2
    def adminExportV2(self, password): 
        url = self.url + "admin/export/v2"
        headers = {
            "apikey": self.session_id,
             "password": password # cripta con password
        }
        response = requests.request("GET", url, headers=headers)
        #printBlock(response)
        return


    ## 
    # https://docs.opswat.com/mdcore/metadefender-core#adminimport
    def adminImport(self):
        url = self.url + "admin/import"
        headers = {
            "Content-Type": "application/json",
            "apikey": self.session_id
        }
        payload = "{\n  \"config\": {\n      \"policy.rule.rule\": {\n          \"items\": [\n              {\n                  \"active\": true,\n                  \"allow_cert\": false,\n                  \"allow_cert.cert\": \"None\",\n... }"
        response = requests.request("POST", url, headers=headers, data=json.dumps(payload))
        #printBlock(response)
        return
    
    ##
    # https://docs.opswat.com/mdcore/metadefender-core#adminimportv2
    def adminImportV2(self):
        return 

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#usercreate        
    def userCreate(self):
        url = self.url + "/admin/user"

        # to do

        return
    
    ##
    # https://docs.opswat.com/mdcore/metadefender-core#rolecreate
    def roleCreate(self):
        url = self.url + "/admin/role"

        # to do

        return

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#getlicensebackup
    def getLicenseBackup(self):
        return
    
    ##
    # https://docs.opswat.com/mdcore/metadefender-core#postlicensebackup
    def postLicenseBackup():
        return
    
    ##
    # https://docs.opswat.com/mdcore/metadefender-core#removebackupinstance
    def removeBackupInstance(self):
        return
    
    ##
    # https://docs.opswat.com/mdcore/metadefender-core#licensebackupnomination
    def licenseBackupNomination(self):
        return
    
    
    
    ##
    # LICENZE - not necessary
    ##


    ##
    # CONFIG - To see
    ##

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#configauditlog
    def configAuditLog():
        # Audit clean up
        return

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#configquarantine
    def configQuarantine(self):
        # Quarantine clean up
        return
    
    ##
    # https://docs.opswat.com/mdcore/metadefender-core#configsanitizedrepo
    def configSanitizedRepo(self):
        # Sanitized file clean up
        return
    
    ##
    # https://docs.opswat.com/mdcore/metadefender-core#configscanhistory
    def configScanHistory(self):
        # Processing history clean up
        return

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#configupdate
    def configUpdate(self):
        # Modules Update Source and Frequency
        return
    
    ##
    # https://docs.opswat.com/mdcore/metadefender-core#configgetskiphash
    def configGetSkipHash(self):
        # get 'skip by hash' list
        return

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#configupdateskiphash
    def configUpdateSkipHashDef(self):
        # Modify 'skip by hash' list
        return

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#configpostskiphash
    def configPostSkipHash(self):
        # Add new hashes to 'skip by hash' list
        return

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#configdeleteskiphash
    def configDeleteSkipHash(self):
        # Delete hashes from 'skip by hash' list
        return

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#configwebhook
    def configWebHook(self):
        # Webhook get configuration
        url = self.url  + "/admin/config/webhook"
        headers = {"apikey": self.session_id}
        response = requests.request("GET", url, headers=headers)
        #printBlock(response)
        return

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#configupdatewebhook
    # Webhook set configuration
    def configUpdateWebHook(self, maxretrytime=3, 
                            delayduration=1000,
                            delayprogression=1000,
                            requestqueue=100,
                            transfertimeout=30000,
                            workercount=1):
        
        url = self.url + "/admin/config/webhook"
        headers = {
            "Content-Type": "application/json",
            "apikey": self.session_id
        }
        payload = {
            "maxretrytime": maxretrytime,
            "delayduration": delayduration,
            "delayprogression": delayprogression,
            "requestqueue": requestqueue,
            "transfertimeout": transfertimeout,
            "workercount": workercount
        }
        print(payload)
        response = requests.request("PUT", url, headers=headers, data=json.dumps(payload))
        #printBlock(response)
        return

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#configgetproxy
    def configGetProxy(self):
        # get proxy
        url = self.url + "/admin/config/proxy"
        return 

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#configupdateproxy
    def configUpdateProxy(self):
        # Modify proxy
        url = self.url +  "/admin/config/proxy"
        return

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#configpostproxytestconnection
    def configPostProxyTestConnection(self):
        # Check connection to proxy server
        return 

    ##
    # to continue... 


    ##
    # YARA - Not used
    ##

    ##
    # ENGINES - To see
    ##

    ##
    # STATS - To be implemented
    ##

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#productversion
    def productVersion(self):
        url = self.url + "/version"
        headers = {"apikey": self.session_id}
        response = requests.request("GET", url, headers=headers)
        #printBlock(response)
        return 

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#enginesstatus
    def enginesStatus(self):
        url = self.url + "/stat/engines"
        headers = {"apikey": self.session_id}
        response = requests.request("GET", url, headers=headers)
        #printBlock(response)
        return
    
    ##
    # https://docs.opswat.com/mdcore/metadefender-core#nodesstatus
    def nodesStatus(self):
        url = self.url + "/stat/nodes"
        headers = {"apikey": self.session_id}
        response = requests.request("GET", url, headers=headers)
        #printBlock(response)
        return


    ##
    # https://docs.opswat.com/mdcore/metadefender-core#activeperformance
    def activePerformance(self):
        url = self.url + "/stat/activeperformance"
        headers = {
            "apikey": self.session_id,
            "rule_name": "{rule_name}"
        }
        querystring = {"hours_range":"8"}
        response = requests.request("GET", url, headers=headers, params=querystring)
        #printBlock(response)
        return

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#healthcheck
    def healthCheck(self):
        url = self.url + "/readyz"
        headers = {"apikey": self.session_id}
        querystring = {"verbose":"true"}
        response = requests.request("GET", url, headers=headers, params=querystring)
        #printBlock(response)
        return
    
    ##
    # end-mine
    ##

    ##
    # Fetch Scan Result by File Hash via MetaDefender Core
    def hashScanResult(self, file_hash):
        url = self.url + "/hash/" + file_hash
        headers = {"apikey": self.session_id}

        # querystring = {"first":"","size":""}
        response = requests.request("GET", url, headers=headers) #, params=querystring)
        data = response.json()
        report = [False, data]
        if file_hash not in data.keys():
            report[0] = True
        return report
    
    ##
    # Scan a File via MetaDefender Core
    def uploadFile(self, file_name):
        url = self.url  + "file"
        files = open(file_name, "rb")
        headers = {"filename": file_name}
        response = requests.post(url, data=files, headers=headers)
        if response.status_code != 200:
            print("The server returned a ", response.status_code, file=sys.stderr)
            sys.exit(1)
        data = response.json()
        return data["data_id"]

    ##
    # Download Sanitized File via MetaDefender Core
    # https://docs.opswat.com/mdcore/metadefender-core#sanitizedfile
    def retrieveSanitizedFile(self, data_id):
        url = self.url + "file/converted/" + data_id
        print("URL:", url)

        headers = {"apikey": self.session_id}
        print("headers: ", headers)

        response = requests.request("GET", url, headers=headers)
        success=False
        if response.status_code == 200:
            success=True
            file_name= "retrieveSanitizedFile_" + data_id
            with open(f'/tmp/{file_name}', 'wb') as file:
                file.write(response.content)
        else:
            printBlock(response)

        return success

    ##
    # Fetch Scan Result (by Data ID) via MetaDefender Core
    def retrieveScanResult(self, apikey, data_id):
        headers = {"apikey": self.session_id}
        url = self.url + "file/" + data_id
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print("The server returned a ", response.status_code, file=sys.stderr)
            sys.exit(1)
        data = response.json()

        # Ensure that we have the full scan report, especially useful for scanning large files
        while data['scan_results']['progress_percentage'] < 100:
            response = requests.get(url)
            data = json.loads(response.text)
            time.sleep(1)

        return

    ##
    # https://docs.opswat.com/mdcore/metadefender-core#productversion
    def getProductVersion(self):
        url = self.url + "version/"
        headers = {"apikey": self.session_id}
        response = requests.get(url, headers=headers)
        print("URL: ", url)
        print("status_code: ", response.status_code)
        retVal=""

        if response.status_code == 200:
            retVal=response.text
            print("RetVal:", retVal)
        elif response.status_code == 404:
            #print("content: ", response.content)
            print("The page you are looking for doesn't exist")
        elif response.status_code == 500:
            print("Unexpected event on server")

        return retVal

##

##
#
def printBlock(response):
    print("############################################################")
    print("### " + inspect.currentframe().f_back.f_code.co_name)
    print("############################################################")
    print("- status_code: " + str(response.status_code))
    print("- JSON:")
    data=json.loads(response.text)
    print(json.dumps(data, indent=3))