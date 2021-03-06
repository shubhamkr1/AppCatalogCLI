

from apache.airavata.api import Airavata
from apache.airavata.api.ttypes import *

from apache.airavata.model.workspace.ttypes import *
from apache.airavata.model.security.ttypes import AuthzToken
from apache.airavata.model.experiment.ttypes import *
from apache.airavata.model.appcatalog.appdeployment.ttypes import *

import argparse
import configparser
import json
import copy

from thrift import Thrift
from thrift.transport import TSocket
#from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

def get_transport(hostname, port):
    # Create a socket to the Airavata Server
    # TODO: validate server certificate
    transport = TSocket.TSocket(hostname, port)

    # Use Buffered Protocol to speedup over raw sockets
    transport = TTransport.TBufferedTransport(transport)
    return transport


def get_airavata_client(transport):
    # Airavata currently uses Binary Protocol
    protocol = TBinaryProtocol.TBinaryProtocol(transport)

    # Create a Airavata client to use the protocol encoder
    airavataClient = Airavata.Client(protocol)
    return airavataClient


def get_authz_token(token,username):
    return AuthzToken(accessToken=token, claimsMap={'gatewayID': "default", 'userName': username})

def create_app_deployment(airavataClient, authzToken,AppDeployObj):
    gatewayId="default"
    appDeployID = airavataClient.registerApplicationDeployment(authzToken,gatewayId,AppDeployObj)
    return appDeployID

def get_all_projects(airavataClient, authzToken, username):
    gatewayId="default"
    projectLists = airavataClient.getUserProjects(authzToken, gatewayId, username, -1, 0)

    return projectLists

if __name__ == '__main__':

    config = configparser.ConfigParser()
    config.read('airavata.ini')
    token = config['credentials']['AccessToken']
    username =  config['credentials']['Username']

    authz_token = get_authz_token(token,username)

    hostname = "api.devscigap.org"
    port = "9930"
    transport = get_transport(hostname, port)
    transport.open()
    airavataClient = get_airavata_client(transport)

    projects = get_all_projects(airavataClient, authz_token, username)
    #transport.close()
    print("project "+projects)

    with open('DeploysData.txt') as file:
      datastore= json.load(file)

    for i in range(len(datastore)):
          #print(str(i)+" element: desc :"+datastore[i]["appDeploymentDescription"])
          #print("depId "+datastore[i]["appDeploymentId"])
          #creating objects one by one on gateway
          AppDeployObj = ApplicationDeploymentDescription()
          AppDeployObj.appDeploymentId = datastore[i]["appDeploymentId"]
          AppDeployObj.appModuleId =   datastore[i]["appModuleId"]
          AppDeployObj.computeHostId = datastore[i]["computeHostId"]
          AppDeployObj.executablePath = datastore[i]["executablePath"]
          AppDeployObj.parallelism = datastore[i]["parallelism"]
          #optional itens
          AppDeployObj.appDeploymentDescription = datastore[i]["appDeploymentDescription"]
          #AppDeployObj.moduleLoadCmds = datastore[i]["moduleLoadCmds"]
          #AppDeployObj.libPrependPaths = datastore[i]["libPrependPaths"]
          #AppDeployObj.libAppendPaths = datastore[i]["libAppendPaths"]
          #AppDeployObj.preJobCommands = datastore[i]["preJobCommands"]
          #AppDeployObj.postJobCommands = datastore[i]["postJobCommands"]
          #CommandObject(datastore[i]["moduleLoadCmds"][0]["command"]))
          #print(moduleCmd)
          list =[]
          for j in range(len(datastore[i]["moduleLoadCmds"])):
             x = datastore[i]["moduleLoadCmds"][j]["command"]
             y = datastore[i]["moduleLoadCmds"][j]["commandOrder"]
             print(CommandObject(x,y))
             list.append(CommandObject(x,y))
             AppDeployObj.moduleLoadCmds = copy.deepcopy(list)

          #print(AppDeployObj.moduleLoadCmds)
          libprePath =[]
          libprePath.append(SetEnvPaths(datastore[i]["libPrependPaths"]))
          AppDeployObj.libPrependPaths = copy.deepcopy(libprePath)
          libappPath =[]
          libappPath.append(SetEnvPaths(datastore[i]["libAppendPaths"])) 
          AppDeployObj.libAppendPaths = copy.deepcopy(libappPath)
          setEnv = []
          setEnv.append(SetEnvPaths(datastore[i]["setEnvironment"]))
          AppDeployObj.setEnvironment = copy.deepcopy(setEnv)
          prejobCmd = []
          prejobCmd.append(CommandObject(datastore[i]["preJobCommands"]))
          AppDeployObj.preJobCommands = copy.deepcopy(prejobCmd)
          postjobCmd = []
          postjobCmd.append(CommandObject(datastore[i]["postJobCommands"]))
          AppDeployObj.postJobCommands = copy.deepcopy(postjobCmd)
          #create_app_deployment(airavataClient, authz_token,AppDeployObj)

