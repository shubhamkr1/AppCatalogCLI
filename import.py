
from apache.airavata.api import Airavata
from apache.airavata.api.ttypes import *

from apache.airavata.model.workspace.ttypes import *
from apache.airavata.model.security.ttypes import AuthzToken
from apache.airavata.model.experiment.ttypes import *

import argparse
import configparser
import json

from thrift import Thrift
from thrift.transport import TSSLSocket
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

def get_transport(hostname, port):
    # Create a socket to the Airavata Server
    # TODO: validate server certificate
    transport = TSSLSocket.TSSLSocket(hostname, port, validate=False)

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

if __name__ == '__main__':

    config = configparser.ConfigParser()
    config.read('airavata.ini')
    token = config['credentials']['AccessToken']
    username =  config['credentials']['Username']

    authz_token = get_authz_token(token,username)

    hostname = "dev.apptestdrive.airavata.org"
    port = "9930"
    transport = get_transport(hostname, port)
    transport.open()
    airavataClient = get_airavata_client(transport)

    with open('DeploysData.txt') as file:
      datastore= json.load(file)

    for i in range(len(datastore)):
          print(str(i)+" element: desc :"+datastore[i]["appDeploymentDescription"])
          print("depId "+datastore[i]["appDeploymentId"])
          #creating objects one by one on gateway
          AppDeployObj = new ApplicationDeploymentDescription() 
          AppDeployObj.appDeploymentId = datastore[i]["appDeploymentId"]
          AppDeployObj.appModuleId =   datastore[i]["appModuleId"]
          AppDeployObj.computeHostId = datastore[i]["computeHostId"]
          AppDeployObj.executablePath = datastore[i]["executablePath"]
          AppDeployObj.parallelism = datastore[i]["parallelism"]
          #optional itens
          AppDeployObj.appDeploymentDescription = datastore[i]["appDeploymentDescription"]
          AppDeployObj.moduleLoadCmds = datastore[i]["moduleLoadCmds"]
          AppDeployObj.libPrependPaths = datastore[i]["libPrependPaths"]
          AppDeployObj.libAppendPaths = datastore[i]["libAppendPaths"]
          AppDeployObj.preJobCommands = datastore[i]["preJobCommands"]
          AppDeployObj.postJobCommands = datastore[i]["postJobCommands"]
          create_app_deployment(airavataClient, authz_token,AppDeployObj)
