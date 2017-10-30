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

def get_user_experiments(airavataClient, authzToken, username):
    gatewayId = "default"
    experiments =  airavataClient.getUserExperiments(authzToken,gatewayId,username,-1,0)
    return experiments

    #fetch all app deployments to get moduleId and deploymentId
def get_all_app_deployments(airavataClient, authzToken, username):
    gatewayId="default"
    appDeploys = airavataClient.getAllApplicationDeployments(authzToken,gatewayId)
    return appDeploys

def get_all_app_interfaces(airavataClient, authzToken, username):
    gatewayId="default"
    appInterfaces = airavataClient.getAllApplicationInterfaces(authzToken,gatewayId)
    return appInterfaces    

def get_all_app_modules(airavataClient, authzToken, username):
    gatewayId="default"
    appModules = airavataClient.getAllAppModules(authzToken,gatewayId)
    return appModules




if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='Arguments to app data')
    parser_1 = subparsers.add_parser('getdeploys', help='Fetch all application deployments')
    parser_1.add_argument('username', type=str, help='Creator of the experiment')
    parser_1.set_defaults(parser1=True)

    args = parser.parse_args()
    print(args)

    config = configparser.ConfigParser()
    config.read('airavata.ini')
    token = config['credentials']['AccessToken']

    username=args.username
    authz_token = get_authz_token(token,username)
    #print(authz_token)

    hostname = "apidev.scigap.org"
    port = "9930"
    transport = get_transport(hostname, port)
    transport.open()
    airavataClient = get_airavata_client(transport)
    print('Airavata client -> ' + str(airavataClient))

    appDeploys = get_all_app_deployments(airavataClient,authz_token,username)

    appInterfaces = get_all_app_interfaces(airavataClient, authz_token, username)

    appModules = get_all_app_modules(airavataClient, authz_token, username)

    with open('DeploysData.txt','w') as outfile:
         json.dump(appDeploys,outfile,default=lambda O:O.__dict__)
  
    with open('InterfaceData.txt','w') as outfile2:
         json.dump(appInterfaces,outfile2,default=lambda O:O.__dict__)

    with open('ModulesData.txt','w') as outfile3:
         json.dump(appInterfaces,outfile3,default=lambda O:O.__dict__)
