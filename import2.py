from apache.airavata.api import Airavata
from apache.airavata.api.ttypes import *

from apache.airavata.model.workspace.ttypes import *
from apache.airavata.model.security.ttypes import AuthzToken
from apache.airavata.model.experiment.ttypes import *

import configparser
import json

from thrift import Thrift
#from thrift.transport import TSSLSocket
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

def get_transport(hostname, port):
    # Create a socket to the Airavata Server
    # TODO: validate server certificate
    transport = TSocket.TSocket(hostname, port) #, validate=False)

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

def get_all_projects(airavataClient, authzToken, username):

    gatewayId = "default"
    projectLists = airavataClient.getUserProjects(authzToken, gatewayId, username, -1, 0)

    return projectLists

if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('airavata.ini')
    token = config['credentials']['AccessToken']
    username=config['credentials']['Username']

    authz_token = get_authz_token(token,username)

    hostname = "apidev.scigap.org"
    port = "9930"
    transport = get_transport(hostname, port)
    transport.open()
    airavataClient = get_airavata_client(transport)
    print('Airavata client -> ' + str(airavataClient))

    projects = get_all_projects(airavataClient, authz_token, username)
    transport.close()
    print(projects)

