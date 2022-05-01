#from starlette.responses import Response
#from passlib.hash import pbkdf2_sha256
#from starlette.websockets import WebSocketDisconnect
from blockchain import Blockchain, DB, NODES
import os
from fastapi import FastAPI, WebSocket
import uvicorn
import socket
#import requests as r
from pydantic import BaseModel
from fastapi.templating import Jinja2Templates
import json
import asyncio
import sys

import time as t
import random
import base64
from sys import getsizeof

sys.path.insert(0, './Utilities')
from cryptography_testing import *
from fastapi_signals import *
from ProofOfStake.main import ProofOfStakeMAIN

proof_of_stake_class = ProofOfStakeMAIN(Blockchain=Blockchain, NODES=NODES)


ring_ct = Ring_CT()
checkbalance = Check_Wallet_Balance()
create_keys = Make_Keys()
primary_addr = primary_addresses()
decoy_addresses = Decoy_addresses()


# {
#  "node": [
#    "http://127.0.0.1:8000", "http://127.0.0.1:8001"
#  ]
#}

tags_metadata = [
    {'name':'information', 
    'description': 'This will allow you to get info about the blockchain',

    'name':'wallet',
    'description': 'this will allow you to access your wallet and make wallets',
    
    'name': 'transaction',
    'description': 'transactions',

    'name': 'mining',
    'description': 'mining', 

    'name': 'nodes',
    'description': 'adding nodes and replacing the chain',


    'name': 'contracts',
    'description': 'smart contracts on the blockchain'
    }]

# CONSTANTS
SERVER_NAME = 'Token Network'
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 8000
SERVER_RELOAD = False
DESCRIPTION = "Welcome to The Token Network, a blockchain network with a cryptocurrency called Token, it's like Dogecoin and Bitcoin but faster than Bitcoin and harder to mine than Dogecoin, welcome to the Future of the world."
algs = Algs()
#S = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#hostname = socket.gethostname()
#IP = socket.gethostbyname(hostname)
# wallet = Wallet()
class Url(BaseModel):
    node: str




app = FastAPI(title=SERVER_NAME, openapi_tags=tags_metadata, description=DESCRIPTION)

templates = Jinja2Templates(directory="templates/")

blockchain = Blockchain()


class Transaction(BaseModel):
    sender_public_send_key: str
    sender_signature: str
    receiver: str
    amount: float



class AddTransaction(BaseModel):
    sender_public_send_key: str
    sender_signature: str
    receiver: str
    transactionID: str
    timestamp: str
    amount: float
    transactiontype: str


class Contract(BaseModel):
    sender_public_send_key: str
    receiver: str
    contractbinary: bytes


class Walletkey(BaseModel):
    publickey: str
    privatekey: str

class Wallet_public(BaseModel):
    viewkey: str

class Passphrase(BaseModel):
    passphrase: str


class Block(BaseModel):
    block: dict


class Recover(BaseModel):
    passphrase: str


class Mining(BaseModel):
    address: str


class EncryptedTransaction(BaseModel):
    sender_publickey: bytes
    receiver: bytes
    amount: float    


def proof_of_work_or_proof_of_stake():
    """ Changes from proof of work to proof of stake after 200,000 blocks have been mined """
    if len(blockchain.chain) >= 200000:
        return True
    else:
        return False


def start_proof_of_stake():
    """ Starts proof of stake process """
    proof_of_stake_class.run_POS(DB)
    return True



@app.get('/')
async def index():
    """ returns index page """ 
    return "see /docs for the api"


# @app.post('/add_contract', tags=['contracts'])
# async def addContract(contractTransaction: Contract):
#     """ Use this to add smart contracts """
#     senderPublicKey = contractTransaction.sender_public_send_key
#     senderPrivateKey = contractTransaction.sender_private_send_key
#     receiver = contractTransaction.receiver
#     senderViewKey = contractTransaction.sender_view_key
#     contractdata = contractTransaction.contractbinary
#     contract = blockchain.add_smartContract(senderprivatekey= senderPrivateKey,
#             sendersendpublickey= senderPublicKey,
#             senderviewkey= senderViewKey,
#             receiver= receiver,
#             compiledcontract=contractdata)
#     return {'message': contract}


@app.get("/get_the_chain", tags=['information'])
async def get_the_chain():
    """ Use this to get the whole blockchain """
    # update = blockchain.replace_chain()
    response = {"blockchain": blockchain.chain, "length": len(blockchain.chain)}
    return response


@app.post("/mining", tags=['mining'])
async def mine(keys:Mining):
    """ This allows you to mine blocks """
        # get previous block
    prev_block = blockchain.get_prev_block()
        # previous proof
    prev_proof = prev_block['proof']
        # proof
    proof = blockchain.proof_of_work(previous_proof=prev_proof)
        # previous hash
    prev_hash = blockchain.hash(block=prev_block)
        # add data
    algs.amount_change(chain=blockchain.chain)

    message = blockchain.create_block(proof=proof, previous_hash=prev_hash, forger=keys.address)
        #returns the last block in the chain
    return {'message': message}



@app.get("/status", tags=['information'])
async def is_valid():
    """ Checks to see if chain is valid """
    is_valid = blockchain.is_chain_valid(chain=blockchain.chain)
    if is_valid:
        response = {"message": "Not compromised"}
    else:
        response = {"message": "Blockchain has been compromised"}
    return response


@app.post("/add_transaction/", tags=['transaction'])
async def add_transaction(transaction: AddTransaction):
    """ the route for nodes to add transactions to this node to prevent loops in the network. """
    senderpublicsendkey = transaction.sender_public_send_key
    sender_signature = transaction.sender_signature
    receiver = transaction.receiver
    amount = transaction.amount
    transactionid = transaction.transactionID
    new_transaction = blockchain.add_transaction(
        sender_signature=sender_signature,
        sendersendpublickey=senderpublicsendkey,
        receiver=receiver,
        amount=amount,
        transactionID=transactionid
    )
    result = 'transaction has been added and is awaiting verification'
    return result







@app.post('/add_unconfirmed_transaction', tags=['transaction'])
async def add_unconfirmed_transaction(transaction: Transaction):
    """ broadcasts transactions to all nodes """

    sender_signature = transaction.sender_signature
    pub_sender_key = transaction.sender_public_send_key
    
    receiver = transaction.receiver
    amount = transaction.amount
    new_transaction = blockchain.add_unconfirmed_transaction(
    sender=pub_sender_key, 
    receiver=receiver, 
    sendersignature=sender_signature, 
    amount=amount)
    blockchain.broadcast_transaction(transaction=new_transaction)
    result = 'transaction has been added and is awaiting verification'
    return result

""" Wallets should be made offline. """





@app.post("/add_node/", tags=['nodes'])
async def add_node(url:Url):
    """ This is used to add nodes and announce the node to the network and should be inserted like this : IP:port or DNS:port"""
    item = url.node
    blockchain.add_node(item) 
    for nodes in blockchain.nodes:
        node = nodes['node']
        if node != item:
            json = {'node':node}
            r.post(f'http://{node}/add_one_node/', json=json)
            json = {'node':node}
            r.post(f'http://{address}/add_one_node/', json=json)            
    result = item


    return result


@app.post('/add_one_node/', tags=['nodes'])
async def add_one_node(url:Url):
	""" adds one node to prevent loops in the network, nodes should be inserted like this : IP:port or DNS:port"""
	item = url.node
	blockchain.add_node(item)
	return item




@app.get("/replace_chain", tags=['nodes'])
async def replace_chain():
    """ replaces the current chain with the most recent and longest chain """
    blockchain.replace_chain()
    blockchain.is_chain_valid(chain=blockchain.chain)
    return{'message': 'chain has been updated and is valid', 
           'longest chain': blockchain.chain}



@app.websocket('/dashboard')
async def dashboard(websocket: WebSocket):
    """ P2p Dashboard """
    await websocket.accept()

    while True:
        block = blockchain.chain
        await websocket.send_text(f'Message: {block}')
        await asyncio.sleep(10)



@app.websocket("/ws")
async def dashboard_endpoint(websocket: WebSocket):
    """ This shows real time data for nodes"""
    await websocket.accept()
    message = None
    while True:
        try:
        
            if message != blockchain.chain:
                message = blockchain.chain
                await websocket.send_json(message)
                print(message)
                t.sleep(0.2)
            else:
                pass
        except Exception as e:
            pass
        break
    print('client disconnected')


# @app.websocket("/nodes")
# async def dashboard_endpoint(websocket: WebSocket):
#     """ This shows real time data of each node, this should be used for detecting new nodes in the network or helping with automating adding nodes"""
#     await websocket.accept()
#     message = None
#     while True:
#         try:
#             if message != blockchain.nodes:
#                 message = blockchain.nodes
#                 await websocket.send_json(message)
#                 print(message)
#                 t.sleep(0.2)
#             else:
#                 pass
#         except Exception as e:
#             pass
#         break
#     print('client disconnected')

    




@app.post('/check_balance', tags=['wallet'])
async def check_balance(wallet:Wallet_public):
    """ Checks the balance of a wallet with the view key """

    balance = checkbalance.balance_check(wallet.viewkey, blockchain=blockchain.chain)
    return {'Address': balance['receive address'], 'balance': f'{balance["balance"]} Tokens'}


@app.post('/insert_block', tags=['nodes'])
async def insert_chain(chain:Block):
    """ replace the chain if all nodes are down or if node has a 
    firewall preventing get requests from web servers """
    print(chain.block)
    updated_chain = blockchain.update_chain(chain.block)
    return updated_chain



if __name__ == '__main__':
    # os.system('touch privkey.pem && touch cert.pem')
    # os.system('openssl rsa -passin pass:x -in keypair.key > privkey.pem')
    # os.system('openssl x509 -req -days 365 -signkey privkey.pem < cert.pem && rm keypair.key')
    # os.system('openssl x509 -req -days 365 -signkey privkey.pem > cert.pem')
    uvicorn.run(app, host=SERVER_HOST, port=SERVER_PORT, reload=SERVER_RELOAD)
