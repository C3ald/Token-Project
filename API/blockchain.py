#!/usr/bin/python3
import sys
sys.path.insert(0, 'Utilities')
sys.path.insert(0, 'Utilities/ProofOfStake')


import datetime
from main import ProofOfStakeMAIN
from tinydb import TinyDB, Query
from cryptography_testing import *
import hashlib
import time
import json
from urllib.parse import urlparse
from uuid import uuid1, uuid4
import requests as r
from urllib import error
import random
from passlib.hash import pbkdf2_sha256
import base64
from Wallets import Signatures
from multiprocessing import Process
# git add .
# git commit -m "Message"
# git push
algs = Algs()
ring_ct = Ring_CT()
decoy_transactions = Decoy_addresses()
DB = TinyDB('db_blockchain.json')
NODES = TinyDB('nodes.json')
wallet_bal = Check_Wallet_Balance()
signatures = Signatures()

class Blockchain:
    """ the blockchain class """

    def __init__(self):
        self.nodes = []
        if len(self.read_data(NODES)) > len(self.nodes):
            self.nodes = self.read_data(NODES)
            print(self.nodes)
        else:
            # NODES.insert(self.nodes)
            # self.read_data(NODES)
            # self.nodes = []
            None

        self.unconfirmed_transactions = []
        self.new_transactions = []
        self.allnodes = None
        self.chain = []  # stores the blockchain
        # Checks to see if a chain is already present
        self.old_chain = self.read_data(DataBase=DB)
        if len(self.old_chain) > len(self.chain):
            self.chain = self.old_chain
            self.transactions = []
        else:
            self.transactions = ["How's our data?"]
            # helps with block creation
            self.create_block(proof=1, previous_hash="0",
                              forger='Network', timestamp='0')


    def add_node_to_file(self):
        """ writes the nodes to a file since tinydb is being a pain """
        current_nodes = self.nodes
        un_added_nodes = []
        for node in current_nodes:
            file1 = open('nodes.txt', 'r')
            if node in file1.read():
                None
            else:
                un_added_nodes.append(f'{node}\n')
        file1 = open('nodes.txt', 'w')
        file1.writelines((un_added_nodes))

    def add_smartContract(self, senderprivatekey: str, senderviewkey: str, sendersendpublickey, receiver, compiledcontract):
        """ This is used to add transactions so they can be verified """

        unconfirmedTransaction = {'sender send publickey': sendersendpublickey, 'sender send privatekey': senderprivatekey, 'sender address': senderviewkey,
                                  'receiver': receiver, 'amount': algs.fee, 'id': uuid1(), 'timestamp': time.time(), 'type': 'Contract', 'contract': compiledcontract}
        verify = self.doubleSpendCheck(unconfirmedTransaction)
        if verify == False:
            self.unconfirmed_transactions.append(unconfirmedTransaction)

        return unconfirmedTransaction

    def to_JSON(self, data):
        """ Converts to json """
        return json.loads(json.dumps(data))

    def add_data(self, data, DataBase):
        """ This adds data to the database that is selected """

        DataBase.truncate()
        for item in data:
            # formatted = {'node': item}
            DataBase.insert(item)
        return 'data has been added!!'

    def add_node_to_file_tinydb(self, data, DataBase):
        """ This adds data to the database that is selected """

        DataBase.truncate()
        for item in data:
            formatted = {'node': item}
            DataBase.insert(formatted)
        return 'data has been added!!'

    def read_data(self, DataBase):
        """ Reads all the data in the selected database """
        data = DataBase.all()
        return data

    def update_nodes(self, node):
        """ Updates the list of nodes on one node to prevent loops when announcing new nodes on the network"""
        self.nodes.append(node)
        self.add_data(data=self.nodes, DataBase=NODES)
        return None

    def create_block(self, proof, previous_hash, forger, timestamp=str(time.time())):
        """ Used to make a block and when a block is being made the transactions are verified, invalid transactions are removed from the list of 
        transactions, the list of transactions resets. When the block is added it is announced to all the nodes as a new block """
        if len(self.chain) > 0:
            valid = self.suspendAlgorithm(forger)
            if valid == False:
                self.new_transactions = []
                miner_reward = algs.amount_change(self.chain)

                transactionlist = []
                if len(self.chain) > 0:
                    for transaction in self.unconfirmed_transactions:
                        # verify transactions and add transaction for the miner
                        valid = self.verify_transactions(transaction)
                        if valid == True:
                            self.transactions.append(transaction)
                        else:
                            self.removeTransaction(transaction)
            

            else:
                return 'Address cannot forge block due to it being in the receiving end of a transaction in the most recent 20 blocks'
            self.add_miner_transaction('network', forger, miner_reward)

        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(timestamp),
            'proof': proof,
            'previous_hash': previous_hash,
            'data': self.transactions
        }
        self.transactions = []
        self.chain.append(block)
        self.add_data(data=self.chain, DataBase=DB)
        print(block)
        if len(self.chain) > 1:
            thread = Process(target=self.post_chain, args=(block, ))
            thread.start()
        return block

    def get_prev_block(self):
        """ get the previous block on the current blockchain """
        return self.chain[-1]


    def post_chain(self, block):
        """ sends the new block to all nodes """
        for nodes in self.nodes:
            try:
                node = nodes['node']
                json = {"block": block}
                url = r.post(f'http://{node}/insert_block', json=json)
                url_status = url.status_code
                print(f"http://{node}/insert_block {url_status}")
            except:
                None
        return 'chain is updated among all nodes'

    def update_chain(self, block: dict):
        """ Updates the chain and checks if the new block is valid """
        lengthofunconfirmedtransactions = len(self.unconfirmed_transactions)
        lengthofblocktransactions = len(block['data'])
        if lengthofunconfirmedtransactions > lengthofblocktransactions:
            new_chain = self.read_data(DB)
            sizeCheck = self.recevBlockCheckSize(block=block)
            new_chain.append(block)
            if len(new_chain) > len(self.chain):
                valid = self.is_chain_valid(chain=new_chain)
                self.checkTransactions(block)
                if valid == True and sizeCheck == True:
                    self.add_data(data=self.chain)
                    self.chain = new_chain
                return self.chain
            else:
                self.replace_chain()
                return self.chain
        else:
            self.replace_chain()
        self.unconfirmed_transactions = []
        # self.add_data(data=self.unconfirmed_transactions, DataBase=UNconfirmed_transactions)
        return self.chain

    def proof_of_work(self, previous_proof):
        """ This is used for mining, the proof of work algorithm """
        new_proof = 1
        check_proof = False

        chain = self.chain
        while check_proof is False:
            if chain == self.chain:
                hash_op = hashlib.sha256(str(new_proof**2 -
                                             previous_proof**2).encode()).hexdigest()
                work = algs.difficulty_increase(self.chain, self.nodes)
                if hash_op[:len(work)] == algs.difficulty:
                    check_proof = True
                else:
                    new_proof += 1
            else:
                check_proof = False
                break
        return new_proof

    def add_false_transactions(self, transaction):
        """ Adds fake transactions """
        transactions = []
        transactions.append(transaction)
        decoy_transact = decoy_transactions.decoy_transactions(
            transactions=transactions)
        for decoy in decoy_transact:
            transactions.append(decoy)
        return transactions

    def hash(self, block):
        """This is used to hash a block using sha256"""
        encoded = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    def blockSizeCheck(self, transactions: list):
        """ Checks the block size of blocks that haven't been created yet """
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(time.time()),
            'proof': random.randint(200, 1000000000000),
            'previous_hash': hashlib.sha256(self.chain[-1].encode()).hexdigest(),
            'data': transactions + transactions[-1]
        }

        size_check = self.dynamicSizeLimit(block)
        return size_check

    def recevBlockCheckSize(self, block):
        """ Checks block size of a newly made block """
        sizeofblock = self.dynamicSizeLimit(block)
        return sizeofblock

    def dynamicSizeLimit(self, Newblock):
        """ Checks using the newest 100 blocks' size """
        sizeofblock = 0
        if len(self.chain) >= 20:
            newest100blocks = self.chain[-20:]
        else:
            newest100blocks = self.chain
        for block in newest100blocks:
            sizeofblock = sys.getsizeof(block) + sizeofblock
        mean = sizeofblock / 20
        times2 = mean * 2
        if sys.getsizeof(Newblock) <= times2:
            return True
        else:
            return False

    def is_chain_valid(self, chain, work=algs.count, limit=algs.difficulty):
        """Checks if the chain is valid with checking the previous hash and the proof"""
        previous_block = chain[0]
        block_index = 1
        algs.difficulty_increase(chain, self.nodes)
        while block_index < len(chain):
            block = chain[block_index]

            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof - previous_proof).encode()).hexdigest()
            # prev_block = chain[block_index - 1]
            if block['index'] == previous_block['index']:
                return False

            if hash_operation[:len(work)] == limit:
                return False
            previous_block = block
            block_index += 1
        return True

    def add_miner_transaction(self, sender: str, receiver: str, amount: float):
        """ This is used to add miner transactions """
        hashed_sender = str(pbkdf2_sha256.hash(sender))
        hashed_sender = hashed_sender.replace('$pbkdf2-sha256$29000$', '')
        hashed_receiver = str(pbkdf2_sha256.hash(receiver))
        hashed_receiver = hashed_receiver.replace('$pbkdf2-sha256$29000$', '')
        senders = ring_ct.make_ring_sign(
            blockchain=self.chain, primary_address=hashed_sender)
        receivers = ring_ct.make_ring_sign(
            blockchain=self.chain, primary_address=hashed_receiver)
        transactionID = str(uuid4())
        timestamp = str(time.time())
        transactionforsigning = {'sender': senders, 'amount': amount,
                                 'receiver': receivers, 'id': transactionID, 'timestamp': timestamp}

        transaction = transactionforsigning
        signsender = transaction

        minertransaction = {'sender': senders, 'amount': amount, 'receiver': receivers,
                            'sender signature': 'Network', 'id': transactionID, 'timestamp': timestamp, 'type': 'Transaction'}
        self.transactions.append(minertransaction)
        previous_block = self.get_prev_block()
        return previous_block['index'] + 1

    def checkTransactions(self, block):
        """ checks if a transaction is in new block """
        return numOfTransactionsInBlock

    def doubleSpendCheck(self, transaction):
        """ checks for double spending in the block"""
        verify = self.equals(transaction)
        verify2 = self.timeStampCheck(transaction)
        verify3 = self.duplicate_id_in_chain(transaction)
        if verify == True or verify2 == True or verify3 == True:
            return True
        return False

    def equals(self, transaction):
        """ checks for repeat transcation ids in the transaction """
        for uncontransaction in self.unconfirmed_transactions:
            transactionID = transaction['id']
            unconfirmedtransactionID = uncontransaction['id']
            if transactionID == unconfirmedtransactionID:
                return True
        return False
    
    def duplicate_id_in_chain(self, transaction):
        """ Checks the transaction id in the whole blockchain """
        unconfirmed_id = transaction['id']
        for block in self.chain:
            if block['index'] != 1:
                for valid_transaction in block['data']:
                        print(valid_transaction)
                        if unconfirmed_id == valid_transaction['id']:
                            return True
        return False



    def timeStampCheck(self, transaction):
        """ Checks for a reapeat timestamp in the transaction """
        for uncontransaction in self.unconfirmed_transactions:
            unconfirmedtimestamp = uncontransaction['timestamp']
            transactiontimestamp = transaction['timestamp']
            if unconfirmedtimestamp == transactiontimestamp:
                return True
        return False

    def suspendAlgorithm(self, address):
        """ Checks to see if the address is reapeating in the blockchain, this is to prevent someone from owning too 
        much of the blockchain and fight against large scale mining and 51% attacks """
        blockIndex = self.chain[-1]['index']
        blockIndex = blockIndex - 20
        if blockIndex >= 0:
            for block in self.chain[20:]:
                for data in block['data']:
                    for receiver in data['receiver']:
                        stealthAddress = receiver
                        verify = Check_Wallet_Balance().verify_keys(
                            publickey=stealthAddress, privatekey=address)
                        if verify == True:
                            return True
            return False
        if blockIndex < 0:
            for block in self.chain[1:]:
                for data in block['data']:
                    for receiver in data['receiver']:
                        stealthAddress = receiver
                        verify = Check_Wallet_Balance().verify_keys(
                            publickey=stealthAddress, privatekey=address)
                        if verify == True:
                            return True
            return False

    def broadcast_transaction(self, transaction):
        """ sends list of unconfirmed transactions to all nodes """
        for nodes in self.nodes:
            node = nodes['node']
            url = f'http://{node}/add_transaction/'
            json = {'transaction': transaction}
            r.post(url, json=json)

    def add_transaction(self, sendersignature: str, sender, receiver, amount: float, transactionID: str):
        """ This is used to add transactions so they can be verified """

        return unconfirmedTransaction

    """ to prevent loops in the network when adding transactions """

    def add_unconfirmed_transaction(self, sendersignature: str, sender, receiver, amount: float):
        """ This is used to add transactions so they can be verified """

        unconfirmedTransaction = {'sender send publickey': sender, 'signature':sendersignature,
                                   'receiver': receiver, 'amount': amount, 'id': str(uuid4()), 'timestamp': time.time(), 'type': 'Transaction'}
        verify = self.doubleSpendCheck(unconfirmedTransaction)
        if verify == False:
            self.unconfirmed_transactions.append(unconfirmedTransaction)

        return unconfirmedTransaction

    def verify_transactions(self, transaction):
        """ verifies transactions on the blockchain """
        sender = transacton['sender']
        receiver = transaction['receiver']
        signature_of_sender = transaction['signature']
        transaction_signature_is_valid = signatures.verify(public_key=sender, receiver=receiver, signature=signature_of_sender)
        double_spend = self.doubleSpendCheck(transaction)
        if double_spend == False and transaction_signature_is_valid == True:
            return True
        else:
            return False






    # P2p nodes
    def removeTransaction(self, transaction):
        """ Removes invalid transactions """
        self.unconfirmed_transactions.remove(transaction)

    def add_node(self, address):
        """ This method adds a node to the network """
        test = r.get(f'http://{address}/get_the_chain')
        if test.status_code == 200:
            new_node = address
            self.nodes.append(new_node)
            # self.nodes = set(self.nodes)
            # self.nodes = list(self.nodes)
            # self.add_node_to_file()
            self.add_node_to_file_tinydb(self.nodes, NODES)
            self.nodes = self.read_data(NODES)
        return self.nodes[-1]

        # try:
        #     if test.status_code == 200:
        #         for node in self.nodes:
        #             json = {'node':address}
        #             r.post(f'http://{node}/add_one_node/', json=json)
        #             json = {'node':node}
        #             r.post(f'http://{address}/add_one_node/', json=json)

        #         return self.nodes[-1]
        #     else:
        #         return {'message': 'invalid node address!'}
        # except:
        #     return {'message': 'invalid node address!'}

        """
        Get the chain and validity of the chain among the nodes
        Find the blockchain with the greatest length and replace the other chains
        """

    def replace_chain(self):
        """ This replaces the chain and checks if it is valid """

        if len(self.nodes) == 0:
            return {'message': 'add some nodes to get the latest chain', 'blockchain': self.chain}
        else:
            longest_chain = None
            print(self.nodes)
            max_length = len(self.chain)
            for nodes in self.nodes:
                node = nodes['node']
                try:
                    print(f'http://{node}/get_the_chain')
                    response = r.get(f'http://{node}/get_the_chain')
                    if response.status_code == 200:
                        length = response.json()['length']
                        chain = response.json()['blockchain']
                        if length > max_length and self.is_chain_valid(chain=chain):
                            max_length = length
                            longest_chain = chain
                    if longest_chain != None:
                        if len(longest_chain) > len(self.chain):
                            self.chain = longest_chain
                            self.unconfirmed_transactions = []
                            self.add_data(
                                data=self.unconfirmed_transactions, DataBase=UNconfirmed_transactions)
                            return True
                        else:
                            longest_chain = self.chain
                    else:
                        longest_chain = self.chain
                    if response.status_code != 200:
                        longest_chain = self.chain
                        max_length = len(self.chain)
                except:
                    longest_chain = self.chain


            return False
