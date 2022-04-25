#!/usr/bin/python3
import hashlib
import time
import json
from urllib.parse import urlparse
from uuid import uuid1, uuid4
import requests as r
import sys
import random 
from passlib.hash import pbkdf2_sha256
import base64
sys.path.insert(0,'Utilities')
from cryptography_testing import *
from tinydb import TinyDB, Query
sys.path.insert(0, 'Utilities/ProofOfStake')
from main import ProofOfStakeMAIN
import datetime
#git add .
#git commit -m "Message"
#git push
algs = Algs()
ring_ct = Ring_CT()
decoy_transactions = Decoy_addresses()
DB = TinyDB('db_blockchain.json')
NODES = TinyDB('nodes.json')
UNconfirmed_transactions = TinyDB('unconfirmed_transactions.json')
signature = Signatures()
wallet_bal = Check_Wallet_Balance()


class Blockchain:
    """ the blockchain class """

    def __init__(self):
        self.nodes = []
        if len(self.read_data(NODES)) > len(self.nodes):
            self.nodes = self.read_data(NODES)
        else:
            # NODES.insert(self.nodes)
            # self.read_data(NODES)
            # self.nodes = []
            None


        self.unconfirmed_transactions = []
        self.new_transactions = []
        self.allnodes = None
        self.chain = [] #stores the blockchain
        self.old_chain = self.read_data(DataBase=DB) #Checks to see if a chain is already present
        if len(self.old_chain) > len(self.chain):
            self.chain = self.old_chain
            self.transactions = []
        else:
            self.transactions = ["How's our data?"]
            self.create_block(proof = 1, previous_hash="0", forger='Network', timestamp='0') #helps with block creation
        self.replace_chain()
    

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


    def add_smartContract(self, senderprivatekey:str, senderviewkey:str, sendersendpublickey, receiver, compiledcontract):
        """ This is used to add transactions so they can be verified """

        unconfirmedTransaction = {'sender send publickey':sendersendpublickey, 'sender send privatekey': senderprivatekey, 'sender address': senderviewkey, 'receiver': receiver,'amount':algs.fee,'id': uuid1(),'timestamp': time.time(), 'type':'Contract', 'contract': compiledcontract}
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
                        validtransaction = self.verify_transactions(transaction)
                        if validtransaction != None:
                            self.transactions.append()
                    if len(self.transactions) > 0:
                        blocksizelimit = False
                        for transaction in self.transactions:
                            if blocksizelimit(transactionlist) == False:
                                hashed_sender = transaction['sender']

                                hashed_receiver = transaction['receiver']
                                signature = str(transaction['sender signature'])
                                transactionid = str(transaction['id'])
                                timestamp = str(transaction['timestamp'])

                                sender_sign = ring_ct.ring_sign(blockchain=self.chain, primary_address=hashed_sender)
                                receiver_sign = ring_ct.ring_sign(blockchain=self.chain, primary_address=hashed_receiver)
                                amount = transaction['amount']
                                new_transaction = {'sender': sender_sign,'amount': amount, 'receiver':receiver_sign, 'sender signature': signature, 'id': transactionid, 'timestamp': timestamp}
                                transactionlist.append(new_transaction)
                                self.new_transactions.append(new_transaction)
                                self.transactions = self.new_transactions
                            else:
                                break
                    sender = Decoy_addresses().decoy_keys()['publickey']
                    self.add_miner_transaction(sender=sender, receiver=forger, amount=miner_reward)
            else:
                return 'Address cannot forge block due to it being in the receiving end of a transaction in the most recent 20 blocks'

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
        self.post_chain(block)
        return block
    

    def get_prev_block(self):
        """ get the previous block on the current blockchain """
        return self.chain[-1]
    
    def signaturecheck(self, transaction):
        supposed_sign = wallet_bal.sign_transactions(transaction)
        actual_sign = transaction['sender signature'] + '$pbkdf2-sha256$29000$'
        verified = wallet_bal.verify_keys(publickey=actual_sign, privatekey=supposed_sign)
        return verified


    def post_chain(self, block):
        """ sends the new block to all nodes """
        for node in self.nodes:
            chain = block
            json = {'blockchain':chain}
            url = r.post(f'http://{node}/insert_block', json)
            url_status = url.status_code
            print(f"http://{node}/insert_block \n{url_status}")
        return 'chain is updated among all nodes'

    def update_chain(self, block:dict):
        """ Updates the chain and checks if the new block is valid """
        lengthofunconfirmedtransactions = len(self.unconfirmed_transactions)
        lengthofblocktransactions = len(block['data'])
        if lengthofunconfirmedtransactions < lengthofblocktransactions:
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
                work = algs.difficulty_increase(chain=self.chain, nodes=self.nodes)
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
        decoy_transact = decoy_transactions.decoy_transactions(transactions=transactions)
        for decoy in decoy_transact:
            transactions.append(decoy)   
        return transactions

    def hash(self, block):
        """This is used to hash a block using sha256"""
        encoded = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    def blockSizeCheck(self, transactions:list):
        """ Checks the block size of blocks that haven't been created yet """
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(time.time()),
            'proof': random.randint(200,1000000000000),
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
        algs.difficulty_increase(chain=chain, nodes=self.nodes)
        while block_index < len(chain):
            block = chain[block_index]

            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof - previous_proof).encode()).hexdigest()
            # prev_block = chain[block_index - 1]
            if block['index'] == previous_block['index']:
                return False
            

            if hash_operation[:len(work)] == limit:
                return False
            previous_block = block
            block_index += 1
        return True


    def add_miner_transaction(self, sender:str, receiver:str, amount:float):
        """ This is used to add miner transactions """
        hashed_sender = str(pbkdf2_sha256.hash(sender))
        hashed_sender = hashed_sender.replace('$pbkdf2-sha256$29000$', '')
        hashed_receiver = str(pbkdf2_sha256.hash(receiver))
        hashed_receiver = hashed_receiver.replace('$pbkdf2-sha256$29000$', '')
        senders = ring_ct.make_ring_sign(blockchain=self.chain, primary_address=hashed_sender)
        receivers = ring_ct.make_ring_sign(blockchain=self.chain, primary_address=hashed_receiver)
        transactionID = str(uuid4())
        timestamp = str(time.time())
        transactionforsigning = {'sender': senders, 'amount': amount, 'receiver': receivers, 'id': transactionID, 'timestamp': timestamp}
        
        transaction = self.signTransaction(transactionforsigning)
        signsender = transaction

        minertransaction = {'sender': senders,'amount': amount, 'receiver':receivers, 'sender signature': signsender, 'id': transactionID, 'timestamp': timestamp, 'type': 'Transaction'}
        self.transactions.append(minertransaction)
        previous_block = self.get_prev_block()
        return previous_block['index'] + 1
    


    def checkTransactions(self, block):
        """ checks if a transaction is in new block """
        numOfTransactionsInBlock = 0
        for transaction in block['data']:
            verify1 = self.equals(transaction)
            verify2 = self.signaturecheck(transaction)
            if verify1 == True and verify2 == True:
                self.unconfirmed_transactions.remove(transaction)
                numOfTransactionsInBlock = numOfTransactionsInBlock + 1
        return numOfTransactionsInBlock
                

    def doubleSpendCheck(self, transaction):
        """ checks for double spending in the block"""
        verify = self.equals(transaction)
        verify2 = self.timeStampCheck(transaction)
        if verify == True or verify2 == True:
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
        if blockIndex >=0:
            for block in self.chain[20:]:
                for data in block['data']:
                    for receiver in data['receiver']:
                        stealthAddress = receiver
                        verify = Check_Wallet_Balance().verify_keys(publickey=stealthAddress, privatekey=address)
                        if verify == True:
                            return True
            return False
        if blockIndex < 0:
            for block in self.chain[1:]:
                for data in block['data']:
                    for receiver in data['receiver']:
                        stealthAddress = receiver
                        verify = Check_Wallet_Balance().verify_keys(publickey=stealthAddress, privatekey=address)
                        if verify == True:
                            return True
            return False
            





    def broadcast_transaction(self, transaction):
        """ sends list of unconfirmed transactions to all nodes """
        for node in self.nodes:
            url = f'http://{node}/add_transaction/'
            json = {'transaction': transaction}
            r.post(url, json)


    def add_transaction(self, senderprivatekey:str, senderviewkey:str, sendersendpublickey, receiver, amount:float, transactionID:str):
        """ This is used to add transactions so they can be verified """

        unconfirmedTransaction = {'sender send publickey':sendersendpublickey, 'sender send privatekey': senderprivatekey, 'sender address': senderviewkey, 'receiver': receiver,'amount': amount,'id': transactionID,'type': 'Transaction'}
        verify = self.doubleSpendCheck(unconfirmedTransaction)
        if verify == False:
            self.unconfirmed_transactions.append(unconfirmedTransaction)

        return unconfirmedTransaction



    """ to prevent loops in the network when adding transactions """
    def add_unconfirmed_transaction(self, senderprivatekey:str, senderviewkey:str, sendersendpublickey, receiver, amount:float):
        """ This is used to add transactions so they can be verified """
 
        unconfirmedTransaction = {'sender send publickey':sendersendpublickey, 'sender send privatekey': senderprivatekey, 'sender address': senderviewkey, 'receiver': receiver,'amount': amount,'id': str(uuid4()),'timestamp': time.time(), 'type': 'Transaction'}
        verify = self.doubleSpendCheck(unconfirmedTransaction)
        if verify == False:
            self.unconfirmed_transactions.append(unconfirmedTransaction)

        return unconfirmedTransaction





    def verify_transactions(self, transaction):
        """ verifies transactions on the blockchain """
        senderSendPublickey = transaction['sender send publickey']
        senderSendPrivatekey = transaction['sender send privatekey']
        senderviewkey = transaction['sender address']
        receiver = transaction['receiver']
        amount = transaction['amount']
        transactionID = transaction['id']
        timestamp = transaction['timestamp']
        transactionType = transaction['type']
        if transactionType == 'Contract':
            Contract = transaction['contract']
        else:
            Contract = None 
        if amount > 0:
            verify4 = True
        else:
            verify4 = False
        verify1 = Check_Wallet_Balance().verify_keys(publickey=senderSendPublickey, privatekey=senderSendPrivatekey)
        verify2 = Check_Wallet_Balance().verify_keys(publickey=senderviewkey, privatekey=senderSendPrivatekey)
        address = primary_addresses().make_primary_address(senderviewkey)
        balance = Check_Wallet_Balance().balance_check(public_view_key=senderviewkey, blockchain=self.chain, transaction=transaction)
        balance = balance['balance']
        newBalance = balance - amount
        if verify1 == True and verify2 == True and newBalance >= 0 and verify4 == True:
            hashed_sender = str(pbkdf2_sha256.hash(address))
            hashed_sender = hashed_sender.replace('$pbkdf2-sha256$29000$', '')
            hashed_receiver = str(pbkdf2_sha256.hash(receiver))
            hashed_receiver = hashed_receiver.replace('$pbkdf2-sha256$29000$', '')

            senders = ring_ct.make_ring_sign(blockchain=self.chain, primary_address=hashed_sender)
            receivers = ring_ct.make_ring_sign(blockchain=self.chain, primary_address=hashed_receiver)
            transactionforsigning = {'sender': senders, 'amount': amount, 'receiver': receivers, 'id': transactionID, 'timestamp': timestamp}
            senderSign = self.signTransaction(transactionforsigning)
            # receiverSign = transaction['signature of receiver']
            if Contract == None:
                verifiedTransaction = {'sender': hashed_sender, 'amount': amount, 'receiver': hashed_receiver, 'sender signature': senderSign, 'id': transactionID, 'timestamp':timestamp, 'type': 'Transaction'}
            if transactionType == "Contract":
                verifiedTransaction = {'sender': hashed_sender, 'amount': amount, 'receiver': hashed_receiver, 'sender signature': senderSign, 'id': transactionID, 'timestamp':timestamp, 'type': 'Contract', 'contract': Contract}
            verify3 = self.doubleSpendCheck(verifiedTransaction)
            if verify3 == False:
                return verifiedTransaction
            else:
               
                self.removeTransaction(transaction)
        else:
            self.removeTransaction(transaction)


    def signTransaction(self, full_transaction):
        """ signs transactions """
        transaction = full_transaction
        full_signature = signature.signTransaction(transaction)
        return full_signature

    #P2p nodes
    def removeTransaction(self, transaction):
        """ Removes invalid transactions """
        self.unconfirmed_transactions.remove(transaction)



    def add_node(self, address):
        """ This method adds a node to the network """
        test = r.get(f'http://{address}/get_the_chain')
        if test.status_code == 200:
            new_node = address
            self.nodes.append(new_node)
            self.nodes = set(self.nodes)
            self.nodes = list(self.nodes)
            # self.add_node_to_file()
            self.add_data(data=self.nodes, DataBase=NODES)
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
        network = self.nodes
        if len(self.nodes) == 0:
            return {'message': 'add some nodes to get the latest chain','blockchain': self.chain}
        else:
            longest_chain = None
            max_length = len(self.chain)
            for node in network:
                print(f'https://{node}/get_the_chain')
                response = r.get(f'https://{node}/get_the_chain')
                if response.status_code==200:
                    length = response.json()['length']
                    chain = response.json()['blockchain']
                    if length > max_length and self.is_chain_valid(chain=chain):
                        max_length = length
                        longest_chain=chain
                if longest_chain != None:
                    if len(longest_chain) > len(self.chain):
                        self.chain = longest_chain
                        self.unconfirmed_transactions = []
                        self.add_data(data=self.unconfirmed_transactions, DataBase=UNconfirmed_transactions)
                        return True
                    else:
                        longest_chain = self.chain
                else:
                    longest_chain = self.chain
                if response.status_code != 200:
                    longest_chain = self.chain
                    max_length = len(self.chain)
                
                return False

    def protocol_connections(self):
        """ The Token Protocol p2p network connection algorithm"""
        all_nodes = self.get_most_nodes()
        interval1 = random.randint(2, len(all_nodes))
        x = 0
        while x != interval1:
            self.nodes.append(random.choice(all_nodes))
            x = x + 1
        return self.nodes


    def get_most_nodes(self):
        """ gets some of the nodes on the network """
        all_nodes = self.nodes
        if len(all_nodes) < 2:
            for node in all_nodes:
                node_sets = r.get(f'https://{node}/show_nodes')
                status = node_sets.status_code
                if status == 200:
                    all_nodes.append(node_sets.json()['nodes'])
                    all_nodes = set(all_nodes)
                    all_nodes = list(all_nodes)
                for nodes in node_sets:
                    more_nodes = r.get(f'https://{nodes}/show_nodes')
                    if more_nodes.status_code == 200:
                        all_nodes.append(more_nodes.json()['nodes'])
                        all_nodes = set(all_nodes)
                        all_nodes = list(all_nodes)
        else:
            return {'message': 'you must add more manually'}
        self.allnodes = all_nodes
        return self.allnodes

                    




    
    def update_transactions(self):
        """ updates the list of transactions """
        network = len(self.nodes)
        if network != 0:
            current_transactions = self.transactions
            updated_transactions = []
            length_current = len(self.chain)
            for node in network:
                node_transactions = r.get(f'http://{node}/get_the_chain').json()
                is_valid = self.is_chain_valid(node_transactions)
                if is_valid != True:
                    continue
                else:
                    i = 1
                    ii = 1
                    iii = 0
                    length = node_transactions['length']
                    while length > i:
                        while ii < len(node_transactions['blockchain'][i]['transactions']):
                            transactions = node_transactions['blockchain'][i]['transactions']
                            if transactions == self.chain[i][transactions]:
                                i = i + 1

                            else:
                                if i - 1 == length_current:
                                    iii = 0
                                    while len(transactions) > iii:
                                        if self.transactions != transactions[iii]:
                                            self.transactions.append(transactions[iii])
                                        iii = iii + 1
                                    ii = ii + 1
                                    return False
                                else:
                                    self.replace_chain()
                                    return True                     
        else:
            return {'message': 'No nodes found in node.'}
