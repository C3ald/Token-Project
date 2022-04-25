from Voting.picknode import PICKNODE
from Voting.voting import VOTING

from add_miner_pool import Pool_miners
from proofforge import PROOF
from punish import Stake_Punishment
from stake_pool import stake_pool
from utilis import UTILS
from winnerpick import PickWinner


from pyclbr import Class
import time as t
import socket as s
import requests
import json
import threading

class ProofOfStakeMAIN:
    """ The main proof of stake class """

    def __init__(self, Blockchain, NODES):
        self.blockchain = Blockchain()
        self.picknode = PICKNODE(Blockchain=Blockchain, NODES=NODES)
        self.voting = VOTING(Blockchain=Blockchain)
        self.pool_miners = Pool_miners()
        self.proof = PROOF(Blockchain=Blockchain)
        self.stake_punishment = Stake_Punishment(Blockchain=Blockchain)
        self.stake_pool = stake_pool(Blockchain=Blockchain)
        self.UTILS = UTILS()
        self.winner_pick = PickWinner()
        self.pos = False

    def get_DomainName(self, ip_addr):
        """ Gets domain name """
        host_name = s.gethostbyaddr(ip_addr)
        if host_name != "":
            return host_name

    def get_my_public_ip(self):
        """ Gets the public ip of YOUR node """
        endpoint = 'https://ipinfo.io/json'
        response = requests.get(endpoint, verify=True)

        if response.status_code != 200:
            return 'Status:', response.status_code, 'Problem with the request. Exiting.'

        data = response.json()

        return data['ip']

    def check_if_your_node_won(self, winning_node):
        """ Checks to see if your node won """
        ip = self.get_my_public_ip
        domain = self.get_DomainName(ip)[0]
        if ip in winning_node or domain in winning_node:
            return True
        return False


    def add_miner(self, public_spend_key, private_spend_key, view_key, stake):
        """ Adds  a miner to the staker pool if the wallet address is valid """
        verify1 = Check_Wallet_Balance().verify_keys(publickey=public_spend_key, privatekey=private_spend_key)
        verify2 = Check_Wallet_Balance().verify_keys(publickey=view_key, privatekey=private_spend_key)
        address = primary_addresses().make_primary_address(view_key)
        balance = Check_Wallet_Balance().balance_check(public_view_key=view_key, blockchain=self.blockchain.chain, transaction=self.blockchain.transactions)
        newBalance = balance - stake
        if stake < 0:
            return None
        if verify1 == True and verify2 == True and newBalance > 0:
            transaction = self.blockchain.add_unconfirmed_transaction(senderprivatekey=private_spend_key, senderviewkey=view_key, sendersendpublickey=public_spend_key, receiver='Network', amount=balance)
            transactionid = transaction['id']
            th = threading.Thread(target=self.update_Staker_DB, args=(address, stake, transactionid))
            th.start()
            return f'Staker: {address} is being added... TransactionID: {str(transactionid)}'


    def update_Staker_DB(self, staker, stake, transactionid):
        """ Checks for an update in the chain and looks for the staker """
        id_check_for = transactionid
        transactionid_in_block = None
        while id_check_for != transactionid_in_block:
            for block in self.blockchain.chain:
                for data in block['data']:
                    transactionid_in_block = data['id']
                    if transactionid_in_block == id_check_for:
                        break
                    break
                break
            break
        self.stake_pool.update_data_base_for_stake_pool(staker=staker, stake=stake)



    def pick_winner(self):
        """ Picks a winner to make a new block and checks to see if your node won """
        self.picknode.vote_on_nodes()
        # t.sleep(1.5)
        voted_nodes = self.voting.get_voted_nodes()
        winner = self.voting.pick_most_popular(voted_nodes=voted_nodes)
        mynodeWon = self.check_if_your_node_won(winning_node=winner)
        return mynodeWon

    def pick_miner(self, mynodeWon:bool, miners):
        """ Picks a winning miner to forge the block. """
        chain = self.blockchain.chain
        if mynodeWon == True:
            winner = self.winner_pick.pick_winner(miners=miners)
            return winner
    
    
    
    def run_POS(self, blockchain_file):
        """ Proof of stake method checks every 1s"""
        while True: 
            if len(chain) >= 200000:
                chain = self.blockchain.read_data(blockchain_file)
                self.pos = True
                prev_block = self.blockchain.chain[-1]
                time_check = self.winner_pick.time_check(previous_block=prev_block)
                if time_check == True:
                    mynode_won = self.pick_winner()
                    if mynode_won == True:
                        winner = self.pick_miner(mynodeWon=mynode_won, miners=self.stake_pool.list_stakers())
                    #TODO Update blocks being created with proof of stake
                        proof = self.proof.make_proof(chain=self.blockchain.chain)
                        prev_hash = prev_block['proof']
                        self.blockchain.create_block(proof, previous_hash=prev_hash, forger=winner)
            else:
                self.pos = False
            t.sleep(1.0)



    
    def start_stake_process(self, blockchain_file):
        """ Starts the proof of stake sequence in the background"""
        thread = threading.Thread(target=self.run_POS, args=(blockchain_file,))
        thread.start()






