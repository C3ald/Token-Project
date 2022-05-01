from pyclbr import Class
from stake_pool import stake_pool
from winnerpick import PickWinner
import time
import requests


class WithDrawStake:
    """ Withdraw stake depending on how long it has been in the pool """

    def __init__(self, blockchain: Class):
        self.blockchain = blockchain
        self.winnerpick = PickWinner()
        self.stake_pool = stake_pool(Blockchain=self.blockchain)

    def withdraw(self, staker: dict):
        """ Withdraw all stake from pool """
        time_staker = staker['time']
        time_check = self.time_check(time_staker_was_added=time_staker)
        if time_check == True:
            self.blockchain.add_miner_transaction(sender='')

    def time_check(self, time_staker_was_added):
        """ If it has been at 1 Day the stake can be withdrawn """
        t = time.time()
        difference = t - time_staker_was_added
        if difference > 86400.0:
            return True
        return False

    def get_my_public_ip(self):
        """ Gets the public ip of YOUR node """
        endpoint = 'https://ipinfo.io/json'
        response = requests.get(endpoint, verify=True)

        if response.status_code != 200:
            return 'Status:', response.status_code, 'Problem with the request. Exiting.'

        data = response.json()

        return data['ip']
