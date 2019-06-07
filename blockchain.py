import hashlib
import json
import re
from time import time

from email.headerregistry import Address
from email.message import EmailMessage
import os
import smtplib

sender = # your email id goes here!! '*****@gmail.com'
wd = # your password goes here!! '*****'

class Blockchain(object):
    def __init__(self):
        self.current_data = []
        self.chain = []
        self.nodes = set()

        # Genesis block
        self.new_block(previous_hash = '1',proof = 100)

    def proof_of_work(self, last_proof):  # (POW algorithm)
        
        """
        Simple Proof of Work Algorithm:
         - Find a number p' such that hash(pp') contains leading 4 zeroes, where p is the previous p'
         - p is the previous proof, and p' is the new proof
        :param last_proof: <int>
        :return: <int>
        """
        
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        
        """
        Validates the Proof: Does hash(last_proof, proof) contain 4 leading zeroes?
        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :return: <bool> True if correct, False if not.
        """
        
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"  # b error


    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1
        while current_index < len(chain):
            block = chain[current_index]
            
            print(f'{last_block}')
            print(f'{block}')
            print("\n---------------\n")
            
            # Check the correctness of hash
            if block['previous_hash'] != last_block['my_hash']:
                return False
            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof']):
                return False
            
            last_block = block
            current_index += 1
            
        return True

    def new_block(self, proof, previous_hash = None):
        
        """
        Create a new Block in the Blockchain
        :param proof: <int> The proof given by the Proof of Work algorithm
        :param previous_hash: <str> Hash of previous Block
        :return: <dict> New Block
        """
        
        if len(self.chain) > 0:    
            previous_hash = self.chain[-1]['my_hash']
        block = {
            'index' : len(self.chain) + 1,
            'timestamp' : time(),            
            'assignment': self.current_data,
            'proof': proof,
            'my_hash':self.hash(proof),
            'previous_hash' : previous_hash or self.hash(self.chain[-1]),
            }
        # Reset the current list of assignments
        self.current_data = []        
        self.chain.append(block)
        return block
    
    def new_assignment(self, uid, category):
        
        """
        Creates a new transaction to go into the next mined Block
        :param UID: <str> Unique Identification Number of the applicant
        :param Assigned category: <str> The category assigned to the applicant
        :return: <int> The index of the Block that will hold this assignment
        """
        
        self.current_data.append({
            'UID' : uid,
            'Assigned category' : category,
            })
        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        
        """
        Creates a SHA-256 hash of a Block
        :param block: <dict> Block
        :return: <str>
        """
        
        # The Dictionary is Ordered to avoid inconsistent hashes
        block_string = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(block_string).hexdigest()

   
def new_request():
    uid = input("Please enter your Unique Identification number ")
    if run(uid) == False:
        print("Wrong input!")
        exit()
    receiver = input("Please enter your email address ")
    if verify_email(receiver) == False:
        print("Wrong input!")
        exit()
    income = input("Please enter your Income ")
    if run(income) == False:
        print("Wrong input!")
        exit()
    else:
        income = int(income)
    if income <= 46000:
        category = 'Class - 1'
    elif income <= 450000:
        category = 'Class - 2'
    elif income <= 600000:
        category = 'Class - 3'
    elif income <= 1200000:
        category = 'Class - 4'
    elif income <= 2400000:
        category = 'Class - 5'
    else:
        category = 'Class - 6'
    index = blockchain.new_assignment(uid, category)

    last_proof = blockchain.chain[-1]['proof']
    proof = blockchain.proof_of_work(int(last_proof))
    previous_hash = blockchain.chain[-1]['previous_hash']
    blockchain.new_block(proof, previous_hash)

    email_text = 'You have been assigned the catergory : '+category
    subject = 'Category Details'

    msg = create_email_message(sender, receiver, subject, email_text)
    
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(sender, wd)
        server.send_message(msg)
        server.close()
        print ('Email sent!')
    except:
        print ('Something went wrong...')

##    print("You have been assigned the category : ", end = "")
##    print(category)
    print("Your details will be added to the Block")
    
def verify():
    """
    Verifies if UID is present in the block chain and
    displays category assigned if present
    """
    search = input("Please enter the UID to validate category ")
    for i in range(1, len(blockchain.chain)):
        if blockchain.chain[i]['assignment'][0]['UID'] == search:
            print(blockchain.chain[i]['assignment'])
            return
        print('UID not found')
        return
        

def create_email_message(from_address, to_address, subject, body):
    """
    Creates email message
    :param from_address: <str> from email address
    :param to_address: <str> to email address
    :param subject: <str> subject of email
    :param body: <str> body of email
    :return: <str> email message content 
    """
    msg = EmailMessage()
    msg['From'] = from_address
    msg['To'] = to_address
    msg['Subject'] = subject
    msg.set_content(body)
    return msg

def run(string):
    """
    Verifies if user input consists of special characters
    :param string: <str> string
    :return: <boolean> True or False
    """
    regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
    if(regex.search(string) == None): 
        return(True)           
    else: 
        return(False)

def verify_email(email):
    """
    Verifies if user input consists of special characters
    :param email: <str> email address string
    :return: <boolean> True or False
    """
    if len(email) > 1:
        return bool(re.match("^.+@(\[?)[a-zA-Z0-9-.]+.([a-zA-Z]{2,3}|[0-9]{1,3})(]?)$", email))

blockchain = Blockchain()

while(True):
    choice  = int(input("Please \nEnter 1 to request for assigment of category \nEnter 2 to verify the assigned category \nEnter 3 to EXIT \n"))
    if choice == 1:
        new_request()
    elif choice == 2:
        if blockchain.valid_chain(blockchain.chain):
            verify()
        else:
            print("BlockChain Tampered! Freeze! End process immediately!")
    elif choice == 3:
        break
    else:
        print("Wrong input!!")

            
        
        
        
