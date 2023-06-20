import rsa
from Crypto.Cipher import AES
import os
import hashlib
import json
from flask import Flask, request

def new_user(pb_name="public_key.pem", pr_name="private_key.pem", vr_name="verfy.sec"):
    (public_key, private_key) = rsa.newkeys(2048)
    p_private_key = private_key.save_pkcs1(format='PEM')
    p_public_key = public_key.save_pkcs1(format='PEM')
    with open(pb_name, "wb") as f:
        f.write(p_public_key)
    with open(pr_name, "wb") as f:
        f.write(p_private_key)
    with open(vr_name, "wb") as f:
        key = os.urandom(32)
        f.write(key)
        cipher = AES.new(key, AES.MODE_EAX)
    print("New user created successfully")

def entry(data,file_pb,file_vr,id,db_file='main.json'):
    with open(file_pb, 'rb') as f:
        pr_key = f.read()
        public_key = rsa.PublicKey.load_pkcs1(pr_key)
    enc_data = rsa.encrypt(data.encode('utf-8'), public_key)
    with open(file_vr, 'rb') as f:
        key = f.read()
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
    sha_data = hashlib.sha256(data.encode("utf-8"))
    print(sha_data)
    token, tag = cipher.encrypt_and_digest(sha_data.digest())
    with open(db_file, "r")as f:
        re = f.read()
        if re == "":
            re = "[]"
        old_d = json.loads(re)
        data = {"id": id, "data": enc_data.hex(), "token": token.hex(), "nonce": nonce.hex()}
        ap = True
        for entry in old_d:
            if entry["id"] == id:
                entry["data"] = enc_data.hex()
                entry["token"] = token.hex()
                entry["nonce"] = nonce.hex()
                ap = False
                break
            else:
                ap = True
        if ap == True:
            old_d.append(data)
    with open(db_file, "w")as s:
        json.dump(old_d, s)
        return "DumP"
        

def see_entry(file_pr,file_vr,id,db_file='main.json'):
    with open(file_pr, 'rb') as f:
        pr_key = f.read()
        private_key = rsa.PrivateKey.load_pkcs1(pr_key)
    with open(file_vr, "rb") as f:
        key = f.read()
    with open(db_file, "r") as f:
        nm_data = f.read()
        data = json.loads(nm_data)
    for entry in data:
        print(entry)
        if entry["id"] == id:
            entr = entry
            break
    iv = bytes.fromhex(entr["nonce"])
    dc_data = rsa.decrypt(bytes.fromhex(entr["data"]), private_key)
    sha_data = hashlib.sha256(dc_data)
    print(sha_data)
    cipher = AES.new(key, AES.MODE_EAX, nonce=iv)
    token = cipher.encrypt_and_digest(sha_data.digest())
    if token[0].hex() == entr["token"]:
        return None,dc_data.decode('utf-8')
    else:
        return "DATA has been MODIFIED !!", dc_data.decode('utf-8'), print(token[0].hex())
class interfaces():
    def interface():
            while True:
                try:
                    inp = input("secDB:>")
                    if inp == "new user":
                        new_user(input("Public Key Name:>"),input("Private key Name:>"),input("Verify file Name:>"))
                    elif inp == "entry":
                        print(entry(input("Data:>"), input("Public Key:>"), input("Verify file:>"),input("id:>"),input("DB file:>")))
                    elif inp == "see":  
                        print(see_entry(input("Private key:>"), input("Verify file:>"), input("id:>"),input("DB file:>")))
                    elif inp == "help":
                        print("""
                        new user   - creates a new user
                        entry      - makes or modify an entry
                        see        - see and verify an entry
                        help       -this
                        """)
                    elif inp == "clear":
                        if os.name == 'nt':  
                            os.system('cls')
                        else:  
                            os.system('clear')
                except Exception as e:
                    print(e)
    def server():
        app = Flask(__name__)
        @app.route('/auth', methods=['POST'])
        def auth():
            user = request.form['user']
            pb_key = request.form['pb_key']
            pr_key = request.form['pr_key']
            verf_key = request.form['verf_key']
            db_file = request.form['db_file']
            pas = request.form['pas']

            user_data_dict = {
                'user': user,
                'pb_key': pb_key,
                'pr_key': pr_key,
                'verf_key': verf_key,
                'db_file': db_file,
                'pas': pas
            }

            # Convert the dictionary to a JSON string
            user_data = json.dumps(user_data_dict)
            return user_data



if __name__ == "__main__":
    interfaces.interface()