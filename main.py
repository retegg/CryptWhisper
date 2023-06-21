import json
from secure_db import secDB
import os
import traceback
import sys
import time
import requests
from flask import Flask, request
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time
import threading

def tunnel():
    global config
    app = Flask(__name__)
    global url_tunnel
    @app.route('/rsa')
    def rs_pb():
        with open('admin/admin_pb.pem', 'rb') as f:
            key_data = f.read()
            return key_data

    @app.route('/conn')
    def conn():
            global url
            global proxies
            url = request.args.get('url')
            if url:
                response = requests.get(url)
                time.sleep(1)
                url_r = url + "/rsa"
                response = requests.get(url_r)
                rsa_k = response.text
                public_key = RSA.import_key(rsa_k)
                cipher = PKCS1_OAEP.new(public_key)
                msg = input("<|msg|>:")
                msg = msg.encode("utf-8")
                ciphertext = cipher.encrypt(msg)
                response = requests.get(f"{url}/lis?data={ciphertext.hex()}", proxies=proxies)
                requests.get(f"{url_tunnel}/conn?url={url}", stream=True, proxies=proxies)
                return "ok!"
            else:
                return "No URL provided."
    @app.route('/lis')
    def lis():
        global url_tunnel
        global url
        global proxies
        data = request.args.get('data')
        with open('admin/admin_pr.pem', 'rb') as file:
            private_key_pem = file.read()
        private_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(private_key)
        ciphertext = bytes.fromhex(data)
        plaintext = cipher.decrypt(ciphertext)
        print(f">>|{plaintext.decode()}|<<")
        requests.get(f"{url}/conn?url={url_tunnel}", stream=True, proxies=proxies)
        requests.get(f"{url_tunnel}/conn?url={url}", stream=True, proxies=proxies)
        return "ok!"

    app.run("0.0.0.0")
if __name__ == '__main__':
    #CHEK IF ADMIN KEY ARE IN
    dir = os.listdir("./admin")
    if str(dir) == "[]":
        secDB.new_user("admin/admin_pb.pem", "admin/admin_pr.pem","admin/admin_v.sec")
    else:
        print("key is already generated.")
    #LOAD CONFIG
    with open("config.json", "r") as config:
        config = json.load(config)
        url_tunnel = config["url_tunnel"]
        proxies = config["list_proxy"]
    #CHECK IF USER DB CRATED
    dir = os.listdir(config["Database_folder"])
    user_file = config["Database_folder"]+"/"+config["Contacts_file"]
    if config["Contacts_file"] not in str(dir):
        with open(user_file, 'w') as f:
            pass
        secDB.entry("-1", "admin/admin_pb.pem", "admin/admin_v.sec","n", user_file)
    else:
        print(dir)
        print("Database is already generated.")
    #INTERFACE
    print("""
_________                                __     __      __  .__      .__                                      
\_   ___ \  _______   ___.__. ______   _/  |_  /  \    /  \ |  |__   |__|   ______ ______     ____   _______  
/    \  \/  \_  __ \ <   |  | \____ \  \   __\ \   \/\/   / |  |  \  |  |  /  ___/ \____ \  _/ __ \  \_  __ \ 
\     \____  |  | \/  \___  | |  |_| |  |  |    \        /  |   Y  \ |  |  \___ \  |  |_| | \  ___/   |  | \/ 
 \______  /  |__|     / ____| |   __/   |__|     \__/\  /   |___|  / |__| /____  > |   __/   \___  >  |__|    
        \/            \/      |__|                    \/         \/            \/  |__|          \/           
                                                                                                              
    """)
    while True:
        try:
            cm = input("<|CryptWhisper|>:")
            if cm == "help":
                print("""░█▀▀░█▀▄░█░█░█▀█░▀█▀░█░█░█░█░▀█▀░█▀▀░█▀█░█▀▀░█▀▄
░█░░░█▀▄░░█░░█▀▀░░█░░█▄█░█▀█░░█░░▀▀█░█▀▀░█▀▀░█▀▄
░▀▀▀░▀░▀░░▀░░▀░░░░▀░░▀░▀░▀░▀░▀▀▀░▀▀▀░▀░░░▀▀▀░▀░▀""")
                print("url: conect to a tunnel")
                print("tunnel: generate a tunnel url")
                print("list: list the users in the ", config["Contacts_file"], " file")
            elif cm == "url":
                key = ""
                url = input("url: ")
                _, num = secDB.see_entry("admin/admin_pr.pem", "admin/admin_v.sec", "n", user_file)
                print(int(num))
                print("---")
                for i in range(int(num)+1):
                    print("---------")
                    print(i)
                    _, data = secDB.see_entry("admin/admin_pr.pem", "admin/admin_v.sec", i, user_file)
                    print(data)
                    if data == "DATA has been MODIFIED !!":
                        print("DATA of id ", i, "has been modified !!!")
                    data = json.loads(data)
                    if data["url"] == url:
                        key = data["key"] 
                        break
                print(key)
                print("finish")
                if key == "":
                    print("USER KEY NOT FOUND PLS REQUEST")
                    key = input("Key: ")
                    json_d = '{"url": "'+url+'", "key": "'+key+'"}'
                    print(json)
                    secDB.entry(json_d, "admin/admin_pb.pem", "admin/admin_v.sec",int(num)+1, user_file)
                    time.sleep(1)
                    print("modify")
                    secDB.entry(str(int(num)+1), "admin/admin_pb.pem", "admin/admin_v.sec", "n", user_file)
                print(key)
                thread = threading.Thread(target=tunnel)
                thread.start()
                requests.get(f"{url}/conn?url={url_tunnel}", stream=True, proxies=proxies)
            elif cm == "tunnel":
                try :
                    print("tu")
                    tunnel()
                except Exception as e :
                    print(e)
            elif cm == "list":
                pass
            elif cm == "exit":
                break
                
        except Exception as e:
            exc_type, exc_value, exc_tb = sys.exc_info()
            tb_info = traceback.extract_tb(exc_tb)
            filename, line_no, _, _ = tb_info[-1]
            print(e)
            print("Exception occurred on line", line_no, "of file", filename)
            pass
            