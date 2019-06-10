import cherrypy

import urllib.request
import json
import base64

import nacl.encoding
import nacl.signing

from nacl.public import PrivateKey, SealedBox

import socket
from threading import Thread

import datetime
import time

import sqlite3

#import eventlet
#eventlet.monkey_patch()



#startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css' /></head><body>"
startHTML = '<!DOCTYPE html><html><body background="https://images3.alphacoders.com/189/thumb-1920-189705.jpg"></body></html>' #for the BG
startHTML +=  '<center><!DOCTYPE html><html><head><style>h1{font-size: 300%;color:white;}</style></head><body><h1>Ahmad Umars Prototype</h1></body></html>'


class MainApp(object):

        # CherryPy Configuration
    _cp_config = {'tools.encode.on': True,
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on': 'True',
                  # increase security on sessions
                  # 'tools.sessions.secure' : 'True',
                  'tools.sessions.httponly': 'True'
                  }

    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = startHTML
        Page +=  '<center><!DOCTYPE html><html><head><style>h1{font-size: 200%;color:black;}</style></head><body><h1>Welcome! This is a prototype for a socialising web app!</h1></body></html>'
        

        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "CONGRATULATIONS!! You have successfully signed in. <a href='/signout'>Sign out</a> <br/>"
            Page += "<br>Functions available:"
            Page += "<br>&emsp; - To get a list of users, click: <a href='/api/list_apis'>List APIs</a> "
            Page += "<br>&emsp; - To get a list of users, click: <a href='/api/list_users'>List Users</a> "
            
            Page += "<br>&emsp; - To update list of users, click: <a href='/api/update_users'>Update Users</a> "
            Page += "<br>&emsp; - To add your public key to the login server, please click: <a href='/api/add_pubkey'>Add Public key</a>."
            Page += "<br>&emsp; - To <font color = 'blue'>report</font> to the login server, please click: <a href='/api/report'>Report</a>."
            Page += "<br>&emsp; - To view all broadcasted messages, please click: <a href='/api/rx_broadcast'>Broadcast Messages</a>."
            Page += "<br>&emsp; - To view received private messages, please click: <a href='/api/rx_privatemessage'>Private Messages</a>."
            #Page += "<br>  </br>"

            Page += "<br>&emsp; - To view blocked users, please click: <a href='/api/print_blocked'>View</a>."

            #Page += "<br> </br>"


            Page += "<br>&emsp; - To view blocked word, please click: <a href='/api/print_blocked_word'>View</a>."
            Page += "<br> </br>"


            Page += '<form action="/api/tx_broadcast" method="post" enctype="multipart/form-data">'
            Page += '&emsp;&emsp;&emsp;&emsp;Type your post: <input name="message"/>'
            Page += '<input type="submit" value="Publish"/></form>'

            Page += "<br> </br>"

            Page += '<form action="/api/tx_privatemessage" method="post" enctype="multipart/form-data">'
            Page += 'Type your private message &#160;&#160;  : <input name="message"/> </br>'
            Page += 'Type your receivers username(upi) : <input name="upi"/>'
            Page += '<input type="submit" value="Send"/></form>'


            Page += "<br> </br>"
            
            Page += '<form action="/api/block" method="post" enctype="multipart/form-data">'
            Page += 'Enter username to block: <input name="upi"/>'
            Page += '<input type="submit" value="Block"/></form>'

            #Page += "<br> </br>"
            
            Page += '<form action="/api/unblock" method="post" enctype="multipart/form-data">'
            Page += 'Enter username to unblock: <input name="upi"/>'
            Page += '<input type="submit" value="Unblock"/></form>'
            
            Page += "<br> </br>"
            
            Page += '<form action="/api/block_words" method="post" enctype="multipart/form-data">'
            Page += 'Enter word to block: <input name="word"/>'
            Page += '<input type="submit" value="Block"/></form>'

            Page += '<form action="/api/unblock_word" method="post" enctype="multipart/form-data">'
            Page += 'Enter word to unblock: <input name="word"/>'
            Page += '<input type="submit" value="Unblock"/></form>'

        except KeyError:  # There is no username
            Page += '<center><!DOCTYPE html><html><style>.button{border: none;color: white;padding: 16px 32px;text-align: center;text-decoration: none;display:inline-block;font-family: verdana;font-size: 20px;margin: 4px 2px;-webkit-transition-duration: 0.4s;}.button{background-color: white;color: black;border-radius:12px;border: 2px solid #555555;}.button:hover{background-color:#555555;color: white;}</style><button class="button button"><a href="login">LOG IN</a></button></html>'
            #Page += "Click here to <a href='login'>login</a>."
        return Page

    @cherrypy.expose
    def login(self, bad_attempt=0):
        Page = startHTML
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"

        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += '&emsp;&emsp;&emsp;Password  : <input type="password" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page

    @cherrypy.expose
    def sum(self, a=0, b=0):  # All inputs are strings by default
        output = int(a)+int(b)
        return str(output)

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authoriseUserLogin(username, password)
        
        if error == 0:
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            add_pubkey(self)

            report(self)
            ApiApp.update_users(self)

            start_time = time.time()
            print(start_time)
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')

    



##################################
############Functions#############
##################################

@cherrypy.expose
def ping(self):
    url = "http://cs302.kiwi.land/api/ping"
    try:
        req = urllib.request.Request(url)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        # load encoding if possible (default to utf-8)
        encoding = response.info().get_content_charset('utf-8')
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))

    return JSON_object


@cherrypy.expose
def list_apis(self):
    url = "http://cs302.kiwi.land/api/list_apis"
    try:
        req = urllib.request.Request(url)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        # load encoding if possible (default to utf-8)
        encoding = response.info().get_content_charset('utf-8')
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))
    return JSON_object

@cherrypy.expose
def list_users(self, username=None, password=None):
    url = "http://cs302.kiwi.land/api/list_users"

    username = cherrypy.session['username']
    password = cherrypy.session['password']

    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        # load encoding if possible (default to utf-8)
        encoding = response.info().get_content_charset('utf-8')
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))
    return JSON_object

@cherrypy.expose
def add_pubkey(self):
    url = "http://cs302.kiwi.land/api/add_pubkey"
    

    username = cherrypy.session['username']
    password = cherrypy.session['password']
    cherrypy.session['check'] = True

    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    priv_key = nacl.signing.SigningKey.generate()  # output is in bytes
    priv_key_hex = priv_key.encode(encoder=nacl.encoding.HexEncoder)  # not used

    public_key_hex = priv_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)

    # readable version of public key NOT BYTES
    public_key = public_key_hex.decode('utf-8')

    cherrypy.session['priv_key'] = priv_key

    cherrypy.session['public_key'] = public_key  # making pub key global
    # if you need any other version of ur pub g, add more global variables

    signature_bytes = bytes(public_key + username, encoding='utf-8')

    signature_hex = priv_key.sign(signature_bytes, encoder=nacl.encoding.HexEncoder)
    signature = signature_hex.signature.decode('utf-8')  # readable version NOT UNDERSTANDABLE

    payload = {

        "pubkey": public_key,
        "username": username,
        "signature": signature
    }

    data_string = json.dumps(payload)

    data_send = data_string.encode()

    try:
        req = urllib.request.Request(url, headers=headers, data=data_send)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        # load encoding if possible (default to utf-8)
        encoding = response.info().get_content_charset('utf-8')
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))
    
    return JSON_object

@cherrypy.expose
def report(self):

    check = False

    url = "http://cs302.kiwi.land/api/report"
    

    username = cherrypy.session['username']
    password = cherrypy.session['password']
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    public_key = cherrypy.session.get('public_key')

    payload = {
        #"connection_address": "172.24.43.158:10050",
        "connection_address": str(socket.gethostbyname(socket.gethostname())) + ":10051",
        "connection_location": 2,
        "incoming_pubkey": public_key
    }
    data_string = json.dumps(payload)
    data_send = data_string.encode()

    try:
        req = urllib.request.Request(url, headers=headers, data=data_send)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        # load encoding if possible (default to utf-8)
        encoding = response.info().get_content_charset('utf-8')
        check = True
        response.close()
    except:
        check = False
    
    
    JSON_object = json.loads(data.decode(encoding))
    check = cherrypy.session['check']
    return JSON_object

@cherrypy.expose
def load_new_apikey(self):
    url = "http://cs302.kiwi.land/api/load_new_apikey"

    username = cherrypy.session.get('username')
    password = cherrypy.session.get('password')

    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        # load encoding if possible (default to utf-8)
        encoding = response.info().get_content_charset('utf-8')
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))
    return JSON_object

@cherrypy.expose
def loginserver_pubkey(self):
    url = "http://cs302.kiwi.land/api/loginserver_pubkey"

    try:
        req = urllib.request.Request(url)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        # load encoding if possible (default to utf-8)
        encoding = response.info().get_content_charset('utf-8')
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))
    return JSON_object

@cherrypy.expose
def get_loginserver_record(self):
    url = "http://cs302.kiwi.land/api/get_loginserver_record"

    username = cherrypy.session.get('username')
    password = cherrypy.session.get('password')

    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        # print(data)
        cherrypy.session['login_record'] = data
        # load encoding if possible (default to utf-8)
        encoding = response.info().get_content_charset('utf-8')
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))

    return JSON_object

@cherrypy.expose
def check_pubkey(self):
    url = "http://cs302.kiwi.land/api/check_pubkey"

    username = cherrypy.session.get('username')
    password = cherrypy.session.get('password')

    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        # load encoding if possible (default to utf-8)
        encoding = response.info().get_content_charset('utf-8')
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))
    return JSON_object

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d




##############################
##########Class ApiApp#######
#############################



class ApiApp(object):

    @cherrypy.expose
    def ping(self):
        Page = startHTML
        JSON_object = ping(self)
        Page += json.dumps(JSON_object)
        return Page
    
    @cherrypy.expose
    def block(self, upi):
        Page = startHTML

        check = False
        #blocked_users = []
        #cherrypy.session['blocked_users'] = blocked_users
        #cherrypy.session.get('blocked_users').append(upi)
        #print(cherrypy.session.get('blocked_users'))
        
        with sqlite3.connect("database.db") as a:
            username = str(upi)
            try:
                a.execute("INSERT INTO blocked VALUES('%s')" % (username))
                #Page += username
                check = True
                #Page += " successfully added to the block list"
            except sqlite3.IntegrityError: 
                print("Error! Line 458")
                check = False
                pass
        
        Page += username
        if check:
            Page += " successfully added to the block list"
        else:
            Page += " is already blocked!"


        
        Page += "<br>&emsp; - To return, please click: <a href='/index'>Home</a> </br>"

        return Page
    
    @cherrypy.expose
    def unblock(self, upi):
        Page = startHTML
        #blocked_users = []
        #cherrypy.session['blocked_users'] = blocked_users
        #cherrypy.session.get('blocked_users').append(upi)
        #print(cherrypy.session.get('blocked_users'))
        
        with sqlite3.connect("database.db") as a:
            username = str(upi)
            try:
                a.execute("DELETE FROM blocked where username = '%s' " % (username))
                Page += username
                Page += " successfully removed from the block list"
            except:
                Page += "Woops, something went wrong"
                pass

        Page += "<br>&emsp; - To return, please click: <a href='/index'>Home</a> </br>"

        return Page

    @cherrypy.expose
    def print_blocked(self):

        Page = startHTML
        connection = sqlite3.connect("database.db")
        connection.row_factory = dict_factory
        
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM blocked")
        results = cursor.fetchall()

        for thing in results:
            #print(thing['username'])
            Page += thing['username']
            Page += "</br>"
        Page += "<br>&emsp; - To return, please click: <a href='/index'>Home</a> </br>"

        return Page
            
    
    @cherrypy.expose
    def block_words(self, word):
        Page = startHTML

        check = False

        with sqlite3.connect("database.db") as a:
            word = str(word)
            try:
                a.execute("INSERT INTO blocked_word VALUES('%s')" % (word))
                #Page += username
                check = True
                #Page += " successfully added to the block list"
            except sqlite3.IntegrityError: 
                print("Error! Line 458")
                check = False
                pass
        
        Page += word
        if check:
            Page += " successfully added to the block list"
        else:
            Page += " is already blocked!"


        
        Page += "<br>&emsp; - To return, please click: <a href='/index'>Home</a> </br>"

        return Page

    @cherrypy.expose
    def unblock_word(self, word):
        Page = startHTML
        with sqlite3.connect("database.db") as a:
            word = str(word)
            try:
                a.execute("DELETE FROM blocked_word where word = '%s' " % (word))
                Page += word
                Page += " successfully removed from the block list"
            except:
                Page += "Woops, something went wrong"
                pass

        Page += "<br>&emsp; - To return, please click: <a href='/index'>Home</a> </br>"

        return Page

    @cherrypy.expose
    def print_blocked_word(self):

        Page = startHTML
        connection = sqlite3.connect("database.db")
        connection.row_factory = dict_factory
        
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM blocked_word")
        results = cursor.fetchall()

        for thing in results:
            #print(thing['username'])
            Page += thing['word']
            Page += "</br>"
        Page += "<br>&emsp; - To return, please click: <a href='/index'>Home</a> </br>"

        return Page
        

    @cherrypy.expose
    def list_apis(self):
        Page = startHTML
        JSON_object = list_apis(self)
        Page += json.dumps(JSON_object)
        return Page

    @cherrypy.expose
    def list_users(self, username=None , password= None):
        Page = startHTML
        Page += "<br>&emsp; - To return, please click: <a href='/index'>Home</a> </br>"
        Page += "</br>"

        JSON_object = list_users(self,username, password)
        #print(JSON_object)

        rough = JSON_object['users']


        for data in rough:
            Page += json.dumps(data['username']) 
            Page += "  at IP address: "
            Page += json.dumps(data['connection_address'])
            Page += "</br>"
        #Page += json.dumps(JSON_object)
        return Page

    @cherrypy.expose
    def update_users(self):
        Page = startHTML
        username = cherrypy.session['username']
        password = cherrypy.session['password']
        JSON_object = list_users(self,username, password)
        #print(JSON_object)

        rough = JSON_object['users']
        check = False

        for data in rough:
            name =  data['username']

            with sqlite3.connect("database.db") as a:

                try:
                    a.execute("INSERT INTO users VALUES ('%s')"% (name))
                    check = True
                    #print("added")

                except sqlite3.IntegrityError: 
                    #print("Error!")
                    pass
        if check:
            Page += "Users database successfully updated! </br>"
        else:
            Page += "No new users were added"
        Page += "<br>&emsp; - To return, please click: <a href='/index'>Home</a> </br>"

        return Page

        
    
    @cherrypy.expose
    def add_pubkey(self):
        Page = startHTML
        JSON_object = add_pubkey(self)
        Page += json.dumps(JSON_object)
        Page += "<br> </br>"
        Page += "<br>&emsp; - To return, please click: <a href='/index'>Home</a>."
        return Page
    

    @cherrypy.expose
    def report(self):
        
        Page = startHTML

        if cherrypy.session.get('check'):
            JSON_object = report(self)
            Page += json.dumps(JSON_object)
            Page += "<br>&emsp; - To return, please click: <a href='/index'>Home</a>."
        else:
            Page += "Error encountered! Please register your public key first."
            Page += "<br>&emsp; - To add your public key to the login server, please click: <a href='/api/add_pubkey'>Add Public key</a>."
        return Page


    @cherrypy.expose
    def load_new_apikey(self):
        Page = startHTML
        JSON_object = load_new_apikey(self)
        Page += json.dumps(JSON_object)
        return Page


    @cherrypy.expose
    def loginserver_pubkey(self):
        Page = startHTML
        JSON_object = loginserver_pubkey(self)
        Page += json.dumps(JSON_object)
        return Page
	

    
    @cherrypy.expose
    def get_loginserver_record(self):
        Page = startHTML
        JSON_object = get_loginserver_record(self)
        Page += json.dumps(JSON_object)
        return Page


    @cherrypy.expose 
    def check_pubkey(self):
        Page = startHTML

        JSON_object = check_pubkey(self)
    
        Page += json.dumps(JSON_object)
        return Page






    @cherrypy.expose
    def tx_broadcast(self, message):
        username = cherrypy.session['username']
        password = cherrypy.session['password']
        priv_key = cherrypy.session.get('priv_key')
        
        clock_started = str(time.time())
        record_JSON = get_loginserver_record(self)
        JSON_object = list_users(self, username, password)
        rough = JSON_object['users']
        IP = "demo"

        Page = startHTML

        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type': 'application/json; charset=utf-8',
            }
        record = record_JSON['loginserver_record']
        msg = message

        signature_bytes =  bytes(record + msg + clock_started, encoding='utf-8')
        signature_hex = priv_key.sign(signature_bytes, encoder= nacl.encoding.HexEncoder)
        signature = signature_hex.signature.decode('utf-8') # readable version NOT UNDERSTANDABLE
        payload = {
            "loginserver_record": record,
            "message": msg,
            "sender_created_at": clock_started,
            "signature": signature
            }
        data_string = json.dumps(payload)
        data_send = data_string.encode()

        for data in rough:
            IP = data['connection_address']
            #print(IP)
            url = "http://" + IP + "/api/rx_broadcast"
            Page += url
            Page += "</br>"
            #print("before the try statement")
            
            try:
                #with eventlet.Timeout(10):
                    req = urllib.request.Request(url, headers=headers, data=data_send)
                    response = urllib.request.urlopen(req)
                    data = response.read()  # read the received bytes
                    # load encoding if possible (default to utf-8)
                    encoding = response.info().get_content_charset('utf-8')
                    response.close()
            except urllib.error.HTTPError as error:
                print("Hey! Im in the error part now")
                print(error.read())
                exit()
            print(IP)
        
        return Page







    @cherrypy.expose    
    def tx_privatemessage(self, message, upi):
        
        username = cherrypy.session['username']
        password = cherrypy.session['password']
        
        JSON_object = list_users(self, username, password)
        rough = JSON_object['users']

        IP = "ds"
        #pubkey = " "
        for data in rough:
            if (upi == data['username']):
                pubkey = data['incoming_pubkey']
                cherrypy.session['pubkey'] = pubkey
                IP = data['connection_address']

                print(IP)
                print("found the user")
                check = True
                break
            else:
                check = False
        

        url = "http://" + str(IP) + "/api/rx_privatemessage"
        Page = startHTML

        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type': 'application/json; charset=utf-8',
        }

        record_JSON = get_loginserver_record(self)
        record = record_JSON['loginserver_record']
        #msg = "sup dawg"
        
        msg = message

        msg_bytes = bytes(msg, encoding='utf-8')


        clock_started = str(time.time())
        
        public_key = cherrypy.session.get('public_key')

        

        
        
        if check == False:
            Page += "ERROR!! User is not online. Please try later. </br>"
            Page += "Please return to home page, "
            Page += "<a href='/index'>Home</a>. </br>"

            return Page

        #pubkey = "2ae0385c711e11f784bd3cad956e6640ad9059d8d96a0127e07102aeb0475911"

        target_usrname = upi

        priv_key = cherrypy.session.get('priv_key')
        
        public_key_hex = priv_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
        cherrypy.session['publickey_hex'] = public_key_hex
        #print(pubkey)
        verifykey = nacl.signing.VerifyKey(pubkey, encoder=nacl.encoding.HexEncoder)
        public_key = verifykey.to_curve25519_public_key()
        sealed_box = nacl.public.SealedBox(public_key)
        encrypted = sealed_box.encrypt(msg_bytes, encoder=nacl.encoding.HexEncoder)
        encrypt_msg = encrypted.decode('utf-8')

        signature_bytes =  bytes(record + pubkey + target_usrname + encrypt_msg + clock_started, encoding='utf-8')

        
        signature_hex = priv_key.sign(signature_bytes, encoder= nacl.encoding.HexEncoder)
        signature = signature_hex.signature.decode('utf-8') # readable version NOT UNDERSTANDABLE


        payload = {

            "loginserver_record": record,
            "target_pubkey": pubkey,
            "target_username": target_usrname,
            "encrypted_message": encrypt_msg,
            "sender_created_at": clock_started,
            "signature": signature
        }

        data_string = json.dumps(payload)

        data_send = data_string.encode()

        try:
            req = urllib.request.Request(url, headers=headers, data=data_send)
            response = urllib.request.urlopen(req)
            data = response.read()  # read the received bytes
            # load encoding if possible (default to utf-8)
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()
        JSON_object = json.loads(data.decode(encoding))

        Page += json.dumps(JSON_object)
        Page += "<br>&emsp; - To return, please click: <a href='/index'>Home</a>."
        return Page





################################
######### class ################
################################

@cherrypy.expose
class rx_broadcast(object):

    @cherrypy.tools.accept(media='text/plain')
    def GET(self):

        Page = startHTML
        blocked = False
        Page += "<br>&emsp; - To return, please click: <a href='/index'>Home</a>. </br>"
        Page += "</br>"

        connection = sqlite3.connect("database.db")
        connection.row_factory = dict_factory
        
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM broadcast")
        results = cursor.fetchall()
        results.reverse()

        cursor1 = connection.cursor()
        cursor1.execute("SELECT * FROM blocked")
        results1 = cursor1.fetchall()
        
        cursor2 = connection.cursor()
        cursor2.execute("SELECT * FROM blocked_word")
        results2 = cursor2.fetchall()

        #print(results)
        for thing in results:
            


            user = thing['loginserver_record']
            #user = str(user)
            name = user[0:7]
            msgg = str(thing['message'])
            #print(name)

            #print(results1)
            for thing1 in results1:
                #print(thing1)
                blocked_username = thing1['username']
                #print(blocked_username)

                #print ( blocked_username + " " + name)
                if name == blocked_username:
                    blocked = True
                    break
                else:
                    blocked = False

            for thing2 in results2:
                #print(thing2)
                blocked_word = thing2['word']
                #print(blocked_username)

                #print ( blocked_username + " " + name)
                if blocked_word in msgg:
                    blocked = True
                    break
                else:
                    blocked = False
            
            #print(blocked_username + " " + name)
            if blocked == False:

                Page += name
                Page += " says </br>"
                Page += thing['message']
                Page += "<br> </br>"
            else:
                pass
                    
        
        return Page

    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def POST(self):
        incoming_json = cherrypy.request.json

        with sqlite3.connect("database.db") as a:
            loginserver_rec = incoming_json['loginserver_record']
            message = incoming_json['message']
            sender_created_at = incoming_json['sender_created_at']
            signature = incoming_json['signature']

            try:
                a.execute("INSERT INTO broadcast VALUES (?, ?,?, ?)", (loginserver_rec,message, sender_created_at, signature))
                outcome = {'response': 'yeet'}

            except:
                print("Error!")
                outcome = {'response': 'woops'}
        
        return outcome



##################################
##################################
############ private #############
##################################
##################################


@cherrypy.expose
class rx_privatemessage(object):

    _cp_config = {'tools.encode.on': True,
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on': 'True',
                  # increase security on sessions
                  # 'tools.sessions.secure' : 'True',
                  'tools.sessions.httponly': 'True'
                  }

    @cherrypy.tools.accept(media='text/plain')
    def GET(self):

        Page = startHTML
        blocked = False

        Page += "<br>&emsp; - To return, please click: <a href='/index'>Home</a>. </br>"
        Page += "</br>"

        connection = sqlite3.connect("database.db")
        connection.row_factory = dict_factory
        
        

        cursor = connection.cursor()
        cursor.execute("SELECT * FROM private")
        results = cursor.fetchall()
        results.reverse()

        cursor1 = connection.cursor()
        cursor1.execute("SELECT * FROM blocked")
        results1 = cursor1.fetchall()


        #print(results)
        for thing in results:
            


            user = thing['loginserver_record']
            #user = str(user)
            name = user[0:7]
            #print(name)

            #print(results1)
            for thing1 in results1:
                print(thing1)
                blocked_username = thing1['username']
                #print(blocked_username)

                #print ( blocked_username + " " + name)
                if name == blocked_username:
                    blocked = True
                    break
                else:
                    blocked = False
            
            #print(blocked_username + " " + name)
            if blocked == False:
                #print('inside now')
                Page += name
                Page += " says </br>"

                Page += thing['encrypted_message']
                Page += "<br> </br>"
                
            else:
                pass
                    
        return Page


    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def POST(self):
        incoming_json = cherrypy.request.json

        with sqlite3.connect("database.db") as a:
            loginserver_rec = incoming_json['loginserver_record']
            target_pkey = incoming_json['target_pubkey']
            target_uname = incoming_json['target_username']
            message = incoming_json['encrypted_message']
            sender_created_at = incoming_json['sender_created_at']
            signature = incoming_json['signature']

            try:
                a.execute("INSERT INTO private VALUES (?, ?,?, ?, ?, ?)", (loginserver_rec,target_pkey, target_uname, message, sender_created_at, signature))
                outcome = {'response': 'yeet'}

            except:
                print("Error!")
                outcome = {'response': 'woops'}
        
        return outcome

####################################
####################################


###
# Functions only after here
###

def authoriseUserLogin(username, password):
    print("Log on attempt from {0}:{1}".format(username, password))



    if (username.lower() == "auma020") and (password.lower() == "ahmadumar020_381561486"):
        print("Success")
        return 0
    else:
        print("Failure")
        return 1
