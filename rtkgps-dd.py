# -*- coding: utf-8 -*-
import socket
import os
from _thread import *
import time
import pynmea2
from OpenSSL import crypto, SSL
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

https_host = ""
https_port = 4443

basestation_connection_host = '10.11.12.148'
basestation_connection_port = 1234
rover_connection_host = '10.11.12.148'
rover_connection_port = 1235

TCP_whitelist = []

data_from_basestation = ""
data_from_rover = ""

basestation_data_lock = allocate_lock()
rover_data_lock = allocate_lock()
whitelist_lock = allocate_lock()

latest_rover_data = {}
'''
Generates self-signed certificates for HTTPS server.
copied from https://stackoverflow.com/questions/27164354/create-a-self-signed-x509-certificate-in-python
'''
def cert_gen(
    emailAddress="emailAddress",
    commonName="commonName",
    countryName="NT",
    localityName="localityName",
    stateOrProvinceName="stateOrProvinceName",
    organizationName="organizationName",
    organizationUnitName="organizationUnitName",
    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=10*365*24*60*60,
    KEY_FILE = "private.key",
    CERT_FILE="selfsigned.crt"):
    #can look at generated file using openssl:
    #openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
        
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        if self.path == "/add_to_whitelist":
            if self.client_address[0] not in TCP_whitelist:
                with whitelist_lock: 
                    TCP_whitelist.append(self.client_address[0])
                    print("Added "+str(self.client_address[0])+" to TCP whitelist") 
            self.wfile.write(b'OK')
            
    def log_message(self, format, *args):   #silence HTTP server logging
        return

                
def start_HTTPS_server():
    httpd = HTTPServer((https_host, https_port), SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket (httpd.socket, 
            keyfile="./private.key", 
            certfile='./selfsigned.crt', server_side=True)
    start_new_thread(httpd.serve_forever(),())
    
try:
    cert_gen()
    print("generated self-signed certificates for HTTPS server")
except:
    print("unable to create self-signed certificate for HTTPS server")
    exit()

print("Starting HTTPS server on "+https_host+":"+str(https_port)+"...",end="")
start_new_thread(start_HTTPS_server,())
print("Started")

print("Opening basestation port...",end="")
basestation_socket = socket.socket()
basestation_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)    #Enable keep-alive
basestation_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 5)   #Consider Socket idle after 5sec
basestation_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3)  #Keep-alive packet interval
basestation_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 10)   #Die after 10 retries (30secs)
basestation_socket.settimeout(1)
try:
    basestation_socket.bind((basestation_connection_host, basestation_connection_port))
except socket.error as e:
    print("Unable to open basestation port")
    print(str(e))
    exit();
print("Opened")

print("Opening rover port...",end="")
rover_socket = socket.socket()
rover_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)    #Enable keep-alive
rover_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 5)   #Consider Socket idle after 5sec
rover_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3)  #Keep-alive packet interval
rover_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 10)   #Die after 10 retries (30secs)
rover_socket.settimeout(1)
try:
    rover_socket.bind((rover_connection_host, rover_connection_port))
except socket.error as e:
    print("Unable to open rover port")
    print(str(e))
    exit();
print("Opened")

basestation_socket.listen(1)    #only allow single basestation connection
rover_socket.listen(1)    #only allow single rover connection

print('Waiting for basestation and rover connections...')

def basestation_client(connection, address):
    with whitelist_lock:
        if address[0] not in TCP_whitelist:
            print(str(address[0])+" not allowed to connect to basestation (IP not in whitelist)")
            connection.close()
            return
    global data_from_basestation
    buffer = ""
    while True:
        data_from_socket = connection.recv(4096)
        buffer += data_from_socket.decode('utf8', 'replace')
        if buffer.rfind("\n") > 0:  #check if recieved data has new line symbol
            with basestation_data_lock:
                data_from_basestation += buffer[:buffer.rfind("\n")]    #Only add full lines
            buffer = buffer[buffer.rfind("\n"):]
        time.sleep(0.005) #sleep 5ms
    connection.close()
    
def rover_client(connection,address):
    with whitelist_lock:
        if address[0] not in TCP_whitelist:
            print(str(address[0])+" not allowed to connect to basestation (IP not in whitelist)")
            connection.close()
            return
    global data_from_rover
    buffer = ""
    while True:
        data_from_socket = connection.recv(4096)
        buffer += data_from_socket.decode('utf8', 'replace')
        if buffer.rfind("\n") > 0:  #check if recieved data has new line symbol
            with rover_data_lock:
                data_from_rover += buffer[:buffer.rfind("\n")]  #Only add full lines
            buffer = buffer[buffer.rfind("\n"):]
        time.sleep(0.005) #sleep 5ms
    connection.close()
    
def dump_rover_data():
    global data_from_rover
    while 1:
        with rover_data_lock:
            lines = data_from_rover.split("\n")
            for line in lines:
                if line != "":
                    try:
                        msg = pynmea2.parse(line)
                        timestamp = msg.timestamp
                        latitude = msg.lat
                        latitude_direction = msg.lat_dir
                        longitude = msg.lon
                        longtitude_direction = msg.lon_dir
                        number_of_satellites = msg.num_sats
                        horizontal_dilusion = msg.horizontal_dil
                        altitude = msg.altitude
                        quality = msg.gps_qual
                        print(type(timestamp))
                        print(str(timestamp)+" "+str(latitude)+" "+str(longitude))
                        if latest_rover_data["timestamp"] < timestamp:
                            latest_rover_data = {   "timestamp" => timestamp, 
                                                    "latitude"=>latitude, 
                                                    "latitude_direction" => latitude_direction,
                                                    "longitude" => longitude, 
                                                    "longtitude_direction" => longtitude_direction,
                                                    "number_of_satellites" => number_of_satellites,
                                                    "horizontal_dilusion" => horizontal_dilusion, 
                                                    "altitude" => altitude, 
                                                    "quality" => quality}
                    except:
                        pass
            data_from_rover = ""
            
start_new_thread(dump_rover_data,())
while True:
    try:
        Client, address = basestation_socket.accept()
        print('Basestation connected to: ' + address[0] + ':' + str(address[1]))
        start_new_thread(basestation_client, (Client, address))
    except:
        pass
    try:
        Client, address = rover_socket.accept()
        print('Rover connected to: ' + address[0] + ':' + str(address[1]))
        start_new_thread(rover_client, (Client, address))
    except:
        pass
    
basestation_socket.close()
rover_socket.close()
