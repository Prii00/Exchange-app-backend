# -*- coding: utf-8 -*-
"""
Created on Wed Aug 25 12:46:30 2021
https://roytuts.com/python-flask-rest-api-file-upload/
@author: PC
"""


from cryptography.fernet import Fernet
import mysql.connector
import os
import urllib.request
from app import app
from flask import Flask, request, redirect, jsonify, Blueprint, render_template
from werkzeug.utils import secure_filename
import os
import boto3
import botocore
from botocore.exceptions import ClientError
import glob
from collections import defaultdict
import random
import string
from botocore.errorfactory import ClientError
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import mysql.connector
import pymysql, json
from cryptography.fernet import Fernet
import re

from flask import Flask, request
access_key = 'AKIASUKCZ7OPDJ2PV3OC'
access_secret = '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'
bucket_name = 'clientphoto'


client_s3 = boto3.client(                   #Connecting to s3 Service
    's3',
    aws_access_key_id = access_key,
    aws_secret_access_key = access_secret,

)

app = Flask(__name__)

ALLOWED_EXTENSIONS = set(['application/pdf', 'image/jpeg'])

def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#key = Fernet.generate_key()

#with open("pass.key", "wb") as key_file:
#    key_file.write(key)

def call_key():
    return open("pass.key", "rb").read()

fernet = Fernet(call_key())


data_file_folder = os.getcwd()
def uploading(filename):
    try:
        client_s3.upload_file(
                #folder,
                os.path.join(data_file_folder, filename),   #file is the name of file to be uploaded
                bucket_name,
                filename    #unique_id is set as the file name itself
                #filename
            )
        return filename
    except ClientError as e:
        print('Credential is incorrect')
        print(e)
    except Exception as e:
        print(e)

@app.route('/file-upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        resp = jsonify({'message' : 'No file part in the request', 'success' : False})
        resp.status_code = 400
        return resp
    file = request.files['file']
    if file.filename == '':
        resp = jsonify({'message' : 'No file selected for uploading', 'success' : False})
        resp.status_code = 400
        return resp
    if 'file' in request.files:
        filename = secure_filename(file.filename)
        imagefile = request.files.get('file', '')
        var = str(imagefile)
        y = re.findall(r"'(.*?)'", var, re.DOTALL)
        x = y[0]
        random_string = ''.join(((random.choice(string.ascii_letters) for x in range(10))))
        random_string += x
        location =  random_string
        imagefile.save(location)
        object_name = uploading(random_string)
        url = "https://%s.s3.amazonaws.com/%s" % (bucket_name, object_name)
        resp = jsonify({'message' : 'File successfully uploaded', 'object_URL': url, 'success' : True})
        resp.status_code = 200
        os.remove(location)
        return resp
    else:
        resp = jsonify({'message' : 'Allowed file types are txt, pdf, png, jpg, jpeg, gif', 'success' : False})
        resp.status_code = 400
        return resp

@app.route('/health-check-api', methods=['GET'])
def health():
    resp = jsonify({'message' : 'Server is running', 'Success' : True})
    return resp



def delete_objects(name):
    try:
        if client_s3.head_object(Bucket=bucket_name, Key=name):
            client_s3.delete_object(Bucket=bucket_name, Key=name)
            return jsonify({'message' : 'File successfully deleted', 'Success' : True})
    except ClientError:
        return jsonify({'message' : 'File does not exist', 'Success' : False})

@app.route("/delete-s3-object/<string:name>", methods=['DELETE'])
def delete_file(name):
    resp = delete_objects(name)
    return resp



def insert_todb(First_Name, Last_Name, Email_ID, Contactnum, Username, Password, Role, Identity_Proof, Document_Name):
        mydbr = mysql.connector.connect(host="database-2.cxsfn2vhpjkw.us-east-1.rds.amazonaws.com",
                                        user="admin2",
                                        passwd="admin#12345",
                                        database = "mydb"
                                        )
        mycursor = mydbr.cursor()
        mycursor.execute("USE mydb")
        fname = First_Name
        lname = Last_Name
        email = Email_ID
        contact = Contactnum
        uname = Username
        password = Password
        role = Role
        proof = Identity_Proof
        docname = Document_Name
        mycursor.execute("INSERT INTO registration(firstname, lastname, emailID,contactnum,username,password,role,proof,documentname) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) ",(fname, lname, email, contact, uname, password, role, proof, docname))
        mydbr.commit()

@app.route("/registration", methods=['POST'])
def registration():
    data = request.get_json()
    pairs = data.items()
    x = {}
    for key, value in pairs:
        x[key] = value
    for key in x:
        if key == 'Password':
            message = x[key]
            ans = fernet.encrypt(message.encode())
            x[key] = ans
            #print(x[key])
    resp = jsonify({'Message' : "User has successfully registered", "Success" : True})
    insert_todb(**x)
    return resp

def login_check(emailid, pswd):
    mydbr = mysql.connector.connect(host="database-2.cxsfn2vhpjkw.us-east-1.rds.amazonaws.com",
                                        user="admin2",
                                        passwd="admin#12345",
                                        database = "mydb"
                                        )
    mycursor = mydbr.cursor()
    mycursor.execute("USE mydb")
    mycursor.execute("SELECT emailID FROM registration where emailID= %s" ,(emailid,))
    data = mycursor.fetchall()
    if data:
        mycursor.execute("SELECT Password FROM registration where emailID = %s", (emailid, ))
        result = mycursor.fetchall()
        val = 0
        for i in result:
            val = i[0]
        results = bytes(val, encoding='utf8')
        ans = fernet.decrypt(results).decode()
        if ans == pswd:
            return True
        else:
            return False
    else:
        return False

def return_user_value(mailid, pswd):
    mydbr = mysql.connector.connect(host="database-2.cxsfn2vhpjkw.us-east-1.rds.amazonaws.com",
                                        user="admin2",
                                        passwd="admin#12345",
                                        database = "mydb"
                                        )
    mycursor = mydbr.cursor()
    mycursor.execute("USE mydb")
    mycursor.execute("SELECT * FROM registration where emailID= %s" ,(mailid,))
    data = mycursor.fetchall()
    pssd = pswd
    for row in data:
        print(type(row))
        f_name = row[0]
        l_name = row[1]
        mail = row[2]
        num = row[3]
        u_name = row[4]
        #pssd = row[5]
        role = row[6]
        proof = row[7]
        doc = row[8]
        resp = jsonify({'message' : 'Login successful','Success' : True, 'First_name' : f_name, 'Last_name' : l_name, 'Email_Id' : mail, 'Contact' : num, 'Username' : u_name,  'Role' : role, 'Identity_Proof' : proof, 'Document' : doc })
        return resp


@app.route("/login", methods=['GET'])
def login():
    data = request.get_json()
    pairs = data.items()
    x = {}
    for key, value in pairs:
        x[key] = value
    for key in x:
        if key == 'Password':
            pswd = x[key]
        elif key == 'Email_ID':
            mailid = x[key]
    value = login_check(mailid, pswd)
    if value == False:
        resp = jsonify({'message' : 'The user has not registered' , 'Success' : False})
        return resp
    else:
        value = return_user_value(mailid, pswd)
        #resp = ({'message' : 'The login is successful' , 'Success' : True})
        return value





def username_checking(name):
    mydbr = mysql.connector.connect(host="database-2.cxsfn2vhpjkw.us-east-1.rds.amazonaws.com",
                                        user="admin2",
                                        passwd="admin#12345",
                                        database = "mydb"
                                        )
    mycursor = mydbr.cursor()
    mycursor.execute("USE mydb")
    mycursor.execute("SELECT username FROM registration where username= %s" ,(name,))
    data = mycursor.fetchall()
    if not data:
        return True
    else:
        return False

@app.route("/username-check/<string:uname>", methods=['GET'])
def username_check(uname):
    uss = uname
    value = username_checking(uss)
    if value is True:
        resp = jsonify({ 'message' : 'Username doesnt exist' , 'Success' : False})
        return resp
    else:
        resp = jsonify({ 'message' : 'Username already exist' , 'Success' : True})
        return resp


def contact_checking(number):
    mydbr = mysql.connector.connect(host="database-2.cxsfn2vhpjkw.us-east-1.rds.amazonaws.com",
                                        user="admin2",
                                        passwd="admin#12345",
                                        database = "mydb"
                                        )
    mycursor = mydbr.cursor()
    mycursor.execute("USE mydb")
    mycursor.execute("SELECT contactnum FROM registration where contactnum= %s" ,(number,))
    data = mycursor.fetchall()
    if not data:
        return True
    else:
        return False

@app.route("/contact-check/<string:contact>", methods=['GET'])
def contact_check(contact):
    num = contact
    value = contact_checking(num)
    if value is True:
        resp = jsonify({ 'message' : 'Contact doesnt exist' , 'Success' : False})
        return resp
    else:
        resp = jsonify({ 'message' : 'Contact already exist' , 'Success' : True})
        return resp

def email_checking(eid):
    mydbr = mysql.connector.connect(host="database-2.cxsfn2vhpjkw.us-east-1.rds.amazonaws.com",
                                        user="admin2",
                                        passwd="admin#12345",
                                        database = "mydb"
                                        )
    mycursor = mydbr.cursor()
    mycursor.execute("USE mydb")
    mycursor.execute("SELECT emailID FROM registration where emailID= %s" ,(eid,))
    data = mycursor.fetchall()
    if not data:
        return True
    else:
        return False

@app.route("/emailid-check/<string:email>", methods=['GET'])
def email_check(email):
    eid = email
    value = email_checking(eid)
    if value is True:
        resp = jsonify({ 'message' : 'Email doesnt exist' , 'Success' : False})
        return resp
    else:
        resp = jsonify({'message' : 'Email already exist' , 'Success' : True})
        return resp

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
        