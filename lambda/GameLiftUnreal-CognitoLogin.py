# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
import os
import sys

import hmac
import hashlib
import base64

# TODO Set to your created app client id and secret. For testing purposes, it is possible to use hardcoded strings here, but please consider using environment variables.
# i.e. USER_POOL_APP_CLIENT_ID = os.environ['USER_POOL_APP_CLIENT_ID'] and USER_POOL_APP_CLIENT_SECRET = os.environ['USER_POOL_APP_CLIENT_SECRET']
# (See https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html for info on programmatically defining environment variables in Lambda.)
USER_POOL_APP_CLIENT_ID = ''

client = boto3.client('cognito-idp')

def get_secret_hash(username, client_id, client_secret):
    message = username + client_id
    dig = hmac.new(
        str(client_secret).encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

def lambda_handler(event, context):
    if 'username' not in event or 'password' not in event:
        return {
            'status': 'fail',
            'msg': 'Username and password are required'
        }
    resp, msg = initiate_auth(event['username'], event['password'])
    if msg != None:
        return {
            'status': 'fail', 
            'msg': msg
        }
    return {
        'status': 'success',
        'tokens': resp['AuthenticationResult']
    }

def initiate_auth(username, password):
    try:
        resp = client.initiate_auth(
            ClientId=USER_POOL_APP_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            })
    except client.exceptions.InvalidParameterException as e:
        return None, "Username and password must not be empty"
    except (client.exceptions.NotAuthorizedException, client.exceptions.UserNotFoundException) as e:
        return None, "Username or password is incorrect"
    except Exception as e:
        print("Uncaught exception:", e, file=sys.stderr)
        return None, "Unknown error"
    return resp, None