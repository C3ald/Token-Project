#!/bin/bash

pip install -r requirements.txt

openssl req -new -x509 -key privkey.pem -out cert.pem -days 1095

