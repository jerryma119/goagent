#!/bin/bash

echo "Adding CA.crt to system keychain, You may need to input your password..."
sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" `dirname $0`/CA.crt
ret=$?

if [ $ret = 0 ]; then
    echo "Done!"
else
    echo "Failed!"
fi
