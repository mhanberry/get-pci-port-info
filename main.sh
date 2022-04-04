#!/bin/bash

set -e

if [[ $# != 1 ]]; then
	echo "usage: `basename $0` profile"
	exit
fi

PROFILE="$1"

login(){
	aws --profile $PROFILE sso login
}

get_security_groups(){
	aws --profile $PROFILE ec2 describe-security-groups --output json > security-groups.json
}

get_network_interfaces(){
	aws --profile $PROFILE ec2 describe-network-interfaces --output json > network-interfaces.json
}

# Main

#login
#get_security_groups
#get_network_interfaces
node build-csv.js
