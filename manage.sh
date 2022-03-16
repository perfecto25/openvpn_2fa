#!/bin/bash

PW=$(pwgen 15 1)
ACTION=$1
CLIENT=$2
HOST=$(hostname)
CLIENTDIR="/opt/openvpn/clients"

if [ $# -lt 1 ] 
then 
    echo -e "usage:\n./manage.sh create/revoke <username>\n./manage.sh status"
    exit 1
fi


function newClient() {
    
    CLIENT=$1
	CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=$CLIENT\$")
	if [[ $CLIENTEXISTS == '1' ]]; then
		echo ""
		echo "The specified client CN was already found in easy-rsa, please choose another name."
		exit
	else
		cd /etc/openvpn/easy-rsa/ || return
		echo "${PW}"; echo "${PW}" | ./easyrsa build-client-full "${CLIENT}"
		#./easyrsa build-client-full "$CLIENT"
		echo "Client $CLIENT added."
	fi


	# create system account for new VPN user, add password to it (if account exists, leave it and just create clientdir)
	user_exists=$(grep -c "^${CLIENT}:" /etc/passwd)
	if [ $user_exists -eq 0 ]
	then
    	useradd -m -d "${CLIENTDIR}/${CLIENT}" -s /bin/nologin "${CLIENT}" || { echo "error creating system account for $CLIENT"; exit 1; }
    else
        mkdir "${CLIENTDIR}/${CLIENT}"
    fi

    # update system user pw, remove pw expiration
    echo "${CLIENT}:${PW}" | chpasswd
    chage -m 0 -M 99999 -I -1 -E -1 "${CLIENT}"

    # Generates the custom client.ovpn
    cp /etc/openvpn/client-template.txt "${CLIENTDIR}/${CLIENT}/${CLIENT}.ovpn"
    {
        echo "<ca>"
        cat "/etc/openvpn/easy-rsa/pki/ca.crt"
        echo "</ca>"
        echo "<cert>"
        awk '/BEGIN/,/END/' "/etc/openvpn/easy-rsa/pki/issued/${CLIENT}.crt"
        echo "</cert>"
        echo "<key>"
        cat "/etc/openvpn/easy-rsa/pki/private/${CLIENT}.key"
        echo "</key>"
        echo "<tls-crypt>"
        cat /etc/openvpn/tls-crypt.key
        echo "</tls-crypt>"
    } >>"${CLIENTDIR}/${CLIENT}/${CLIENT}.ovpn"

    echo ""
    echo "The configuration file has been written to ${CLIENTDIR}/${CLIENT}/${CLIENT}.ovpn."

}

if [ ! "${ACTION}" == "create" ] && [ ! "${ACTION}" == "revoke" ] && [ ! "${ACTION}" == "status" ]
then
    echo -e "usage:\n./manage.sh create/revoke <username>\n./manage.sh status"
    exit 1
fi

cd /opt/openvpn || exit 1

if [ "${ACTION}" == "create" ]
then
    [ -z $CLIENT ] && { echo "provide a username to create"; exit 1; }

    newClient "${CLIENT}" || { echo "error generating user VPN profile"; exit 1; }

    ### setup Google Authenticator
    google-authenticator -t -d -f -r 3 -R 30 -W -C -s "/opt/openvpn/google-auth/${CLIENT}" || { echo "error generating QR code"; exit 1; }
    secret=$(head -n 1 "/opt/openvpn/google-auth/${CLIENT}")
    qrencode -t PNG -o "/opt/openvpn/google-auth/$CLIENT.png" "otpauth://totp/${CLIENT}@${HOST}?secret=${secret}&issuer=openvpn" || { echo "error generating PNG"; exit 1; }
        
    ### Email the profile to the user
    hostlist=$(cat /etc/hosts | grep -v "#" | grep -v "localhost" | grep -v "127.0.0.1" | grep -v -e "^$")
        
    content="""
##########    OpenVPN connection profile (${HOST})  ###################

use the attached VPN profile to connect using Tunnelblick or OpenVPN Connect.

VPN usename: ${CLIENT}
VPN password:  ${PW}

user attached QR code to register your 2 Factor Authentication with Authy.

All hostname IPs are provided by DNS resolvers.

If DNS is not working, you can use the /etc/hosts list below to connect to hosts:

----------------------------------------
${hostlist}
    """
    echo "${content}" | mailx -s "Your OpenVPN profile" -a "${CLIENTDIR}/${CLIENT}/${CLIENT}.ovpn" -a "/opt/openvpn/google-auth/${CLIENT}.png" -r "Devops<devops@company.com>" ${CLIENT}@company.com || { echo "error mailing profile to client"; exit 1; }
fi


if [ ${ACTION} == "revoke" ]
then

    [ -z $CLIENT ] &&  { echo "provide a username to revoke"; exit 1; }

    cd /etc/openvpn/easy-rsa/ || exit 1

    ./easyrsa --batch revoke $ACTION
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
    rm -f pki/reqs/$CLIENT.req*
    rm -f pki/private/$CLIENT.key*
    rm -f pki/issued/$CLIENT.crt*
    rm -f /etc/openvpn/crl.pem
    cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
    chmod 644 /etc/openvpn/crl.pem
    rm -rf "${CLIENTDIR:?}/${CLIENT}"

    # remove client from PKI index
    echo "$(grep -v "CN=${CLIENT}$" pki/index.txt)" >pki/index.txt

    # remove system acct that was created by OpenVPN manage.sh script
    user_exists=$(grep $CLIENT /etc/passwd | grep openvpn | grep nologin | grep -v "^openvpn:" | wc -l)
    if [ $user_exists -eq 1 ]
    then
        userdel -r -f ${CLIENT}
    fi

    echo "VPN access for $CLIENT is revoked"
fi


if [ "${ACTION}" == "status" ]
then
    cat /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | grep -v "server_"
fi