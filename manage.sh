#!/bin/bash

ACTION=$1
CLIENT=$2
HOST=$(hostname)
CLIENTDIR="/opt/openvpn/clients"

R="\e[0;91m"
G="\e[0;92m"
W="\e[0;97m"
B="\e[1m"
C="\e[0m"

if [ $# -lt 1 ] 
then 
    echo -e "${W}usage:\n./manage.sh create/revoke <username>\n./manage.sh status\n./manage.sh send <username>${C}"
    exit 1
fi


function emailProfile() {

    CLIENT=$1
    PASSWORD=$2

    ### Email the profile to the user
    hostlist=$(cat /etc/hosts | grep -v "#" | grep -v "localhost" | grep -v "127.0.0.1" | grep -v -e "^$")
        
    content="""
##########    OpenVPN connection profile (${HOST})  ###################

use the attached VPN profile to connect using Tunnelblick or OpenVPN Connect.


VPN usename: ${CLIENT}
VPN password:  ${PASSWORD}

user attached QR code to register your 2 Factor Authentication with Authy.

If DNS is not working, you can use the /etc/hosts list below to connect to hosts:
----------------------------------------
${hostlist}

    """
    echo "${content}" | mailx -s "Your OpenVPN profile" -a "${CLIENTDIR}/${CLIENT}/${CLIENT}.ovpn" -a "/opt/openvpn/google-auth/${CLIENT}.png" -r "Devops<devops@company.com>" "${CLIENT}@company.com" || { echo "${R}${B}error mailing profile to client: ${CLIENT}${C}"; exit 1; }
}


function newClient() {
    CLIENT=${1:?}
	CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=${CLIENT}\$")
	if [[ $CLIENTEXISTS == '1' ]]; then
		echo -e "${W}The specified client CN was already found in easy-rsa, please choose another name.${C}"
		exit
	else
        echo -e "${W}new user does not exist, creating..${C}"
        
        # generate user password
        mkdir "${CLIENTDIR}/${CLIENT}"
        PW=$(pwgen 15 1)
        echo "${PW}" > "${CLIENTDIR}/${CLIENT}/pass"

        cd /etc/openvpn/easy-rsa/ || return
		echo "${PW}"; echo "${PW}" | ./easyrsa build-client-full "${CLIENT}"
		echo -e "${G}Client $CLIENT added.${C}"
	fi


	# create system account for new VPN user, add password to it
	user_exists=$(grep -c "^${CLIENT}:" /etc/passwd)
	if [ $user_exists -eq 0 ]
	then
    	useradd -m -d "${CLIENTDIR}/${CLIENT}" -s /bin/nologin "${CLIENT}" || { echo -e "${R}${B}Error creating system account for ${CLIENT} ${C}"; exit 1; }    
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

    chown -R root:root "${CLIENTDIR}/${CLIENT}"
    chmod -R 600 "${CLIENTDIR}/${CLIENT}"

    echo -e "${W}The configuration file has been written to ${CLIENTDIR}/${CLIENT}/${CLIENT}.ovpn${C}"

}

if [ ! "${ACTION}" == "create" ] && [ ! "${ACTION}" == "revoke" ] && [ ! "${ACTION}" == "status" ] && [ ! "${ACTION}" == "send" ]
then
    echo -e "${W}usage:\n./manage.sh create/revoke <username>\n./manage.sh status\n./manage.sh send <username>${C}"
    exit 1
fi

cd /opt/openvpn || exit 1

if [ "${ACTION}" == "create" ]
then
    [ -z "${CLIENT}" ] && { echo -e "${R}Provide a username to create${C}"; exit 1; }

    newClient "${CLIENT}" || { echo -e "${R}${B}Error generating user VPN profile${C}"; exit 1; }

    ### setup Google Authenticator
    google-authenticator -t -d -f -r 3 -R 30 -W -C -s "/opt/openvpn/google-auth/${CLIENT}" || { echo -e "${R}${B}error generating QR code${C}"; exit 1; }
    secret=$(head -n 1 "/opt/openvpn/google-auth/${CLIENT}")
    qrencode -t PNG -o "/opt/openvpn/google-auth/${CLIENT}.png" "otpauth://totp/${CLIENT}@${HOST}?secret=${secret}&issuer=openvpn" || { echo -e "${R}${B}Error generating PNG${C}"; exit 1; }

    PW=$(cat "${CLIENTDIR}/${CLIENT}/pass") || { echo -e "${R}${B}Error generating new user${C}"; exit 1; }
    emailProfile "${CLIENT}" "${PW}" || { echo -e "${R}${B}Error sending profile to new user ${CLIENT} ${C}"; exit 1; }
fi


if [ "${ACTION}" == "revoke" ]
then

    [ -z "${CLIENT}" ] &&  { echo -e "${R}Provide a username to revoke${C}"; exit 1; }

    cd /etc/openvpn/easy-rsa/ || exit 1

    ./easyrsa --batch revoke "${CLIENT}"
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
    rm -f "pki/reqs/${CLIENT}.req*"
    rm -f "pki/private/${CLIENT}.key*"
    rm -f "pki/issued/${CLIENT}.crt*"
    rm -f /etc/openvpn/crl.pem
    cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
    chmod 644 /etc/openvpn/crl.pem
    

    # remove client from PKI index
    sed -i "/CN=${CLIENT}$/d" /etc/openvpn/easy-rsa/pki/index.txt

    # remove user OS acct that was created by OpenVPN manage.sh script
    id "${CLIENT}" && userdel -r -f "${CLIENT}"
    
    rm -rf "${CLIENTDIR:?}/${CLIENT:?}"

    echo -e "${G}VPN access for $CLIENT is revoked${C}"
fi


if [ "${ACTION}" == "status" ]
then
    cat /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | grep -v "server_"
fi

if [ "${ACTION}" == "send" ]
then

    [ -z "${CLIENT}" ] && { echo -e "${R}Provide a username to send profile to${C}"; exit 1; }
    PW=$(cat "${CLIENTDIR}/${CLIENT}/pass") || { echo -e "${R}${B}User doesnt exist${C}"; exit 1; }
    emailProfile "${CLIENT}" "${PW}" || { echo -e "${R}${B}Error sending profile to user ${CLIENT}${C}"; exit 1; }
    echo -e "${G}Email profile sent to ${CLIENT} ${C}"
fi
