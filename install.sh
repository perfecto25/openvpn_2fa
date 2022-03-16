#!/bin/bash
# installs OpenVPN on Rocky 8 Linux (with 2FA via Google Authenticator)
# Code taken from this repo: https://github.com/angristan/openvpn-install
# and adjusted specifically for Rocky 8 (using all default encryption settings)

SUBNET="10.8.24.0"

function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS() {
	
	if [[ -e /etc/system-release ]]; then
		source /etc/os-release
		if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
			OS="centos"
			if [[ ! $VERSION_ID =~ (7|8) ]]; then
				echo "⚠️ Your version of CentOS is not supported."
				echo ""
				echo "The script only support CentOS 7 and CentOS 8."
				echo ""
				exit 1
			fi
		fi
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, Amazon Linux 2, Oracle Linux 8 or Arch Linux system"
		exit 1
	fi
}

function initialCheck() {
	if ! isRoot; then
		echo "Sorry, you need to run this as root"
		exit 1
	fi
	if ! tunAvailable; then
		echo "TUN is not available"
		exit 1
	fi
	checkOS
}

function installQuestions() {
	echo "Welcome to the OpenVPN installer!"
	echo ""

	# Detect public IPv4 address and pre-fill for the user
	IP=$(curl -4 icanhazip.com)

	PUBLICIP=$IP
	IPV6_SUPPORT="n"
	PORT="1194"
    PROTOCOL="udp"
	DNS=1
	COMPRESSION_ENABLED="n"
    CIPHER="AES-128-GCM"
    CERT_TYPE="1" # ECDSA
    CERT_CURVE="prime256v1"
    CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
    DH_TYPE="1" # ECDH
    DH_CURVE="prime256v1"
    HMAC_ALG="SHA256"
    TLS_SIG="1" # tls-crypt
    RSA_KEY_SIZE="2048"
	DH_KEY_SIZE="2048"
	
	echo ""
	echo "Starting OpenVPN configuration based on these default values:"
    echo -e "\n
    PUBLICIP=$IP
    IPV6_SUPPORT=$IPV6_SUPPORT
    PORT=$PORT
    PROTOCOL=$PROTOCOL
    DNS=$DNS
    COMPRESSION_ENABLED=$COMPRESSION_ENABLED
    CIPHER=$CIPHER
    CERT_TYPE=$CERT_TYPE
    CERT_CURVE=$CERT_CURVE
    CC_CIPHER=$CC_CIPHER
    DH_TYPE=$DH_TYPE
    DH_CURVE=$DH_CURVE
    HMAC_ALG=$HMAC_ALG
    TLS_SIG=$TLS_SIG
    RSA_KEY_SIZE=$RSA_KEY_SIZE
    DH_KEY_SIZE=$DH_KEY_SIZE
    \n
    "
	
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "Press any key to continue..."
	fi
}
function installOpenVPN() {
	if [[ $AUTO_INSTALL == "y" ]]; then
		# Set default choices so that no questions will be asked.
		APPROVE_INSTALL=${APPROVE_INSTALL:-y}
		APPROVE_IP=${APPROVE_IP:-y}
		IPV6_SUPPORT=${IPV6_SUPPORT:-n}
		PORT_CHOICE=${PORT_CHOICE:-1}
		PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
		DNS=${DNS:-1}
		COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
		CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
		CLIENT=${CLIENT:-client}
		PASS=${PASS:-1}
		CONTINUE=${CONTINUE:-y}
		ENDPOINT=${ENDPOINT:-$PUBLIC_IP}
	fi
	# Run setup questions first, and set other variables if auto-install
	installQuestions
	# Get the "public" interface from the default route
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

	# $NIC can not be empty for script rm-openvpn-rules.sh
	if [[ -z $NIC ]]; then
		echo
		echo "Can not detect public interface."
		echo "This needs for setup MASQUERADE."
		until [[ $CONTINUE =~ (y|n) ]]; do
			read -rp "Continue? [y/n]: " -e CONTINUE
		done
		if [[ $CONTINUE == "n" ]]; then
			exit 1
		fi
	fi

    mkdir -p /etc/openvpn /opt/openvpn/clients /opt/openvpn/google-auth /var/log/openvpn

	# If OpenVPN isn't installed yet, install it. This script is more-or-less
	# idempotent on multiple runs, but will only install OpenVPN from upstream
	# the first time.
	if [[ ! -e /etc/openvpn/server.conf ]]; then
			
        yum install -y epel-release cmake3 git lz4 lz4-devel lzo-devel google-authenticator qrencode pam-devel pwgen
        yum -y groupinstall "Development Tools"
        yum -y copr enable dsommers/openvpn-release
        yum install -y iptables openssl wget ca-certificates curl tar 'policycoreutils-python*' openvpn

		# An old version of easy-rsa was available by default in some openvpn packages
		if [[ -d /etc/openvpn/easy-rsa/ ]]; then
			rm -rf /etc/openvpn/easy-rsa/
		fi
	fi
	# Find out if the machine uses nogroup or nobody for the permissionless group
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi
	# Install the latest version of easy-rsa from source, if not already installed.
	if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
		local version="3.0.7"
		wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
		mkdir -p /etc/openvpn/easy-rsa
		tar xzf ~/easy-rsa.tgz --strip-components=1 --directory /etc/openvpn/easy-rsa
		rm -f ~/easy-rsa.tgz
		cd /etc/openvpn/easy-rsa/ || return
		case $CERT_TYPE in
		1)
			echo "set_var EASYRSA_ALGO ec" >vars
			echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
			;;
		2)
			echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
			;;
		esac

		# Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
		SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_CN" >SERVER_CN_GENERATED
		SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_NAME" >SERVER_NAME_GENERATED
		echo "set_var EASYRSA_REQ_CN $SERVER_CN" >>vars
		
        # Create the PKI, set up the CA, the DH params and the server certificate
		./easyrsa init-pki
		./easyrsa --batch build-ca nopass
        
		./easyrsa build-server-full "$SERVER_NAME" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
		openvpn --genkey --secret /etc/openvpn/tls-crypt.key
        
		
	else
		# If easy-rsa is already installed, grab the generated SERVER_NAME
		# for client configs
		cd /etc/openvpn/easy-rsa/ || return
		SERVER_NAME=$(cat SERVER_NAME_GENERATED)
	fi
	
    # Move all the generated files
	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	
	# Make cert revocation list readable for non-root
	chmod 644 /etc/openvpn/crl.pem

	# Generate server.conf
	echo -e "port $PORT \n
proto ${PROTOCOL} \n
dev tun \n
user nobody \n
group $NOGROUP \n
persist-key \n
persist-tun \n
keepalive 10 120 \n
topology subnet \n
server ${SUBNET} 255.255.255.0 \n
ifconfig-pool-persist ipp.txt \n
push \"redirect-gateway def1 bypass-dhcp\" \n
ecdh-curve ${DH_CURVE} \n
tls-crypt tls-crypt.key \n
crl-verify crl.pem \n
ca ca.crt \n
cert ${SERVER_NAME}.crt \n
key ${SERVER_NAME}.key \n
auth ${HMAC_ALG} \n
cipher ${CIPHER} \n
ncp-ciphers ${CIPHER} \n
tls-server \n
tls-version-min 1.2 \n
tls-cipher ${CC_CIPHER} \n
dh none \n
ecdh-curve $DH_CURVE \n
client-config-dir /etc/openvpn/ccd \n
status /var/log/openvpn/status.log \n
duplicate-cn \n
verb 3" >>/etc/openvpn/server.conf

    # remove empty lines
    sed -i '/^$/d' /etc/openvpn/server.conf

	# Create client-config-dir dir
	mkdir -p /etc/openvpn/ccd
	# Create log dir
	mkdir -p /var/log/openvpn
	# Enable routing
	echo "net.ipv4.ip_forward=1" >/etc/sysctl.d/99-openvpn.conf
    echo "net.ipv6.conf.all.disable_ipv6=1" >/etc/sysctl.d/99-openvpn.conf
    echo "net.ipv6.conf.default.disable_ipv6=1" >/etc/sysctl.d/99-openvpn.conf

	# Apply sysctl rules
	sysctl --system
	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ $PORT != '1194' ]]; then
				semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
			fi
		fi
	fi
	# Finally, restart and enable OpenVPN
	
    # Don't modify package-provided service
    cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service
    # Workaround to fix OpenVPN service on OpenVZ
    sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
    # Another workaround to keep using /etc/openvpn/
    sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service
    systemctl daemon-reload
    systemctl enable openvpn@server
    systemctl restart openvpn@server

	# Add iptables rules in two scripts
	mkdir -p /etc/iptables
	# Script to add rules
	echo "#!/bin/sh
    iptables -t nat -I POSTROUTING 1 -s ${SUBNET}/24 -o $NIC -j MASQUERADE
    iptables -I INPUT 1 -i tun0 -j ACCEPT
    iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
    iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
    iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh
	
	# Script to remove rules
	echo "#!/bin/sh
    iptables -t nat -D POSTROUTING -s ${SUBNET}/24 -o $NIC -j MASQUERADE
    iptables -D INPUT -i tun0 -j ACCEPT
    iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
    iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
    iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh
	
	chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh
	# Handle the rules via a systemd script
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service
	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn
	# If the server is behind a NAT, use the correct IP address for the clients to connect to
	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi
	# client-template.txt is created so we have a template to add further users later
	echo -e "client \n
proto udp \n
explicit-exit-notify \n
remote $IP $PORT \n
dev tun \n
resolv-retry infinite \n
nobind \n
persist-key \n
persist-tun \n
remote-cert-tls server \n
verify-x509-name ${SERVER_NAME} name \n
auth ${HMAC_ALG} \n
auth-nocache \n
cipher ${CIPHER} \n
tls-client \n
tls-version-min 1.2 \n
tls-cipher ${CC_CIPHER} \n
ignore-unknown-option block-outside-dns \n
remote-cert-tls server \n
auth-user-pass \n
static-challenge \"Enter 2FA Authenticator code:\" 1 \n
dhcp-option DOMAIN-ROUTE . \n
pull-filter ignore redirect-gateway \n
verb 3" >>/etc/openvpn/client-template.txt

sed -i '/^$/d' /etc/openvpn/client-template.txt

echo -e "\nInstall complete\n"
}

function removeOpenVPN() {
	echo ""
	read -rp "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
	if [[ $REMOVE == 'y' ]]; then
		# Get OpenVPN port from the configuration
		PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
		PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
		
        # Stop OpenVPN
		if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
			systemctl disable openvpn@server
			systemctl stop openvpn@server
			# Remove customised service
			rm /etc/systemd/system/openvpn@.service
		fi
		# Remove the iptables rules related to the script
		systemctl stop iptables-openvpn
		# Cleanup
		systemctl disable iptables-openvpn
		rm /etc/systemd/system/iptables-openvpn.service
		systemctl daemon-reload
		rm /etc/iptables/add-openvpn-rules.sh
		rm /etc/iptables/rm-openvpn-rules.sh

		# SELinux
		if hash sestatus 2>/dev/null; then
			if sestatus | grep "Current mode" | grep -qs "enforcing"; then
				if [[ $PORT != '1194' ]]; then
					semanage port -d -t openvpn_port_t -p "$PROTOCOL" "$PORT"
				fi
			fi
		fi

		# Cleanup
		find /home/ -maxdepth 2 -name "*.ovpn" -delete
		find /root/ -maxdepth 1 -name "*.ovpn" -delete
		rm -rf /etc/openvpn
		rm -rf /usr/share/doc/openvpn*
		rm -f /etc/sysctl.d/99-openvpn.conf
		rm -rf /var/log/openvpn
        yum -y remove openvpn
		
		echo "OpenVPN removed!"
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function manageMenu() {
	echo "Welcome to OpenVPN installer!"
	echo "to add/remove users, use manage.sh script"
	echo ""
	echo "It looks like OpenVPN is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Remove OpenVPN"
	echo "   2) Exit"
	until [[ $MENU_OPTION =~ ^[1-4]$ ]]; do
		read -rp "Select an option [1-4]: " MENU_OPTION
	done
	case $MENU_OPTION in
	1)
		removeOpenVPN
		;;
	2)
		exit 0
		;;
	esac
}
# Check for root, TUN, OS...
initialCheck

# Check if OpenVPN is already installed
if [[ -e /etc/openvpn/server.conf && $AUTO_INSTALL != "y" ]]; then
	manageMenu
else
	installOpenVPN
fi