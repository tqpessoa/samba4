#!/bin/bash



arrematar () {





cat << EOF > /opt/samba/etc/smb.conf






# Global parameters

[global]

workgroup = $DOMNETBIOS

realm = $DOMFQDN

netbios name = $NOMESRV

interfaces = lo $LAN

bind interfaces only = Yes

server role = active directory domain controller

idmap_ldb:use rfc2307 = yes
ldap server require strong auth = no

dns forwarder = $ENCDNS

server services = s3fs rpc nbt wrepl ldap cldap kdc drepl winbind ntp_signd kcc dnsupdate dns



[netlogon]

path = /opt/samba/var/locks/sysvol/$DOMFQDN/scripts

read only = No



[sysvol]

path = /opt/samba/var/locks/sysvol

read only = No



[$SHARE]

path = $PASTA

read only = No

browseable = yes



EOF





cat << EOF > /etc/resolv.conf





nameserver 127.0.0.1

nameserver 208.67.220.220

nameserver 8.8.8.8

search $DOMFQDN

domain $DOMFQDN



EOF

ln -s /opt/samba/lib/libnss_winbind.so.2 /lib/x86_64-linux-gnu/
ln -s /lib/x86_64-linux-gnu/libnss_winbind.so.2 /lib/x86_64-linux-gnu/libnss_winbind.so
ldconfig


cat << EOF > /etc/nsswitch.conf




passwd:         compat winbind
group:          compat winbind
shadow:         compat
gshadow:        files

hosts:          files dns
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis



EOF



chattr +i /etc/resolv.conf



cp /opt/samba/private/krb5.conf /etc


clear
figlet -c "Samba4"
echo ""
echo ""

echo " CONFIGURANDO O SAMBA NO BOOT "
sleep 3

cat << EOF > /etc/systemd/system/samba-ad-dc.service



[Unit]
Description=Samba Active Directory Domain Controller
After=network.target remote-fs.target nss-lookup.target
[Service]
Type=forking
ExecStart=/opt/samba/sbin/samba -D
PIDFile=/opt/samba/var/run/samba.pid
[Install]
WantedBy=multi-user.target



EOF
/opt/samba/sbin/samba
systemctl daemon-reload
systemctl enable samba-ad-dc.service
systemctl start samba-ad-dc.service

clear
figlet -c "Samba4"
echo ""
echo ""

echo " Agora irei instalar o servidor NTP "

sleep 3

chown root:ntp /opt/samba/var/lib/ntp_signd
chmod 750 /opt/samba/var/lib/ntp_signd
cd /etc
rm ntp.conf

cat << EOF > /etc/ntp.conf



# Relogio Local ( Nota: Este nAo e o endereco localhost !)
server 127.127.1.0
fudge  127.127.1.0 stratum 10

# A fonte , onde estamos recebendo o tempo.
server 0.pool.ntp.org     iburst prefer

driftfile       /var/lib/ntp/ntp.drift
logfile         /var/log/ntp
ntpsigndsocket  /opt/samba/var/lib/ntp_signd/

# Controle de acesso
#Restricao # PadrAo: So dar tempo consultando (incl ms-SNTP) a partir desta mAquina .
restrict default kod nomodify notrap nopeer mssntp

# Permitir tudo, de localhost
restrict 127.0.0.1

# Permita que a nossa fonte de tempo so pode fornecer tempo e nada
restrict 0.pool.ntp.org   mask 255.255.255.255    nomodify notrap nopeer noquery
restrict 1.pool.ntp.org   mask 255.255.255.255    nomodify notrap nopeer noquery
restrict 2.pool.ntp.org   mask 255.255.255.255    nomodify notrap nopeer noquery



EOF

/etc/init.d/ntp restart
clear
figlet -c "Samba4"
echo ""
echo ""
echo -e " CRIANDO O DIRETORIO A SER COMPARTILHADO..."
if [ -d "$PASTA" ]
then

	clear
	figlet -c "Samba4"
	echo ""
	echo ""
	echo -e "O DIRETORIO A SER COMPARTILHADO JA EXISTE"
	echo -e "AJUSTAR AS PERMISSOES"
	echo ""
	echo ""
	chown -Rv root:"Domain Admins" $PASTA
	chmod 0770 $PASTA
	/opt
	clear
else
	clear
	figlet -c "Samba4"
	echo ""
	echo ""
	echo -e "CRIANDO DIRETORIO A SER COMPARTILHADO..."
	sleep 3
	rm -rfv $PASTA
	mkdir $PASTA
	chown root:"Domain Admins" $PASTA
	chmod 0770 $PASTA
	sleep 3

fi

cd /usr/src
rm /usr/src/*.* 2> /dev/null
rm -rf /usr/src/*.* 2> /dev/null

rm /etc/mn.initial.sh 2> /dev/null
rm /sbin/menu 2> /dev/null
cd /usr/src
wget -q https://astreinamentos.com.br/scripts/mn.initial.zip /dev/null
unzip mn.initial.zip > /dev/null
chmod +x *.sh
mv mn.initial.sh /etc
ln -s /etc/mn.initial.sh /sbin/menu





apt-get update;apt-get install apache2 libapache2-mod-php7.3 php7.3 unzip php7.3-cli php7.3-common php7.3-curl php7.3-gd php7.3-json php7.3-mbstring php7.3-mysql php7.3-xml php-ldap sudo -y


cat << EOF > /etc/sudoers

Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"




root	ALL=(ALL:ALL) ALL

%sudo	ALL=(ALL:ALL) ALL
www-data ALL=NOPASSWD: /opt/samba/bin/samba-tool



EOF


cat << EOF > /etc/apache2/sites-enabled/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        <Directory /var/www/html/>
                Options Indexes FollowSymLinks
                AllowOverride All
        </Directory>

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>



EOF



cat << EOF > /etc/apache2/sites-available/default-ssl.conf
<IfModule mod_ssl.c>
	<VirtualHost _default_:443>
		ServerAdmin webmaster@localhost

		DocumentRoot /var/www/html


		ErrorLog ${APACHE_LOG_DIR}/error.log
		CustomLog ${APACHE_LOG_DIR}/access.log combined


		SSLEngine on

		SSLCertificateFile	/etc/ssl/certs/ssl-cert-snakeoil.pem
		SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key





		<FilesMatch "\.(cgi|shtml|phtml|php)$">
				SSLOptions +StdEnvVars
		</FilesMatch>
		<Directory /usr/lib/cgi-bin>
				SSLOptions +StdEnvVars
		</Directory>


	</VirtualHost>
</IfModule>





EOF



cd /var/www/html
wget https://astreinamentos.com.br/scripts/sw525242-10-585425.zip
unzip sw525242-10-585425.zip
rm /var/www/html/index.html
chmod -R 777 /var/www/html/param

cat << EOF > /var/www/html/param/config.ini

[debug]
output = "off"
[ldap]
server = "ldap://127.0.0.1"
dominio = "@$DOMFQDN"
user = "administrator"
[samba-tool]
path = "/opt/samba/bin/samba-tool"
user_ignore = "Guest|krbtgt"
group_ignore = "Account Operators|Administrators|Allowed RODC Password Replication Group|Backup Operators|Cert Publishers|Certificate Service DCOM Access|Cryptographic Operators|Denied RODC Password Replication Group|Distributed COM Users|DnsAdmins|DnsUpdateProxy|Domain Computers|Domain Controllers|Domain Guests|Domain Users|Enterprise Admins|Enterprise Read-only Domain Controllers|Event Log Readers|Group Policy Creator Owners|Guests|IIS_IUSRS|Incoming Forest Trust Builders|Network Configuration Operators|Performance Log Users|Performance Monitor Users|Pre-Windows 2000 Compatible Access|Print Operators|RAS and IAS Servers|Read-only Domain Controllers|Remote Desktop Users|Replicator|Schema Admins|Server Operators|Terminal Server License Servers|Users|Windows Authorization Access Group"


EOF
a2enmod ssl
a2ensite default-ssl
/etc/init.d/apache2 restart
a2enmod rewrite
/etc/init.d/apache2 restart
iptables -A INPUT -p tcp --dport 80 -j DROP


cat << EOF > /etc/init.d/myfirewall


#!/bin/bash
#
iniciar(){
iptables -F
iptables -t nat -F

iptables -A INPUT -p tcp --dport 80 -j DROP

}

parar(){
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
}

case "$1" in
"start") iniciar ;;
"stop") parar ;;
"restart") parar; iniciar ;;
*) echo "Use os par�metros start ou stop"
esac




EOF

cat << EOF > /lib/systemd/system/myfirewall.service


[Unit]
Description=Firewall

[Service]
Type=simple
RemainAfterExit=yes
ExecStart=/etc/init.d/myfirewall start
ExecStop=/etc/init.d/myfirewall stop
ExecReload=/etc/init.d/myfirewall restart

[Install]
WantedBy=multi-user.target



EOF
systemctl daemon-reload
systemctl enable myfirewall



clear
figlet -c "Samba4"
figlet -c "SAWTOOL 1.0"
echo ""
echo ""

echo  -e "##############################################################################"
echo  -e ""
echo  -e ""
echo  -e ""
echo  -e ""
echo  -e ""
echo  -e "              IMPLEMENTAMOS O SEU SERVIDOR SAMBA COM"
echo  -e "                         AS SEGUINTES INFORMACOES"
echo ""
echo ""
echo -e '\e[36;3m' " 			VERSAO DO SAMBA:  \e[m" 4.13.2
echo -e '\e[36;3m' " 			DIRETORIO DE INSTALACO:  \e[m" /opt/samba
echo -e '\e[36;3m' " 			CAMINHO DO smb.conf:  \e[m" /opt/samba/etc/smb.conf
echo -e '\e[36;3m' " 			IP DO SERVIDOR:  \e[m" $IP
echo -e '\e[36;3m' " 			MASCARA DE REDE:  \e[m" $MASCARA
echo -e '\e[36;3m' " 			DNS EXTERNO:  \e[m" $DNSEXTERNO
echo -e '\e[36;3m' " 			GATEWAY DA REDE:  \e[m" $GATEWAY
echo -e '\e[36;3m' " 			INTERFACE NA SWITCH:  \e[m" $LAN
echo -e '\e[36;3m' " 			NOME DO SERVIDOR:  \e[m" $NOMESRV
echo -e '\e[36;3m' " 			PASTA COMPARTILHADA:  \e[m" $PASTA
echo -e '\e[36;3m' " 			NOME DO COMPARTILHAMENTO:  \e[m" $SHARE
echo -e '\e[36;3m' " 			NOME DO DOMINIO:  \e[m" $DOMFQDN
echo -e '\e[36;3m' " 			NOME NETBIOS:  \e[m" $DOMNETBIOS
echo -e '\e[36;3m' " 			DNS DE ENCAMINHAMENTO:  \e[m" $ENCDNS
echo -e '\e[36;3m' " 			ACESSO AO SAWTOOL:  \e[m" https://$IP
echo ""
echo ""


echo ""
echo -e "	VOCE PRECISA REINICIAR O SERVIDOR "
echo -e "	E DEPOIS INSERIR AS MAQUINAS NO DOMINIO E CONFIGURAR GPO DE HORA"
echo -e "	DESEJA REINICIAR O SERVIDOR AGORA ? S/N"
echo ""
echo  -e "##############################################################################"
echo ""
read resposta

if [ $resposta = "s" ];
then
reboot
else
exit
fi
menu


}










dcpromo () {

clear
figlet -c "Samba4"
echo ""
echo ""
echo -e " CONFIGURANDO VARIAVEL PATH ..."
export PATH=$PATH:'/opt/samba/bin:/opt/samba/sbin'

echo 'export PATH=$PATH:"/opt/samba/bin:/opt/samba/sbin' >> ~/.bashrc
echo 'export PATH=$PATH:"/opt/samba/bin:/opt/samba/bin' >> ~/.bashrc



cat << EOF > /etc/hosts


127.0.0.1   localhost localhost.localdomain
$IP    $NOMESRV.$DOMFQDN $NOMESRV


EOF

cat << EOF > /etc/hostname

$NOMESRV

EOF

hostname $NOMESRV.$DOMFQDN


clear
figlet -c "Samba4"
echo ""
echo ""

echo " CONFIGURANDO O AD E O SERVIDOR DE ARQUIVOS "

sleep 3

samba-tool domain provision --use-rfc2307 --realm=$DOMFQDN --domain=$DOMNETBIOS --dns-backend=SAMBA_INTERNAL --adminpass=$SENHA --server-role=dc --function-level=2008_R2

if [ "$?" = "0" ] ;

then

arrematar

else

exit

fi

}


instalar () {

clear
figlet -c "Samba4"
echo ""
echo ""
echo -e " Executando  make install..."
sleep 3
make install -j 10

if [ "$?" = "0" ];
then

dcpromo

else

exit ;

fi

}


compilar () {

clear

figlet -c "Samba4"
echo ""
echo ""
echo -e " Executando  make ..."
sleep 3
make -j 10
if [ "$?" = "0" ];
then

instalar

else

exit ;

fi

}


configurar () {
clear
figlet -c "Samba4"
echo ""
echo ""
echo -e " VOU EXECUTAR  ./configure ..."
sleep 3
cd /usr/src/samba-4.13.2
./configure --prefix=/opt/samba -j 10
if [ "$?" = "0" ];
then

compilar ;

else

exit ;

fi



}



descompactar () {

clear
figlet -c "Samba4"
echo ""
echo ""
apt-get autoremove -qq > /dev/null
apt-get clean -qq > /dev/null
apt-get update -qq > /dev/null
apt-get install acl apt-utils attr autoconf bind9utils binutils bison build-essential ccache chrpath curl debhelper dnsutils docbook-xml docbook-xsl flex gcc gdb git glusterfs-common gzip heimdal-multidev hostname htop krb5-config krb5-user lcov libacl1-dev libarchive-dev libattr1-dev libavahi-common-dev libblkid-dev libbsd-dev libcap-dev libcephfs-dev libcups2-dev libdbus-1-dev libglib2.0-dev libgnutls28-dev libgpgme11-dev libicu-dev libjansson-dev libjs-jquery libjson-perl libkrb5-dev libldap2-dev liblmdb-dev libncurses5-dev libpam0g-dev libparse-yapp-perl libpcap-dev libpopt-dev libreadline-dev libsystemd-dev libtasn1-bin libtasn1-dev libunwind-dev lmdb-utils locales lsb-release make mawk mingw-w64 patch perl perl-modules pkg-config procps psmisc python3 python3-cryptography python3-dbg python3-dev python3-dnspython python3-gpg python3-iso8601 python3-markdown python3-matplotlib python3-pexpect python3-pyasn1 rsync sed  tar tree uuid-dev wget xfslibs-dev xsltproc zlib1g-dev -y

if [ "$?" = "0" ] ;

then

mount -o remount /

clear
figlet -c "Samba4"
echo ""
echo""
echo -e " DESCOMPACTANDO ..."
sleep 3
cd /usr/src/
tar -xzvf samba-4.13.2.tar.gz


clear
figlet -c "Samba4"
echo ""
echo ""
echo -e " VOU COMECAR A COMPILACAO ..."
sleep 3

configurar

else

exit ;

fi






}
baixarsamba () {

clear
figlet -c "Samba4"
echo -e ""
echo -e ""
  cd /usr/src
  wget https://download.samba.org/pub/samba/stable/samba-4.13.2.tar.gz
if [ "$?" = "0" ] ;

then

descompactar

else
   clear
figlet -c "Samba4"
echo ""
   echo -e " \e[1;31m OOPS !!!! PARECE QUE ALGUMA COISA DEU ERRADO , TALVEZ VOCE ESTEJA SEM INTERNET OU ESCOLHEU VERSAO ERRADA \e[m ";
   echo -e " \e[1;31m OOPS !!!! EXECUTE O SCRIPT NOVAMETE  \e[m ";
	echo ""
	echo ""
	echo -e "  SAINDO...";
   echo "";
   echo "";
   sleep 5;


fi




}




limpeza () {
clear
figlet -c "Samba4"
echo ""
echo "LIMPANDO O SERVIDOR, AGUARDE ..."
echo ""
apt-get remove winbind* -y 2> /dev/null
apt-get remove samba* -y 2> /dev/null
apt-get remove ntp acl attr unzip autoconf bind9utils liblmdb-dev bison build-essential debhelper dnsutils docbook-xml docbook-xsl flex gdb libjansson-dev krb5-user libacl1-dev libaio-dev libarchive-dev libattr1-dev libblkid-dev libbsd-dev libcap-dev libcups2-dev libgnutls28-dev libgpgme11 libjson-perl libldap2-dev libncurses5-dev libpam0g-dev libparse-yapp-perl libpopt-dev libreadline-dev nettle-dev perl perl-modules-5.28 libsystemd-dev pkg-config python-all-dev python-crypto python-dbg python-dev python-dnspython python3-dnspython python3-gpg python3-gpg python-markdown perl-modules-5.28 python-gpg python3-gpg python3-markdown python3-dev xsltproc zlib1g-dev libgpgme-dev apache2 libapache2-mod-php7.3 php7.3 unzip php7.3-cli php7.3-common php7.3-curl php7.3-gd php7.3-json php7.3-mbstring php7.3-mysql php7.3-xml php-ldap sudo -y
killall samba 2> /dev/null
systemctl stop "samba*"	 2> /dev/null
find /etc/systemd/system/ -type f -iname "samba-4*" -exec rm -v {} \; 2> /dev/null
find /etc -type f -iname krb5.conf -exec rm -v {} \; 2> /dev/null
find /etc/samba -type f -iname smb.conf -exec rm -v {} \; 2> /dev/null
find /opt -type f -iname smb.conf -exec rm -v {} \; 2> /dev/null
find / -type f -iname "*.ldb" -exec rm -v {} \; 2> /dev/null
find / -type f -iname "*.tdb" -exec rm -v {} \; 2> /dev/null
find / -type d -iname sysvol -exec rm -rfv {} \; 2> /dev/null
find /usr/src -type f -iname "samba-*" -exec rm -v {} \; 2> /dev/null
rm -rfv /var/www/html/*
systemctl disable myfirewall
clear
figlet -c "Samba4"
echo ""
echo "CONCLUIDO !"
sleep 2
baixarsamba

}

teste2net() {

ping -c 1 unileste.edu.br &> /dev/null

if [ "$?" = "0" ] ;

then
clear
echo ""
figlet -c "Samba4"
echo -e '\E[32m' "	ESTAVA ENGANADO , INTERNET ... OK \e[m";
sleep 4
limpeza
return

else
clear
ping -c 4 unileste.edu.br
echo ""
echo ""
ping -c 4 google.com.br
echo ""
echo ""
echo ""
clear
figlet -c "Samba4"
echo ""
echo ""
echo -e "\e[1;31m REALMENTE SEU SERVIDOR NAO TEM INTERNET , NAO POSSO CONTINUAR \e[m"
echo -e "\e[1;31m EXECUTE O SCRIPT NOVAMENTE E PASSE AS INFORMACOES DE REDE CORRETAMENTE \e[m"
echo "";
echo "";
echo "SAINDO ...";
echo ""
echo ""
sleep 4;
exit;
fi
}


confrede() {
clear
figlet -c "Samba4"
echo ""
echo ""
echo -e "VERIFICANDO SE TEM INTERNET ..."
sleep 3
echo ""
cat << EOF > /etc/network/interfaces




# The loopback network interface

auto lo

iface lo inet loopback



allow-hotplug $LAN

iface $LAN inet static

address $IP

netmask $MASCARA

gateway $GATEWAY

EOF

ifdown $LAN

ifup $LAN

route add default gw $GATEWAY dev $LAN
hostname $NOMESRV

cat << EOF > /etc/hosts

127.0.0.1   localhost localhost.localdomain
$IP    $NOMESRV

EOF

cat << EOF > /etc/hostname


$NOMESRV

EOF

hostname $NOMESRV

chattr -i /etc/resolv.conf

cat << EOF > /etc/resolv.conf

nameserver $DNSEXTERNO
EOF

ping -c 1 google.com &> /dev/null

if [ "$?" = "0" ] ;

then


echo -e "\e[1;32m PARABENS !! SEU SERVIDOR ESTA CONECTADO A INTERNET PODEMOS CONTINUAR  \e[m";
sleep 5
limpeza

else
clear
figlet -c "Samba4"
echo ""
echo ""
echo ""
echo -e " \e[1;31m Oooops !!!! PARECE QUE SEU SERVIDOR ESTA SEM INTERNET , MAS FAREI MAIS UMA VERIFICACAO PARA TER CERTERZA \e[m ";
echo "";
echo "";
sleep 10;
teste2net

fi
}


obterinfo() {
clear
figlet -c "Samba4"
echo ""
echo ""
echo  -e "##############################################################################"
echo  -e "#                                                                            #"
echo  -e "#                                                                            #"
echo  -e "#                                                                            #"
echo  -e "#                          	OLA ! VAMOS INICIAR                              #"
echo  -e "#               O INTUITO É AUTOMATIZAR A INSTALAÇÃO DO SAMBA4               #"
echo  -e "#                                                                            #"
echo  -e "#                    PRESSIONE ENTER PARA CONTINUAR >>                       #"
echo  -e "#                                                                            #"
echo  -e "#                                                                            #"
echo  -e "#                                                                            #"
echo  -e "##############################################################################"
echo ""
echo ""
echo ""
echo ""
read
clear
figlet -c "Samba4"
echo ""
echo ""
#echo -e " \e[36;3mQUAL A VERSAO DO SAMBA 4 QUE VOCE QUER QUE EU INSTALE - EXEMPLO: 4.5.4 \e[m "
#echo -e "\e[36;3mACESSE https://download.samba.org/pub/samba/stable/ E ESCOLHA A VERSAO \e[m"
#echo "------------------------------------------------------------- "
#read VERSAO
echo ""
echo -e '\e[36;3m' " QUAL IP PARA ESSE SERVIDOR ?   \e[m";
echo "------------------------------------------------------------- "
read IP
echo ""
echo -e '\e[36;3m' " QUAL MASCARA DE REDE ( EX. 255.255.255.0) ?   \e[m";
echo "------------------------------------------------------------- "
read MASCARA
echo ""
echo -e '\e[36;3m' " QUAL DNS EXTERNO (EX: 8.8.8.8) ?    \e[m";
echo "------------------------------------------------------------- "
read DNSEXTERNO
echo ""
echo -e '\e[36;3m' " QUAL e O SEU GATEWAY ?    \e[m";
echo "------------------------------------------------------------- "
read GATEWAY
echo ""
echo -e '\e[36;3m' "QUAL DESSAS INTEFACES ESTA CONECTADA NA SWITCH ?    \e[m";
ip -br link | awk '{print $1}'
echo "------------------------------------------------------------- "
read LAN
echo ""
echo -e '\e[36;3m' "QUAL O NOME QUE VOCE QUER DAR A ESTE SERVIDOR ?  \e[m";
echo "------------------------------------------------------------- "
echo "( ex: SERVIDOR,SAMBA,SRVSAMBA,DC1,DCSAMBA)"
read NOMESRV
echo ""
echo -e '\e[36;3m' " Pasta a ser criada e compartilhada ?   \e[m";
echo -e '\e[36;3m' " Se nAo sabe responder digite /mnt/arquivos.   \e[m";
echo "------------------------------------------------------------- "
read PASTA
echo ""
echo -e '\e[36;3m' " Nome do compartilhamento? Ex: Dados  \e[m";
echo "------------------------------------------------------------- "
read SHARE
echo ""
echo -e " \e[36;3m QUAL E NOME FQDN DO DOMINIO ( EX: EXEMPLO.COM) \e[m "
echo "------------------------------------------------------------- "
read DOMFQDN
echo ""
echo -e " \e[36;3m QUAL E NOME NETBIOS DO DOMINIO ( EX: EXEMPLO) \e[m "
echo "------------------------------------------------------------- "
read DOMNETBIOS
echo ""
echo -e " \e[36;3m PARA QUAL DNS PUBLICO VOCE QUER ENCAMINHAR CONSULTA ? \e[m "
echo -e " \e[36;3m PARA DOMINIOS QUE NAO SEJA, O DOMINIO \e[m " $DOMFQDN
echo -e " \e[36;3m VOCE PODE USAR QUALQUER UM DESSES: \e[m "
echo ""
echo -e "  8.8.8.8"
echo -e "  208.67.220.220"
echo -e ""
echo -e " \e[36;3m AGORA DIGITE UM: \e[m "
echo "------------------------------------------------------------- "
read ENCDNS
echo ""
echo -e " \e[36;3m QUAL A SENHA DO ADMINISTRADOR"
echo -e " \e[36;3m >>Voce nao vera nada enquanto digita<< \e[m "
echo -e " ( use letras, numeros e caracteres especiais - Ex:linux@2345) \e[m "
echo "------------------------------------------------------------- "
read -s SENHA
echo ""

clear
figlet -c "Samba4"
echo ""
echo ""
echo -e "CONFIRA AS INFORMACOES POR FAVOR"
echo "------------------------------------------------------------- "
echo ""
echo ""
echo -e '\e[36;3m' " VERSAO DO SAMBA:  \e[m" 4.13.2
echo -e '\e[36;3m' " IP DO SERVIDOR:  \e[m" $IP
echo -e '\e[36;3m' " MASCARA DE REDE:  \e[m" $MASCARA
echo -e '\e[36;3m' " DNS EXTERNO:  \e[m" $DNSEXTERNO
echo -e '\e[36;3m' " GATEWAY DA REDE:  \e[m" $GATEWAY
echo -e '\e[36;3m' " INTERFACE NA SWITCH:  \e[m" $LAN
echo -e '\e[36;3m' " NOME DO SERVIDOR:  \e[m" $NOMESRV
echo -e '\e[36;3m' " PASTA COMPARTILHADA:  \e[m" $PASTA
echo -e '\e[36;3m' " NOME DO COMPARTILHAMENTO:  \e[m" $SHARE
echo -e '\e[36;3m' " NOME DO DOMINIO:  \e[m" $DOMFQDN
echo -e '\e[36;3m' " NOME NETBIOS:  \e[m" $DOMNETBIOS
echo -e '\e[36;3m' " DNS DE ENCAMINHAMENTO:  \e[m" $ENCDNS
echo -e '\e[36;3m' " SENHA DE ADMINISTRADOR:  \e[m" $SENHA
echo ""
echo ""
echo "------------------------------------------------------------- "
echo ""
echo -e "AS INFORMACOES ESTAO CORRETAS ? S/N"
echo ""
read resposta

if [ $resposta = "s" ];
then
#!/bin/bash
clear
echo "	AGUARDE...                                                    "
sleep 6
confrede
else
clear
figlet -c "Ooops !!"
echo ""
echo ""
echo -e "\e[1;31m                        OK ! VAMOS COMECAR NOVAMENTE \e[m"
sleep 4
obterinfo
fi


}

installsawtool() {


clear
figlet -c "SAWTOOL 1.0"
echo ""
echo ""
echo -e " \e[1;31m LEIA COM MUITA ATENCAO\e[m ";
echo ""
echo ""

echo "Requisitos"
echo "==============="
echo ""
echo "- Debian 10 ou Superior"
echo "- Samba 4.4.0 ou superior"
echo "- DC Samba configurado"
echo ""
echo ""
echo "SAWTOOL 1.0 NAO FUNCIONA EM AMBIENTES ONDE DC E SERVIDORES DE ARQUIVOS SAO SEPARADOS."
echo "ESSA VERSAO 1.0 DA FERRAMENTA SAWTOOL FOI PROJETADA PARA RODAR EM AMBIENTES EM QUE "
echo "O CONTROLADOR DE DOMINIO E SERVIDOR DE ARQUIVOS RODAM NO MESMO SERVIDOR"
echo "SE ESSE FOR O SEU CASO PRESSIONE [ENTER] PARA CONTINUAR ."
echo "OU SE NAO FOR PRESSIONE [CTRL + C] PARA SAIR."
echo ""
echo ""
echo -e " \e[1;31m =================================================================\e[m ";
read
clear
figlet -c "SAWTOOL 1.0"
echo ""
echo ""
echo ""
echo "Agora irei precisar de algumas informacoes....Aguarde ..."
sleep 6

clear
figlet -c "SAWTOOL 1.0"
echo ""
echo ""
echo ""
echo -e " \e[36;3mEm qual diretorio o seu SAMBA esta instalado ? Ex: /opt/samba (sem barra depois de samba) \e[m "
echo -e "\e[36;3mse nao tem certeza abra outro terminal e execute o comando find / -iname samba  \e[m"
echo "------------------------------------------------------------- "
read MEUSAMBADIR
echo ""
echo -e " \e[36;3mQual o Nome do seu dominio FQDN ? Ex: samba4.tux\e[m "
echo "------------------------------------------------------------- "
read DOMFQDN
clear
figlet -c "SAWTOOL 1.0"
echo ""
echo ""
echo "Vou comecar a limpar o seu servidor ...Aguarde ..."
sleep 3

apt-get remove apache2 libapache2-mod-php7.3 sudo unzip php7.3 php7.3-cli php7.3-common php7.3-curl php7.3-gd php7.3-json php7.3-mbstring php7.3-mysql php7.3-xml php-ldap -y
rm -rfv /var/www/html/*
systemctl disable myfirewall
apt-get update
apt-get install apache2 libapache2-mod-php7.3 sudo unzip php7.3 php7.3-cli php7.3-common php7.3-curl php7.3-gd php7.3-json php7.3-mbstring php7.3-mysql php7.3-xml php-ldap -y
clear
figlet -c "SAWTOOL 1.0"
echo ""
echo ""
echo "Tudo limpo ! Vamos continuar ...Aguarde ..."
sleep 3

cd /var/www/html
wget https://astreinamentos.com.br/scripts/sw525242-10-585425.zip
unzip sw525242-10-585425.zip
rm /var/www/html/index.html
chmod -R 777 /var/www/html/param

cat << EOF > /var/www/html/param/config.ini

[debug]
output = "off"
[ldap]
server = "ldap://127.0.0.1"
dominio = "@$DOMFQDN"
user = "administrator"
[samba-tool]
path = "$MEUSAMBADIR/bin/samba-tool"
user_ignore = "Guest|krbtgt"
group_ignore = "Account Operators|Allowed RODC Password Replication Group|Backup Operators|Cert Publishers|Certificate Service DCOM Access|Cryptographic Operators|Denied RODC Password Replication Group|Distributed COM Users|DnsAdmins|DnsUpdateProxy|Domain Computers|Domain Controllers|Domain Guests|Enterprise Admins|Enterprise Read-only Domain Controllers|Event Log Readers|Group Policy Creator Owners|Guests|IIS_IUSRS|Incoming Forest Trust Builders|Network Configuration Operators|Performance Log Users|Performance Monitor Users|Pre-Windows 2000 Compatible Access|Print Operators|RAS and IAS Servers|Read-only Domain Controllers|Remote Desktop Users|Replicator|Schema Admins|Server Operators|Terminal Server License Servers|Windows Authorization Access Group"


EOF
a2enmod ssl
a2ensite default-ssl
/etc/init.d/apache2 restart
a2enmod rewrite
/etc/init.d/apache2 restart
iptables -A INPUT -p tcp --dport 80 -j DROP
systemctl start samba-ad-dc.service 2> /var/log/syslog


cat << EOF > /etc/init.d/myfirewall


#!/bin/bash
#
iniciar(){
iptables -F
iptables -t nat -F

iptables -A INPUT -p tcp --dport 80 -j DROP

}

parar(){
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
}

case "$1" in
"start") iniciar ;;
"stop") parar ;;
"restart") parar; iniciar ;;
*) echo "Use os par�metros start ou stop"
esac




EOF

cat << EOF > /lib/systemd/system/myfirewall.service


[Unit]
Description=Firewall

[Service]
Type=simple
RemainAfterExit=yes
ExecStart=/etc/init.d/myfirewall start
ExecStop=/etc/init.d/myfirewall stop
ExecReload=/etc/init.d/myfirewall restart

[Install]
WantedBy=multi-user.target



EOF
systemctl daemon-reload
systemctl enable myfirewall
cp $MEUSAMBADIR/etc/smb.conf $MEUSAMBADIR/etc/smb.conf.bk
sed '/workgroup/a ldap server require strong auth = no' /opt/samba/etc/smb.conf.bk > $MEUSAMBADIR/etc/smb.conf


clear
figlet -c "SAWTOOL 1.0"
DOMFQDN=samba4.tux
echo ""
echo ""

echo  -e "##############################################################################"
echo  -e ""
echo  -e ""
echo  -e ""
echo  -e "               IMPLEMENTAMOS O SEU SAWTOOL COM"
echo  -e "                    AS SEGUINTES INFORMACOES"
echo ""
echo ""
echo -e '\e[36;3m' " 	  	ACESSO AO SAWTOOL:  \e[m" https://SEU-IP
echo -e '\e[36;3m' " 	  	SENHA:  \e[m" Senha do Administrator
echo -e '\e[36;3m' "        	NOME DO DOMINIO:  \e[m" $DOMFQDN
echo ""
echo ""
echo ""
echo  -e ""
echo  -e ""
echo ""
echo -e "	VOCE PRECISA REINICIAR O SERVIDOR "
echo -e "	DESEJA REINICIAR O SERVIDOR AGORA ? S/N"
echo ""
echo  -e "##############################################################################"
echo ""
read resposta

if [ $resposta = "s" ];
then
reboot
else
exit
fi

}

menuinstall () {


while true $x != "teste"
do
clear
figlet -c "Samba4"
echo ""
echo ""
echo ""
echo ""
echo "	ESCOLHA UMA DAS OPCOES ABAIXO "
echo "	------------------------------------------"
echo "	Opcoes:"
echo
echo "	1.  Instalar servidor completo (AD + File Server + Sawtool)"
echo "	2.  Somente SAWTOOL"
echo
echo "================================================"
echo "Digite a opcao desejada:"
echo ""
echo ""
read x
echo "Op��o informada ($x)"
echo "================================================"

case "$x" in


    1)
obterinfo
;;

    2)
installsawtool
;;

esac
done

}

clear
echo -e "carregando..."
DEBIAN_FRONTEND=noninteractive
export DEBIAN_FRONTEND
apt-get install figlet -qq > /dev/null
clear
figlet -c "Samba4"
figlet -c "SAWTOOL 1.0"
echo ""
echo ""
echo ""
echo ""
sleep 15
clear

		echo -e "VOCE DESEJA INSTALAR O SAMBA4 ? s/n "
		read resposta

		if [ $resposta = "s" ];
		then
		clear
		menuinstall
		else
		exit
		fi
