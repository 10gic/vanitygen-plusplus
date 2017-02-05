<pre>
Vanitygen plus!

Forked from samr7/vanitygen ,
then modified by Corey Harding
to support Many Alt-Coins!
with the following changes:

+Generate vanity addresses for 70+ coins!
+I also removed the prefix length limit, now capable of searching for a whole address.
So technically this is capable of brute forcing a complete address if you have trillions of years to waste.
+Manually merge changes from: cryptapus For -Y privkey values
+Manually merge changes from: elichai For keyconv decrypt
+Manually merge changes from: salfter For compressed key support
+Manually merge changes from: WyseNynja For oclvanityminer updates
+Manually merge changes from: Rytiss For Initialize bn_zero to allow Intel CPU OpenCL compilation
+Manually merge changes from: fizzisist For Document -P option
+Manually merge changes from: bitkevin For fix hd 68/69xx, 7xxx 

WARNING! This program has not been thoroughly tested.  Please attempt importing an address first.
Send a tiny amount you don't mind losing to the address.  Then perform a test spend.
I will not be held liable for lost funds as a result of the use of this program.
Also do not use this program for nefarious purposes!  I do not condone illegal activity.
The chances of actually brute forcing an address is nearly impossible anyways.

Be sure to report any issues or bugs and fixes, I am happy to accept pull requests!
If you have an altcoin you would like to add please let me know.

------
Getting Started
------
See this link for more detailed instructions on compiling from source:
https://legacysecuritygroup.com/index.php/projects/recent/12-software/35-oclvanitygen-compiling-and-use

A Linux binary is included. (Compiled on 64bit Debian Testing)

NOTE: All arguments are case sensitive!
Using GPU(oclvanitygen) requires correct drivers be installed openCL and appropriate dependencies.
See above link for list of said dependencies for oclvanitygen.
This may take some fiddling depending on your distro.
Link above works for Kali Rolling and can be adopted for other distros.
If using CPU only the guide below should suffice.

Downloading:
apt-get install git
git clone https://github.com/exploitagency/vanitygen-plus.git
cd vanitygen-plus
cd linux-binary

Now get a list of the Coins with:
./vanitygen -C LIST

Choose your coin.

"./vanitygen -C LBRY -o results.txt -k bTEST"
"-C LBRY" : Chooses the LBRY coin
"-o results.txt" : saves the matches to results.txt
"-k" : keep going even after match is found
"bTEST" : the address you are searching for

Example output:
Pattern: bTEST
Address: bTESTWkCCzPkakWbZTxUWnRSb5VXVyUmU9
Privkey: 6ErCAAcXhe25jGYm94uamfetTPZxR9MfLG1YNkrNEEfUjTDVMmQ
------
END Getting Started
------

-------
Fix libcrypto.so.1.0.2 error(Debian, Ubuntu)
-------
./vanitygen: error while loading shared libraries: libcrypto.so.1.0.2: cannot open shared object file: No such file or directory

wget http://ftp.us.debian.org/debian/pool/main/g/glibc/libc6-udeb_2.24-9_amd64.udeb
dpkg -i libc6-udeb_2.24-9_amd64.udeb
wget http://ftp.us.debian.org/debian/pool/main/o/openssl1.0/libcrypto1.0.2-udeb_1.0.2k-1_amd64.udeb
dpkg -i libcrypto1.0.2-udeb_1.0.2k-1_amd64.udeb
rm libc6-udeb_2.24-9_amd64.udeb
rm libcrypto1.0.2-udeb_1.0.2k-1_amd64.udeb
-------
END Fix libcrypto.so.1.0.2 error(Debian, Ubuntu)
-------

------
Encrypting and Decrypting a vanitygen private key
------

./vanitygen -C AC Aa -E 5
"-C AC Aa" Choose coin AC and address prefix "Aa"
"-E 5" Encrypt key with password as "5",
more secure to use option "-e" with no trailing password,
then vanitygen prompts for a password so theres no command history.

Generating AC Address
Difficulty: 23
Estimated password crack time: >1 seconds
WARNING: Password contains only numbers
WARNING: Protecting private keys with weak password
Pattern: Aa                                                                    
Address: Aa853vQs6QGrTuTHb7Q45tbeB8n4EL47vd
Protkey: yTYFUWAsgFmMxCbKtu3RdrrJXosZrjxiQFA2o43neB4jPpfLe5owNNrteTs8mpvua8Ge

Now refer to the list address-x-y-value-for-keyconv.txt and pick your -X and -Y values.
Ticker 	: Coin 			: Address Prefix 	: -X Value 	: -Y Value
---------------
AC 	: Asiacoin 		: A			: 23	<---	: 151 <---
For AC(Asiacoin) these values are 23 and 151.

./keyconv -X 23 -Y 151 -d yTYFUWAsgFmMxCbKtu3RdrrJXosZrjxiQFA2o43neB4jPpfLe5owNNrteTs8mpvua8Ge
"-X 23 -Y 151" Specifies coin configuration
"-d" for decrypt and protected key of "yTYFUWAsgFmMxCbKtu3RdrrJXosZrjxiQFA2o43neB4jPpfLe5owNNrteTs8mpvua8Ge"
Enter import password: 5 <--- Enter "5" or whatever you specified as password and press enter
Address: Aa853vQs6QGrTuTHb7Q45tbeB8n4EL47vd
Privkey: 66GRP2W5H4sWbgrBRAuPc3qZxUtP5boubJ9N2M5wZio6fhWjzbr
------
END Encrypting and Decrypting a vanitygen private key
------

If you found this repo useful, please consider a donation.  Thank You!
Donate Bitcoin: 1egacySQXJA8bLHnFhdQQjZBLW1gxSAjc
Donate Zcash or Zclassic: t1egacynGZDT9mTfmMSCG1yCaedq7bGTs1a
Z-Address: zcashPngjXyQJUjePXH6wvg2vfHHngaZiYLmmDE2bp3PqMAPpErdfpbctug78P6m8xqKXyxX1dmfCYoUeJYfX8hDLSueuKL
Donate Ethereum or Ethereum Classic: 0x1337aeb726eee1a51fc3b22a7eafa329d950297a
Donate LBRY: bLEGACYsaVR11r9qp6bXnWeWtpf7Usx9rX
Donate Litecoin: LegacyeBuSwLaZaF5QLMiJL8E4rNCH6tJ7
Donate Namecoin: N1egacyRAKumMKiFaVrTqwzmdkJVL9mNDs
Donate Feathercoin: 71egacyuSdmPUMM3EKp4dw8yBgTruKhKZc
Donate Vertcoin: Vry1337ZVSFftzLWvBkEhf787HAXAqyupJ

Current List of Available Coins for Address Generation
---------------------------------------------------
Argument(UPPERCASE) : Coin : Address Prefix
---------------
AC : Asiacoin : A
AIB : Advanced Internet Block by IOBOND : A
ANC : Anoncoin : A
ARS : Arkstone : A
AUR : Auroracoin : A
BLK : Blackcoin : B
BQC : BBQcoin : b
BTC : Bitcoin : 1
TEST : Bitcoin Testnet : m or n
BTCD : Bitcoin Dark : R
CCN : Cannacoin : C
CDN : Canadaecoin : C
CLAM : Clamcoin : x
CNC : Chinacoin : C
CON : PayCon : P
DASH : Dash Pay : X
DGB : Digibyte : D
DGC : Digitalcoin : D
DOGED : Doge Dark Coin : D
DOGE : Dogecoin : D
DOPE : Dopecoin : 4
EFL : Electronic-Gulden-Foundation : L
EXCL : Exclusivecoin : E
FAIR : Faircoin2 : f
FLOZ : FLOZ : F
FTC : Feathercoin : 6 or 7
GCR : Global Currency Reserve : G
GRC : GridcoinResearch : R or S
GRS : Groestlcoin : F
HODL : HOdlcoin : H
IXC : Ixcoin : x
JBS : Jumbucks : J
LBRY : LBRY : b
LEAF : Leafcoin : f
LTC : Litecoin : L
MMC : Memorycoin : M
MONA : Monacoin : M
MUE : Monetary Unit : 7
MYRIAD : Myriadcoin : M
MZC : Mazacoin : M
NEOS : Neoscoin : S
NLG : Gulden : G
NMC : Namecoin : M or N
NVC : Novacoin : 4
NYAN : Nyancoin : K
OK : OK Cash : P
OMC : Omnicoin : o
PKB : Parkbyte : P
PND : Pandacoin : P
POT : Potcoin : P
PPC : Peercoin : P
PTC : Pesetacoin : K
PTS : Protoshares : P
RBY : Rubycoin : R
RDD : Reddcoin : R
RIC : Riecoin : R
SDC : Shadowcoin : S
SKC : Skeincoin : S
START : Startcoin : s
SXC : Sexcoin : R or S
TPC : Templecoin : T
UIS : Unitus : U
UNO : Unobtanium : u
VIA : Viacoin : V
VPN : Vpncoin : V
VTC : Vertcoin : V
WDC : Worldcoin Global : W
WUBS : Dubstepcoin : D
XC : XCurrency : X
XPM : Primecoin : A
YAC : Yacoin : Y
ZOOM : Zoom coin : i
ZRC : Ziftrcoin : Z

If you found this repo useful, please consider a donation.  Thank You!

Donate Bitcoin: 1egacySQXJA8bLHnFhdQQjZBLW1gxSAjc
Donate Zcash or Zclassic: t1egacynGZDT9mTfmMSCG1yCaedq7bGTs1a
Z-Address: zcashPngjXyQJUjePXH6wvg2vfHHngaZiYLmmDE2bp3PqMAPpErdfpbctug78P6m8xqKXyxX1dmfCYoUeJYfX8hDLSueuKL
Donate Ethereum or Ethereum Classic: 0x1337aeb726eee1a51fc3b22a7eafa329d950297a
Donate LBRY: bLEGACYsaVR11r9qp6bXnWeWtpf7Usx9rX
Donate Litecoin: LegacyeBuSwLaZaF5QLMiJL8E4rNCH6tJ7
Donate Namecoin: N1egacyRAKumMKiFaVrTqwzmdkJVL9mNDs
Donate Feathercoin: 71egacyuSdmPUMM3EKp4dw8yBgTruKhKZc
Donate Vertcoin: Vry1337ZVSFftzLWvBkEhf787HAXAqyupJ
</pre>