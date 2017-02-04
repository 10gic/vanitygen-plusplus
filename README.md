<pre>
Vanitygen plus!

Forked from samr7/vanitygen ,
then modified by Corey Harding with the following changes:

+Generate vanity addresses for 50+ coins!
+I also removed the prefix length limit, now capable of searching for a whole address.
So technically this is capable of brute forcing a complete address if you have trillions of years to waste.
+Manually merge changes from: https://github.com/cryptapus For -Y privkey values
+Manually merge changes from: https://github.com/elichai For keyconv decrypt
+Manually merge changes from: https://github.com/salfter For compressed key support
+Manually merge changes from: https://github.com/WyseNynja For oclvanityminer updates

WARNING! This program has not been thoroughly tested.  Please attempt importing an address first.
Send a tiny amount you don't mind losing to the address.  Then perform a test spend.
I will not be held liable for lost funds as a result of the use of this program.
Also do not use this program for nefarious purposes!  I do not condone illegal activity.
The chances of actually brute forcing an address is nearly impossible anyways.

Be sure to report any issues or bugs and fixes, I am happy to accept pull requests!

------
Getting Started
------

Requires libssl1.0-dev
"apt-get install libssl1.0-dev"

The first thing to do is install the required packages then run:
"make all"

A 64 bit Debian binary is also included.

NOTE: All arguments are case sensitive!

Now get a list of the alt-coins with: "./oclvanitygen -C LIST"

Choose your coin.

"./oclvanitygen -C LBRY -o results.txt -k bTEST"
"-C LBRY" : Chooses the LBRY alt-coin
"-o results.txt" : saves the matches to results.txt
"-k" : keep going even after match is found
"bTEST" : the address you are searching for

Example output:
Pattern: bTEST
Address: bTESTWkCCzPkakWbZTxUWnRSb5VXVyUmU9
Privkey: 6ErCAAcXhe25jGYm94uamfetTPZxR9MfLG1YNkrNEEfUjTDVMmQ

------
Encrypting and Decrypting a vanitygen private key for altcoins.
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

Current List of Available Alt-Coins for Address Generation
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
CCN : Canacoin : C
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