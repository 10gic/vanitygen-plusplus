<pre>
Vanitygen plus!

Forked from samr7/vanitygen ,
then modified by Corey Harding with the following changes:

+Generate vanity addresses for 50+ coins!
+I also removed the prefix length limit, now capable of searching for a whole address.
So technically this is capable of brute forcing a complete address if you have trillions of years to waste.
+PR From: https://github.com/cryptapus For -Y privkey values
+PR From: https://github.com/elichai For keyconv decrypt
+PR From: https://github.com/salfter For compressed key support

WARNING! This program has not been thoroughly tested.  Please attempt importing an address first.
Send a tiny amount you don't mind losing to the address.  Then perform a test spend.
I will not be held liable for lost funds as a result of the use of this program.
Also do not use this program for nefarious purposes!  I do not condone illegal activity.
The chances of actually brute forcing an address is nearly impossible anyways.

Be sure to report any issues or bugs and fixes, I am happy to accept pull requests!

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
BTC : Bitcoin : 1
TEST : Bitcoin Testnet : m or n
LTC : Litecoin : L
LBRY : LBRY : b
NMC : Namecoin : M or N
DOGE : Dogecoin : D
DASH : Dash Pay : X
PPC : Peercoin : P
FTC : Feathercoin : 6 or 7
BLK : Blackcoin : B
MZC : Mazacoin : M
VIA : Viacoin : V
RBY : Rubycoin : R
GRS : Groestlcoin : F
DGC : Digitalcoin : D
CCN : Canacoin : C
DGB : Digibyte : D
MONA : Monacoin : M
CLAM : Clamcoin : x
XPM : Primecoin : A
NEOS : Neoscoin : S
JBS : Jumbucks : J
ZRC : Ziftrcoin : Z
VTC : Vertcoin : V
MUE : Monetary Unit : 7
ZOOM : Zoom coin : i
VPN : Vpncoin : V
CDN : Canadaecoin : C
SDC : Shadowcoin : S
PKB : Parkbyte : P
PND : Pandacoin : P
START : Startcoin : s
GCR : Global Currency Reserve : G
NVC : Novacoin : 4
AC : Asiacoin : A
BTCD : Bitcoin Dark : R
DOPE : Dopecoin : 4
TPC : Templecoin : T
AIB : Advanced Internet Block by IOBOND : A
OK : OK Cash : P
DOGED : Doge Dark Coin : D
EFL : Electronic-Gulden-Foundation : L
POT : Potcoin : P
OMC : Omnicoin : o
ANC : Anoncoin : A
CNC : Chinacoin : C
IXC : Ixcoin : x
NYAN : Nyancoin : K
RDD : Reddcoin : R
PTC : Pesetacoin : K
YAC : Yacoin : Y
BQC : BBQcoin : b

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