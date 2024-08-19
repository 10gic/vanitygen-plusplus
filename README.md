# Vanitygen plus plus
Vanity address generator for BTC, ETH, LTC, TRX etc (more than 100 crypto currencies).

# Usage
List all supported crypto currencies:
```
$ ./vanitygen++ -C LIST
ETH : Ethereum : 0x
BTC : Bitcoin : 1
LTC : Litecoin : L
...... (skip many output)
```

Generate BTC vanity address (legacy):
```
$ ./vanitygen++ 1Love
Difficulty: 4476342
[1.35 Mkey/s][total 885248][Prob 17.9%][50% in 1.6s]
Pattern: 1Love
Address: 1Love1ZYE2nzXGibw9rtMCPq2tmg2qLtfx
Privkey: 5KDnavUAswEzQDYY1sAwKPVMUZhZh5hhyS2MnZs8q6SEsQMk2k4
```

Generate BTC vanity address (native witness):
```
$ ./vanitygen++ -F p2wpkh bc1qqqq
Pattern: bc1qqqq
BTC Address: bc1qqqqlp27ga4awzu67r5ffn8w6ku5k2wve35453a
BTC Privkey (hex): 04eff710d1cc965f5ae9d4918af24d6900e86fbb8ae802acc19134b2e442f3af
```

Generate BTC vanity address (taproot):
```
$ ./vanitygen++ -F p2tr bc1pppp
Pattern: bc1pppp
BTC Address: bc1pppphk840d8etdgav2xm3yvkz4me86cnm3cmzcthhqd6a3nda8e4qx6kfh7
BTC Privkey (hex): f6a4665fcf77e9e83085aa473757b7550e93261e58ec2bd3f8cda8ea42e3efb9
```

Generate ETH vanity address:
```
$ ./vanitygen++ -C ETH 0x999999
Generating ETH Address
Difficulty: 16777216
[1.38 Mkey/s][total 2392064][Prob 13.3%][50% in 6.7s]
ETH Pattern: 0x999999
ETH Address: 0x999999987AB952f1C634D9dd6e0596659B80D0f8
ETH Privkey: 0x2c61eafe9c95314f8bc8ec0fb2f201d04337dd53b3f7484b46149862d0550c47
```

Generate ETH vanity contract address:
```
$ ./vanitygen++ -C ETH -F contract 0x999999
Generating ETH Address
Difficulty: 16777216
[1.38 Mkey/s][total 2392064][Prob 13.3%][50% in 6.7s]
ETH Pattern: 0x999999
ETH Address: 0x999999188b45BcfA499Ff1bDc041eE21cc890B16
ETH Privkey: 0xdb3813534c0c9595f9b8b35d6f544827065b33930ae42c38a9d7ce41a1d74669
```

If you have OpenCL-compatible GPU, please use `oclvanitygen++`, it's faster.

# Build
## Method 1: Install dependencies manually
Step 1: Install dependencies

On Redhat/CentOS:
```
$ yum install openssl-devel
$ yum install libcurl-devel
```

On Ubuntu:
```
$ apt install build-essential
$ apt install libssl-dev
$ apt install libpcre3-dev
$ apt install libcurl4-openssl-dev
```

On MacOS:
```
$ brew install openssl@3
$ brew install pcre
```

Step 2: Build executable file:
```
$ make          # build: vanitygen++ keyconv
$ make all      # build: vanitygen++ keyconv oclvanitygen++ oclvanityminer
```

## Method 2: Install dependencies automatically (nix-build)
You need install nix-build firstly, for more information please visit: https://nixos.org/manual/nix/stable/installation/installing-binary.html

After you install nix-build successfully, just run:
```
$ git clone https://github.com/10gic/vanitygen-plusplus.git
$ cd vanitygen-plusplus
$ nix-build                           # Build: vanitygen++ oclvanitygen++ keyconv oclvanityminer
$ ./result/bin/vanitygen++ 1Love      # Executable files are stored at ./result/bin/
Pattern: 1Love
Address: 1Love3h1c5qd9ZRoDKkCLSeWfBKR5MTF7t
Privkey: 5JYtyNYLTRX3dvpN5PCiYF1AKFnETmgBLukCNgfkoBjDHZ2yJp1
```

# Solve Puzzle
This tool can be used for solving the [Bitcoin puzzle](https://bitcointalk.org/index.php?topic=1306983.0).

For example, solve puzzle 6:
```
$ ./vanitygen++ -F compressed -Z 0000000000000000000000000000000000000000000000000000000000000000 -l $((256-6)) 1PitScNLyp2HCygzad
Difficulty: 376259307977702824629384382540
Pattern: 1PitScNLyp2HCygzad
Address: 1PitScNLyp2HCygzadCh7FveTnfmpPbfp8
Privkey: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU7Tmu6qHxS
```

Solve puzzle 20:
```
$ ./vanitygen++ -F compressed -Z 0000000000000000000000000000000000000000000000000000000000000000 -l $((256-20)) 1HsMJxNiV7TLxmoF6u
Difficulty: 376259307977702824629384382540
Pattern: 1HsMJxNiV7TLxmoF6u
Address: 1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum
Privkey: KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rHfuE2Tg4nJW
```

# Split-key Vanity Address Generation
This tool supports [split-key](https://en.bitcoin.it/wiki/Split-key_vanity_address) vanity address generation.

Step 1, Alice generates a key pair on her computer:
```shell
$ ./keyconv -G
Pubkey (hex): 044a9fef408ec4db7e264c8f1bfc712a9f6089025bd1980660f7f72c731b7d4c6a6fa5e0fe2174aaa02fffb6ed4a5735fc3109bae2fefe060d8a09bdb8f819f38b
Privkey (hex): B6761A9A575C3C125F24B09A7ADB5F3613BB654F73ADB7097657D737FCD1C310
Address: 1AF518xd1zBNCQh2q1qsneaxAs5nPyXzNf
Privkey: 5KCeK2bzDq2YzUMfwUrNp79mEsk2eeY1dzYtCTTxEgbbFav8RtA
```
Then, Alice send the generated public key and the wanted prefix (for example `1ALice`) to Bob. Nevertheless, Alice has to keep safely the private key and not expose it.

Step 2, Bob runs vanitygen++ (or oclvanitygen++) using the Alice's public key and the wanted prefix (`1ALice`).
```shell
$ ./vanitygen++ -P 044a9fef408ec4db7e264c8f1bfc712a9f6089025bd1980660f7f72c731b7d4c6a6fa5e0fe2174aaa02fffb6ed4a5735fc3109bae2fefe060d8a09bdb8f819f38b 1ALice
Difficulty: 259627881
Pattern: 1ALice
Address: 1ALicexPg59dVvYgtAP8QCphdrFep6nRwy
PrivkeyPart: 5KAuZAyz71TFwgDpiBPyMJX6YFxKyJEJDsr2tNr8uraw6JLBMpQ
```
Bob sends back the generated PrivkeyPart to Alice. The partial private key does not allow anyone to guess the final Alice's private key.

Step 3, Alice reconstructs the final private key using her private key (the one generated in step 1) and the PrivkeyPart from Bob:
```shell
$ ./keyconv -c 5KAuZAyz71TFwgDpiBPyMJX6YFxKyJEJDsr2tNr8uraw6JLBMpQ 5KCeK2bzDq2YzUMfwUrNp79mEsk2eeY1dzYtCTTxEgbbFav8RtA
Address: 1ALicexPg59dVvYgtAP8QCphdrFep6nRwy
Privkey: 5JcX7HgrPxEbYKcWhtBT83L3BHcdJ8K8p8X1sNHmcJLsSyMNycZ
```

## How Split-key Works
See the explanation in another similar [project](https://github.com/JeanLucPons/VanitySearch#how-it-works).

# Credit
Many thanks to following projects:
1. https://github.com/samr7/vanitygen, see https://bitcointalk.org/index.php?topic=25804.0
2. https://github.com/exploitagency/vanitygen-plus (now it's 404)
3. https://github.com/kjx98/vanitygen-eth

# Known Issue
1. oclvanitygen++ (GPU version) can't find vanity ETH address start with 0x00.
2. ETH vanity address difficulty estimation is **always** for case-insensitive searching.

# License
GNU Affero General Public License

# Donate
I don't have much time to maintain this project, donations will encourage me to keep going.
1. BTC: 123456WcsbL1NRiU2H3jNSSDEp3q8M9u8t
2. ETH: 0x123456E35147E215FBec2A1B4502C7Cf6Ecb62cD
