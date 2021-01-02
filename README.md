# Vanitygen plus plus
Vanity address generator for BTC, ETH, LTC, etc (more than 100 crypto currencies).

# Build
Intall building dependencies in Redhat/CentOS:
```
$ yum install openssl-devel
$ yum install libcurl-devel
```

Build executable file:
```
$ make          # build: vanitygen++ keyconv
$ make all      # build: vanitygen++ keyconv oclvanitygen++ oclvanityminer
```

# Usage
List all supported crypto currencies:
```
$ ./vanitygen++ -C LIST
ETH : Ethereum : 0x
BTC : Bitcoin : 1
LTC : Litecoin : L
...... (skip many output)
```

Generate BTC vanity address:
```
$ ./vanitygen++ 1Love
Difficulty: 4476342
[1.35 Mkey/s][total 885248][Prob 17.9%][50% in 1.6s]
Pattern: 1Love
Address: 1Love1ZYE2nzXGibw9rtMCPq2tmg2qLtfx
Privkey: 5KDnavUAswEzQDYY1sAwKPVMUZhZh5hhyS2MnZs8q6SEsQMk2k4
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

# Credit
Many thanks to following projects:
1. https://github.com/samr7/vanitygen
2. https://github.com/exploitagency/vanitygen-plus
3. https://github.com/kjx98/vanitygen-eth

# Known Issue
1. oclvanitygen++ (GPU version) can't find vanity ETH address start with 0x00.
2. ETH vanity address difficulty estimation is **always** for case-insensative searching.

# Next Work
1. Support split-key vanity address.

# License
GNU Affero General Public License
