# Vanitygen plus plus
Vanity address generator for BTC, ETH, etc.

# Build
Run:
```
$ make          # build: vanitygen++ keyconv
$ make all      # build: vanitygen++ keyconv oclvanitygen++ oclvanityminer
```

# Usage
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

# Credit
Many thanks to following projects:
1. https://github.com/samr7/vanitygen
2. https://github.com/exploitagency/vanitygen-plus
3. https://github.com/kjx98/vanitygen-eth

# Known Issue
1. ETH vanity address difficulty estimation is **always** for case-insensative searching.

# Next Work
1. Support split-key vanity address.

# License
GNU Affero General Public License
