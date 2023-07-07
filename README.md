# bhwmonitoring-go

This is a Go implementation of the monitoring protocol proposed in the paper "[_Bernoulli Honeywords_]()" (NDSS '24, to appear). Currently, 
this implementation is for purpose of performance evaluation only.

### Performance Evaluation

_performance.go_ can be used to show average message sizes and computation times over a specified number of runs.

Run experiments with default parameters:

```Golang
go run performance.go
```

or run experiments with specified parameters. For example,

``` Golang
go run performance.go keyLength=256 -BFLength=128 -numHFs=20 -numOnes=30 -numThreads=1 -enablePC -numRounds=50 -monitorInput="Simba"
```

Parameters:
* -keyLength=256: the key length of the underlying ECC-ElGamal is 256 bits. Other options include 224, 384, and 512. (Default: 256)
* -BFLength=128: the size of the underlying Bloom filter is 128. (Default: 128)
* -numHFs=20: 20 hash functions are used to construct a Bloom filter (denoted by _k_ in the paper). (Default: 20)
* -numOnes=30: There are 30 "1"s in the Bloom filter (which depends on the choice of $p_h$ in the paper). (Default: 30)
* -numThreads=1: both parties run the protocol with 1 thread. (Default: 1)
* -enablePC: Point compression (specified in section 4.3.6 of ANSI X9.62) for the underlying curve is enabled. (Default: enabled)
* -numRounds=50: 50 rounds are required to produce an evaluation result. (Default: 50)
* -monitorInput="Simba": the monitor/responder/sender's input element. (Default: "Simba")

In _performance.go_, the target's Bloom filter is filled with "Simba" as the user password and some "1"s at some randomly selected positions to reach the specified "numOnes".

### Citation

```latex
@inproceedings {wang2024:bernoullihw,
title = {Bernoulli Honeywords},
author = {Wang, Ke Coby and Reiter, Michael K.},
booktitle = {31\textsuperscript{st} {ISOC} Network and Distributed System Security Symposium},
publisher = {Internet Society},
month = {Feb},
year = {2024}
}
```
