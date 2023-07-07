package pcr

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"math/rand"
	"time"
	bloom "bhwmonitoring-go/bloom"
	elgamal "bhwmonitoring-go/elgamal"
	"io/ioutil"
	"math/big"
	"sync"
	"math/bits"
	"os"
	"fmt"
	"errors"
)


type ReqPara struct {
	Params int
	BfLength int
	BfNumOnes int
	NumHashFuncs int
	NumThreads int
	PointCompression bool
}

type QueryMessage struct {
	BfLength int
	BfNumOnes int
	NumHashFuncs int
	NumThreads int
	PointCompression bool
	PK *elgamal.PublicKey
	EBF []*elgamal.CiphertextByte
	ZKPs []*elgamal.ZKPByte
	Challenge []byte
}

type QueryMessagePlus struct {
	BfLength int
	BfNumOnes int
	NumHashFuncs int
	NumThreads int
	PointCompression bool
	PK *elgamal.PublicKey
	EBF []*elgamal.CiphertextByte
	C1 *elgamal.CiphertextByte
}

type ResponseMessage struct {
	Z1 *elgamal.CiphertextByte
	Z2 *elgamal.CiphertextByte
}

var mutex sync.Mutex

func GetBFNumOnes(bf *bloom.BloomFilter) int {
	bfGob, _ := bf.GobEncode()
	currNumOnes := 0
	for i := 0; i < int(bf.Cap()/8); i++  {
		currNumOnes += bits.OnesCount(uint(bfGob[24 + i]))
	}
	return currNumOnes
}

func ReqBFGen(pk *elgamal.PublicKey, reqPara *ReqPara, pwd string) *bloom.BloomFilter {

	hashedPWD := elgamal.HashSha256([]byte(pwd))

	bf := bloom.New(uint(reqPara.BfLength), uint(reqPara.NumHashFuncs))
	bf.Add(hashedPWD)


	bfGob, _ := bf.GobEncode()

	// To be optimized
	randBits := []byte{1, 2, 4, 8, 16, 32, 64, 128}

	rand.Seed(time.Now().UnixNano())
	for i := 0; GetBFNumOnes(bf) < reqPara.BfNumOnes ; i++ {
		randBit := randBits[rand.Intn(len(randBits))]
		randBFByteIdx := 24 + rand.Intn(reqPara.BfLength/8) // BloomFilter struct has 24 bits of parameters before BF bits
		bfGob[randBFByteIdx] = bfGob[randBFByteIdx] | randBit
		bf.GobDecode(bfGob)
	}
	// fmt.Println(GetBFNumOnes(bf), bfGob, bf.K())
	return bf
}

func ReqInit(params int, bfLength int, bfNumOfOnes int, numHashFuncs, numWorkers int, pointCompression bool) (*elgamal.PublicKey, *elgamal.SecretKey, *ReqPara) {
	pk, sk := elgamal.KeyGen(params, pointCompression)
	reqPara := &ReqPara{params, bfLength, bfNumOfOnes, numHashFuncs, numWorkers, pointCompression}

	return pk, sk, reqPara
}

func QueryGen(pk *elgamal.PublicKey, reqPara *ReqPara, bf *bloom.BloomFilter) *QueryMessage {

	var reqGen sync.WaitGroup
	bf2encrypt := make([]*big.Int, reqPara.BfLength)

	for i := 0; uint(i) < bf.Cap(); i++ {
		bfIndex := []uint64{uint64(i)}
		if bf.TestLocations(bfIndex) {
			bf2encrypt[i] = big.NewInt(1)
		} else {
			bf2encrypt[i] = big.NewInt(-1)
		}
	}

	ebf, zkps, challenge := pk.EncryptSeqWithZKP(bf2encrypt, reqPara.NumThreads)
	ebfBytes := make([]*elgamal.CiphertextByte, len(ebf))
	zkpsBytes := make([]*elgamal.ZKPByte, len(ebf))

	chWorker := make(chan int, reqPara.NumThreads)
	defer close(chWorker)

	for i, _ := range ebf {
		chWorker <- 1
		reqGen.Add(1)
		go func(i int) {
			defer reqGen.Done()
			ebfBytes[i] = pk.Ciphertext2Bytes(ebf[i], reqPara.PointCompression)
			zkpsBytes[i] = pk.ZKP2Bytes(zkps[i], reqPara.PointCompression)
			<- chWorker
		}(i)
		
	}
	reqGen.Wait()

	queryMessage := &QueryMessage{reqPara.BfLength, reqPara.BfNumOnes, reqPara.NumHashFuncs, reqPara.NumThreads, reqPara.PointCompression, pk, ebfBytes, zkpsBytes, challenge.Bytes()}

	return queryMessage
}

func RespDeployment(queryMessage *QueryMessage) *QueryMessagePlus {
	
	var respDep sync.WaitGroup

	pk := queryMessage.PK
	pk.InitCurve()

	ebfBytes := queryMessage.EBF
	zkpsBytes := queryMessage.ZKPs
	ebf := make([]*elgamal.Ciphertext, len(ebfBytes))
	zkps := make([]*elgamal.ZKP, len(ebfBytes))
	challenge := big.NewInt(1).SetBytes(queryMessage.Challenge)

	chWorker := make(chan int, queryMessage.NumThreads)
	defer close(chWorker)

	for i := range ebfBytes {
		chWorker <- 1
		respDep.Add(1)
		go func(i int) {
			defer respDep.Done()
			ebf[i] = pk.Bytes2Ciphertext(ebfBytes[i], queryMessage.PointCompression)
			zkps[i] = pk.Bytes2ZKP(zkpsBytes[i], queryMessage.PointCompression)
			<- chWorker
		}(i)
		
	}
	respDep.Wait()

	if !pk.VerifySeqZKP(ebf, zkps, challenge, queryMessage.NumThreads) {
		err := errors.New("Invalid ZKP!")
		fmt.Println(err)
		os.Exit(-1)
	}

	encInvSum := pk.Encrypt(big.NewInt(int64(queryMessage.BfLength-2*queryMessage.BfNumOnes)))

	resCT := pk.Encrypt(big.NewInt(0))
	for _, ebit := range ebf {
		resCT = pk.Add(resCT, ebit, false)
	}
	resCT = pk.Add(resCT, encInvSum, false)

	c1 := pk.Ciphertext2Bytes(resCT, queryMessage.PointCompression)
	queryMessagePlus := &QueryMessagePlus{queryMessage.BfLength, queryMessage.BfNumOnes, queryMessage.NumHashFuncs, queryMessage.NumThreads, queryMessage.PointCompression, queryMessage.PK, queryMessage.EBF, c1}
	return queryMessagePlus
}


func ResponseGen(sk *elgamal.SecretKey, queryMessagePlus *QueryMessagePlus, submittedPWD string) *ResponseMessage {

	var respGen sync.WaitGroup

	pk := queryMessagePlus.PK
	pk.InitCurve()

	hashedPWD := elgamal.HashSha256([]byte(submittedPWD))
	encHashedPWD := pk.EncryptMul([]byte(submittedPWD))

	bf := bloom.New(uint(queryMessagePlus.BfLength), uint(queryMessagePlus.NumHashFuncs))
	bf.Add(hashedPWD)

	chWorker := make(chan int, queryMessagePlus.NumThreads)
	defer close(chWorker)

	chRes := make(chan *elgamal.Ciphertext, queryMessagePlus.NumThreads)
	defer close(chRes)

	taskUnit := int(bf.Cap())/int(queryMessagePlus.NumThreads)

	for t := 0; t < queryMessagePlus.NumThreads; t++ {
		chWorker <- 1
		respGen.Add(1)
		if (t < queryMessagePlus.NumThreads - 1) {
			go func(start, end int) {
				defer respGen.Done()
				encRes := pk.Encrypt(big.NewInt(0))
				for i := start; i < end; i++ {
					bfIndex := []uint64{uint64(i)}
					if bf.TestLocations(bfIndex) {
						encNegOne := pk.Encrypt(big.NewInt(-1))
						encShouldBeZero := pk.Add(encNegOne, pk.Bytes2Ciphertext(queryMessagePlus.EBF[i], queryMessagePlus.PointCompression), false)
						encShouldBeZero = pk.ScalarMultRandomizer(encShouldBeZero, false)
						encRes = pk.Add(encRes, encShouldBeZero, false)
					} 
				}
				chRes <- encRes
				<- chWorker
			}(t * taskUnit, (t + 1) * taskUnit)
		} else {
			go func(start, end int) {
				defer respGen.Done()
				encRes := pk.Encrypt(big.NewInt(0))
				for i := start; i < end; i++ {
					bfIndex := []uint64{uint64(i)}
					if bf.TestLocations(bfIndex) {
						encNegOne := pk.Encrypt(big.NewInt(-1))
						encShouldBeZero := pk.Add(encNegOne, pk.Bytes2Ciphertext(queryMessagePlus.EBF[i], queryMessagePlus.PointCompression), false)
						encShouldBeZero = pk.ScalarMultRandomizer(encShouldBeZero, false)
						encRes = pk.Add(encRes, encShouldBeZero, false)
					} 
				}
				chRes <- encRes
				<- chWorker
			}(t * taskUnit, int(bf.Cap()))
		}
	
	}
	respGen.Wait()

	c2 := pk.Encrypt(big.NewInt(0))
	go func() {
		for ciphertext := range chRes {
			c2 = pk.Add(c2, ciphertext, false)
		}
	}()
	
	
	c1 := pk.Bytes2Ciphertext(queryMessagePlus.C1, queryMessagePlus.PointCompression)
	c1 = pk.ScalarMultRandomizer(c1, false)
	c1PLUSc2 := pk.Add(c1, c2, false)

	z1 := pk.Ciphertext2Bytes(pk.ScalarMultRandomizer(c1PLUSc2, false), queryMessagePlus.PointCompression)
	z2 := pk.Ciphertext2Bytes(pk.Add(c1PLUSc2, encHashedPWD, false), queryMessagePlus.PointCompression)
	responseMessage := &ResponseMessage{z1, z2}
	return responseMessage
}

func ResponseDecrypt(pk *elgamal.PublicKey, sk *elgamal.SecretKey, reqPara *ReqPara, responseMessage *ResponseMessage, bf *bloom.BloomFilter) (success bool, result []byte) {

	if sk.DecryptAndCheck0(pk.Bytes2Ciphertext(responseMessage.Z1, reqPara.PointCompression)) {
		pt := sk.Decrypt(pk.Bytes2Ciphertext(responseMessage.Z2, reqPara.PointCompression))
		if bf.Test(elgamal.HashSha256([]byte(pt)))  {
			return true, pt
		} else {
			return false, []byte("Responder is cheating!")
		}
		
	} else {
		return false, []byte("")
	}
	
}


// This function encodes a query message struct into bytes.
func EncodeQuery(queryMessage *QueryMessage) []byte {

	queryMessageJson, _ := json.Marshal(*queryMessage)

	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, err := w.Write(queryMessageJson)
	err = w.Close()
	if err != nil {
		panic(err)
	}
	msg := []byte(b.String())

	return msg
}


// This function decodes a query message in bytes back to struct.
func DecodeQuery(queryMessageBytes []byte) *QueryMessage {

	var queryMessage QueryMessage

	r, err := gzip.NewReader(bytes.NewBuffer(queryMessageBytes))
	if err != nil {
		panic(err)
	}
	jsonQM, err := ioutil.ReadAll(r)
	err = r.Close()
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(jsonQM, &queryMessage)
	err = r.Close()
	if err != nil {
		panic(err)
	}

	return &queryMessage
}


// This function encodes a response message struct to bytes.
func EncodeResponse(responseMessage *ResponseMessage) []byte {

	responseMessageJson, _ := json.Marshal(*responseMessage)
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, err := w.Write(responseMessageJson)
	err = w.Close()
	if err != nil {
		//fmt.Println("gzip error occurred!!!")
		panic(err)
	}
	msg := []byte(b.String())

	return msg
}

// This function decodes a response message in bytes to struct.
func DecodeResponse(responseMessageBytes []byte) *ResponseMessage {

	var responseMessage ResponseMessage

	r, err := gzip.NewReader(bytes.NewBuffer(responseMessageBytes))
	if err != nil {
		panic(err)
	}
	jsonRM, err := ioutil.ReadAll(r)
	err = r.Close()
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(jsonRM, &responseMessage)
	if err != nil {
		panic(err)
	}

	return &responseMessage
}