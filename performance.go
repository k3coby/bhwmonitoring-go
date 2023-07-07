package main

import (
	"flag"
	"fmt"
	"runtime"
	pcr "bhwmonitoring-go/pcr"
	util "bhwmonitoring-go/util"
)

func main() {

	//////////////////  ARGUMENTS  /////////////////

	var bfLength, bfNumOfOnes, numHashFuncs int
	var numThreads, params int
	var pointCompression bool
	var pwd2check string
	var maxRounds int

	var allResponderDeploymentTime, allQueryGenTime, allResponseGenTime, allResponseRevealTime []int64
	var allQuerySize, allResponseSize []int

	paramPtr := flag.Int("keyLength", 256, "224, 256, 384 or 512")
	bfLengthPtr := flag.Int("BFLength", 128, "an int")
	bfNumOfOnesPtr := flag.Int("numOnes", 30, "an int")
	numHashFuncsPtr := flag.Int("numHFs", 20, "an int")
	numThreadsPtr := flag.Int("numThreads", 50, "an int")
	pointCompressionPtr := flag.Bool("enablePC", true, "true or false")
	roundsPtr := flag.Int("numRounds", 50, "an int")
	pwd2checkPtr := flag.String("monitorInput", "Simba", "a string")

	flag.Parse()

	params = *paramPtr
	bfLength = *bfLengthPtr
	bfNumOfOnes = *bfNumOfOnesPtr
	numHashFuncs = *numHashFuncsPtr
	numThreads = *numThreadsPtr
	pointCompression = *pointCompressionPtr
	pwd2check = *pwd2checkPtr
	maxRounds = *roundsPtr

	if runtime.NumCPU() <=numThreads {
		numThreads = runtime.NumCPU()
	}

	fmt.Printf("\n==== Experiment Parameters ========\n[OS] # of threads >>> %d/%d\n", numThreads, runtime.NumCPU())
	fmt.Println("[ECC-ElGamal] key length (bits) >>>", params)
	fmt.Println("[ECC-ElGamal] Point compression >>>", pointCompression)
	fmt.Printf("[Target] Bloom filter length >>> %d\n", bfLength)
	fmt.Printf("[Target] # of hash functions >>> %d\n", numHashFuncs)
	fmt.Printf("[Target] # of ones in a Bloom filter >>> %d\n", bfNumOfOnes)


	for i := 0; i < maxRounds; i++ {
		//////////////////  PROTOCOL OFFLINE PHASE  /////////////////

		/*  Requester/Receiver Offline Phase */
		time0 := util.MakeTimestamp()

		
		pk, sk, reqData := pcr.ReqInit(params, bfLength, bfNumOfOnes, numHashFuncs, numThreads, pointCompression) // Key generation and parameter initialization
		bf := pcr.ReqBFGen(pk, reqData, "Simba")

		//////////////////  PROTOCOL ONLINE PHASE  /////////////////

		/*  Requester/Receiver Online Phase I: Query Generation */
		
		queryMessage := pcr.QueryGen(pk, reqData, bf) // Query generation based on input element
		queryMessageBytes:= pcr.EncodeQuery(queryMessage) // Encodes query message into bytes
		queryMessageSize := len(queryMessageBytes) // Gets message size in bytes

		time1 := util.MakeTimestamp()

		/*    Responder/Sender Online Phase I: Response Generation  */
		rcvQueryMessage := pcr.DecodeQuery(queryMessageBytes) // Decodes query message from bytes
		rcvQueryMessagePlus := pcr.RespDeployment(rcvQueryMessage)

		time2 := util.MakeTimestamp()

		responseMessage := pcr.ResponseGen(sk, rcvQueryMessagePlus, pwd2check) // Generates response based on query
		responseMessageBytes := pcr.EncodeResponse(responseMessage) // Encodes response message to bytes
		responseMessageSize := len(responseMessageBytes) // gets response message size in bytes

		time3 := util.MakeTimestamp()

		/*  Requester/Receiver Online Phase II: Response Decryption */
		rcvResponseMessage := pcr.DecodeResponse(responseMessageBytes) // Decodes response message from bytes
		success, result := pcr.ResponseDecrypt(pk, sk, reqData, rcvResponseMessage, bf) // Decrypt response to get the result
		
		time4 := util.MakeTimestamp()


		////////////////////////////////////////////////////////

		queryGenTime := time1 - time0
		responderDeploymentTime := time2 - time1
		responseGenTime  := time3 - time2
		responseRevealTime := time4 - time3

		revealRes := ""
		if success {
			// revealRes = "Positive: " + string(result)
			revealRes = "Positive"
		} else if !success && string(result) == "" {
			revealRes = "Negative"
		} else {
			revealRes = "Cheating Monitor alert!"
		}

		// Report the revealing result for only the last run
		if i == maxRounds - 1 {
			fmt.Println("[PCR] PCR result >>>", revealRes)
		}

	
		allQueryGenTime = append(allQueryGenTime, queryGenTime)
		allResponderDeploymentTime = append(allResponderDeploymentTime, responderDeploymentTime)
		allResponseGenTime = append(allResponseGenTime, responseGenTime)
		allResponseRevealTime = append(allResponseRevealTime, responseRevealTime)
		allQuerySize = append(allQuerySize, int(queryMessageSize))
		allResponseSize = append(allResponseSize, int(responseMessageSize))
	}

	fmt.Printf("==== Mean over %d repeated experiments ===\n", maxRounds)
	fmt.Printf("[Target] queryGen() takes %.2f ms (rstd: %.4f)\n", float32(util.GetAvgInt64(allQueryGenTime))/1000.0, float32(util.GetRelativeStdInt64(allQueryGenTime)))
	fmt.Printf("[Target] Query message size >>> %.2f KB (rstd: %.4f)\n", float32(util.GetAvgInt(allQuerySize))/1000.0, float32(util.GetRelativeStdInt(allQuerySize)))
	fmt.Printf("[Monitor] responderDeployment() takes %.2f ms (rstd: %.4f)\n", float32(util.GetAvgInt64(allResponderDeploymentTime))/1000.0, float32(util.GetRelativeStdInt64(allResponderDeploymentTime)))
	fmt.Printf("[Monitor] responseGen() takes %.2f ms (rstd: %.4f) \n", float32(util.GetAvgInt64(allResponseGenTime))/1000.0, float32(util.GetRelativeStdInt64(allResponseGenTime)))
	fmt.Printf("[Monitor] Response message size >>> %.2f KB (rstd: %.4f)\n", float32(util.GetAvgInt(allResponseSize)) / 1000.0, float32(util.GetRelativeStdInt(allResponseSize)))
	fmt.Printf("[Target] responseReveal() takes %.2f ms (rstd: %.4f) \n", float32(util.GetAvgInt64(allResponseRevealTime))/1000.0, float32(util.GetRelativeStdInt64(allResponseRevealTime)))

}