package util

import (
	"time"
	"strconv"
	"os"
	"bufio"
	"log"
	"fmt"
	"math"
)

func GetElipsedTimeInString(elipsed_time int64) string{
	return strconv.FormatInt(elipsed_time/1000/1000, 10) + "s " +
		strconv.FormatInt(elipsed_time/1000%1000, 10) + "ms " + strconv.FormatInt(elipsed_time%1000, 10) + "us"
}

func GetMsgSizeInString(size_bytes int) string {
	return strconv.Itoa(size_bytes/1024/1024) + "MB " +
		strconv.Itoa(size_bytes/1024%1024) + "KB " + strconv.Itoa(size_bytes%1024) + "B"
}

func MakeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Microsecond)
}

func ReadAddrFromFile(file_path string) (addrs []string) {
	if file, err := os.Open(file_path); err == nil {
		// make sure it gets closed
		defer file.Close()
		// create a new scanner and read the file line by line
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if len(scanner.Text()) == 0 {
				continue
			}
			addrs = append(addrs, scanner.Text())
		}
		// check for errors
		if err = scanner.Err(); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Fatal(err)
	}
	return addrs
}

func CheckError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}

func GetSumInt64(data []int64) int64 {
	//fmt.Println(data)
	sum := int64(0)
	for _, v := range data {
		sum += v
	}
	return sum
}

func GetAvgInt64(data []int64) int64 {
	return int64(GetSumInt64(data)/int64(len(data)))
}

func GetSumInt(data []int) int {
	//fmt.Println(data)
	sum := int(0)
	for _, v := range data {
		sum += v
	}
	return sum
}

func GetAvgInt(data []int) int{
	return int(GetSumInt(data)/int(len(data)))
}

func GetStdInt64(data []int64) float64 {
	var dataDiff []int64
	avg := GetAvgInt64(data)
	for _, v := range data {
		dataDiff = append(dataDiff, (v - avg)*(v - avg))
	}
	sum := GetSumInt64(dataDiff)
	sum /= int64(len(data) - 1)
	return math.Sqrt(float64(sum))
}
func GetStdInt(data []int) float64 {
	var dataDiff []int
	avg := GetAvgInt(data)
	for _, v := range data {
		dataDiff = append(dataDiff, (v - avg)*(v - avg))
	}
	sum := GetSumInt(dataDiff)
	sum /= int(len(data) - 1)
	return math.Sqrt(float64(sum))
}

func GetRelativeStdInt64 (data []int64) float64 {
	return float64(GetStdInt64(data))/float64(GetAvgInt64(data))
}

func GetRelativeStdInt (data []int) float64 {
	return float64(GetStdInt(data))/float64(GetAvgInt(data))
}