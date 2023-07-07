package bloom

import (
	"bytes"
	"encoding/binary"
	"io"
	"github.com/willf/bitset"
	"crypto/sha1"
	"math/big"
)

type BloomFilter struct {
	m uint
	k uint
	b *bitset.BitSet
}

func max(x, y uint) uint {
	if x > y {
		return x
	}
	return y
}

func New(m uint, k uint) *BloomFilter {
	return &BloomFilter{max(1, m), max(1, k), bitset.New(m)}
}

func (f *BloomFilter) location(data []byte, seed_i uint) uint {
	i := make([]byte, 8)
	binary.LittleEndian.PutUint64(i, uint64(seed_i))
	i = append(data, i...)

	return uint(HashSha1(i) % uint64(f.m))
}


func (f *BloomFilter) Cap() uint {
	return f.m
}

func (f *BloomFilter) K() uint {
	return f.k
}

func (f *BloomFilter) BitSet() *bitset.BitSet {
	return f.b
}

// Add data to the Bloom Filter. Returns the filter (allows chaining)
func (f *BloomFilter) Add(data []byte) *BloomFilter {
	for i := uint(0); i < f.k; i++ {
		seed := uint(big.NewInt(0).SetBytes(data).Uint64())
		f.b.Set(f.location(data, i+seed))
	}
	return f
}

func (f *BloomFilter) Test(data []byte) bool {
	for i := uint(0); i < f.k; i++ {
		seed := uint(big.NewInt(0).SetBytes(data).Uint64())
		if !f.b.Test(f.location(data, i+seed)) {
			return false
		}
	}
	return true
}

func (f *BloomFilter) TestLocations(locs []uint64) bool {
	for i := 0; i < len(locs); i++ {
		if !f.b.Test(uint(locs[i] % uint64(f.m))) {
			return false
		}
	}
	return true
}

func (f *BloomFilter) WriteTo(stream io.Writer) (int64, error) {
	err := binary.Write(stream, binary.BigEndian, uint64(f.m))
	if err != nil {
		return 0, err
	}
	err = binary.Write(stream, binary.BigEndian, uint64(f.k))
	if err != nil {
		return 0, err
	}
	numBytes, err := f.b.WriteTo(stream)
	return numBytes + int64(2*binary.Size(uint64(0))), err
}

func (f *BloomFilter) ReadFrom(stream io.Reader) (int64, error) {
	var m, k uint64
	err := binary.Read(stream, binary.BigEndian, &m)
	if err != nil {
		return 0, err
	}
	err = binary.Read(stream, binary.BigEndian, &k)
	if err != nil {
		return 0, err
	}
	b := &bitset.BitSet{}
	numBytes, err := b.ReadFrom(stream)
	if err != nil {
		return 0, err
	}
	f.m = uint(m)
	f.k = uint(k)
	f.b = b
	return numBytes + int64(2*binary.Size(uint64(0))), nil
}

func (f *BloomFilter) GobEncode() ([]byte, error) {
	var buf bytes.Buffer
	_, err := f.WriteTo(&buf)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (f *BloomFilter) GobDecode(data []byte) error {
	buf := bytes.NewBuffer(data)
	_, err := f.ReadFrom(buf)

	return err
}

func HashSha1(input []byte) uint64 {
	hash := sha1.New()
	hash.Write(input)
	output := hash.Sum(nil)
	return big.NewInt(0).SetBytes(output).Uint64()
}