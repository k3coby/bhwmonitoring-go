package elgamal

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"log"
	"math/big"
	"math"
	"os"
	"fmt"
	"errors"
	"sync"
	"bytes"
)

type GroupElement struct {
	X *big.Int
	Y *big.Int
}

type PublicKey struct {
	Curve *elliptic.Curve
	SecParam int
	Gx *big.Int
	Gy *big.Int
	Hx *big.Int
	Hy *big.Int
	PointCompression bool
}

type SecretKey struct {
	Curve *elliptic.Curve
	Hx *big.Int
	Hy *big.Int
	Priv []byte
}

type Ciphertext struct {
	C1x *big.Int
	C1y *big.Int
	C2x *big.Int
	C2y *big.Int
}

type CiphertextByte struct {
	C1 []byte
	C2 []byte
}

type ZKP struct {
	A1x *big.Int
	A1y *big.Int
	B1x *big.Int
	B1y *big.Int
	A2x *big.Int
	A2y *big.Int
	B2x *big.Int
	B2y *big.Int
	D1 *big.Int
	D2 *big.Int
	R1 *big.Int
	R2 *big.Int
}

type ZKPByte struct {
	A1 []byte
	B1 []byte
	A2 []byte
	B2 []byte
	D1 []byte
	D2 []byte
	R1 []byte
	R2 []byte
}

const PaddingBytes = 4

// This function generates a EC-ElGamal key pair
func KeyGen(secParam int, pointCompression bool) (*PublicKey, *SecretKey) {

	curve := *(initCurve(secParam))

	priv, Hx, Hy, _ := elliptic.GenerateKey(curve, rand.Reader)
	Gx, Gy := curve.ScalarBaseMult(big.NewInt(1).Bytes())

	// create public key
	pk := &PublicKey{&curve, secParam, Gx, Gy, Hx, Hy, pointCompression}

	// create secret key
	sk := &SecretKey{&curve, Hx, Hy, priv}
	return pk, sk
}


// This function, given a public key, encrypts a plaintext message
// and return a ciphertext
func (pk *PublicKey) Encrypt(m *big.Int) *Ciphertext {

	curve := *pk.Curve
	m = m.Mod(m, curve.Params().N)
	z := newCryptoRandom(curve.Params().N.Bytes())
	c1x, c1y := curve.ScalarBaseMult(z)
	Hzx, Hzy := curve.ScalarMult(pk.Hx, pk.Hy, z)
	gmx, gmy := curve.ScalarBaseMult(m.Bytes())
	c2x, c2y := curve.Add(gmx, gmy, Hzx, Hzy)

	c := &Ciphertext{c1x, c1y, c2x, c2y}

	return c
}

func (pk *PublicKey) polynomial(x *big.Int) *big.Int {
	curve := *pk.Curve
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	x3.Sub(x3, threeX)
	x3.Add(x3, curve.Params().B)
	x3.Mod(x3, curve.Params().P)

	return x3
}

func (pk *PublicKey) EncryptMul(msg []byte) *Ciphertext {

	curve := *pk.Curve
	// m = m.Lsh(m, 32)
	p := curve.Params().P
	msgExt := msg
	for i := 0; i < PaddingBytes; i ++ {
		msgExt = append(msgExt, 0)
	}
	mx := big.NewInt(0).SetBytes(msgExt)
	my := big.NewInt(0)
	for i := 0; i < int(math.Pow(2, PaddingBytes*8)); i++ {
		my = pk.polynomial(mx)
		my = my.ModSqrt(my, p)
		if curve.IsOnCurve(mx, my) {
			break
		}
		mx = mx.Add(mx, big.NewInt(1))
	}
	if !curve.IsOnCurve(mx, my) {
		os.Exit(-1)
	}
	z := newCryptoRandom(curve.Params().N.Bytes())
	c1x, c1y := curve.ScalarBaseMult(z)
	Hzx, Hzy := curve.ScalarMult(pk.Hx, pk.Hy, z)
	c2x, c2y := curve.Add(mx, my, Hzx, Hzy)

	c := &Ciphertext{c1x, c1y, c2x, c2y}

	return c
}


func (pk *PublicKey) EncryptSeqWithZKP(ms []*big.Int, numThreads int) ([]*Ciphertext, []*ZKP, *big.Int) {

	var encSeqZKP sync.WaitGroup

	curve := *pk.Curve
	zs := make([]*big.Int, len(ms))
	a1s := make([]*GroupElement, len(ms))
	a2s := make([]*GroupElement, len(ms))
	b1s := make([]*GroupElement, len(ms))
	b2s := make([]*GroupElement, len(ms))
	r1s := make([]*big.Int, len(ms))
	r2s := make([]*big.Int, len(ms))
	d1s := make([]*big.Int, len(ms))
	d2s := make([]*big.Int, len(ms))
	ws := make([]*big.Int, len(ms))
	cs := make([]*Ciphertext, len(ms))
	zkps := make([]*ZKP, len(ms))


	chWorkerEnc := make(chan int, numThreads)
	defer close(chWorkerEnc)

	for i := range ms {
		chWorkerEnc <- 1
		encSeqZKP.Add(1)

		go func(i int) {
			defer encSeqZKP.Done()
			
			if big.NewInt(1).CmpAbs(ms[i]) != 0 {
				err := errors.New("Invalid message space!")
				fmt.Println(err)
				os.Exit(-1)	
			}

			// Encryption
		
			ms[i] = ms[i].Mod(ms[i], curve.Params().N)
			gmx, gmy := curve.ScalarBaseMult(ms[i].Bytes())
			zs[i] = big.NewInt(1).SetBytes(newCryptoRandom(curve.Params().N.Bytes()))
			c1x, c1y := curve.ScalarBaseMult(zs[i].Bytes())
			Hzx, Hzy := curve.ScalarMult(pk.Hx, pk.Hy, zs[i].Bytes())
			c2x, c2y := curve.Add(Hzx, Hzy, gmx, gmy)

			cs[i] = &Ciphertext{c1x, c1y, c2x, c2y}
			<- chWorkerEnc
		}(i)
		
	}
	encSeqZKP.Wait()


	buf := &bytes.Buffer{}
	for i := range ms {
		buf.Write(cs[i].C1x.Bytes())
		buf.Write(cs[i].C1y.Bytes())
		buf.Write(cs[i].C2x.Bytes())
		buf.Write(cs[i].C2y.Bytes())
	}
	// csbytes := buf.Bytes()


	chWorkerZKP := make(chan int, numThreads)
	defer close(chWorkerZKP)

	for i := range ms {
		chWorkerZKP <- 1
		encSeqZKP.Add(1)

		go func(i int) {
			defer encSeqZKP.Done()
			
			a1x := big.NewInt(0)
			a1y := big.NewInt(0)
			b1x := big.NewInt(0)
			b1y := big.NewInt(0)
			a2x := big.NewInt(0)
			a2y := big.NewInt(0)
			b2x := big.NewInt(0)
			b2y := big.NewInt(0)
			w := big.NewInt(0)
			d1 := big.NewInt(0)
			d2 := big.NewInt(0)
			r1 := big.NewInt(0)
			r2 := big.NewInt(0)
			
			if big.NewInt(1).Cmp(ms[i]) == 0 {

				w = big.NewInt(1).SetBytes(newCryptoRandom(curve.Params().N.Bytes()))
				r1 = big.NewInt(1).SetBytes(newCryptoRandom(curve.Params().N.Bytes()))
				d1 = big.NewInt(1).SetBytes(newCryptoRandom(curve.Params().N.Bytes()))
				gr1x, gr1y := curve.ScalarBaseMult(r1.Bytes())
				c1d1x, c1d1y := curve.ScalarMult(cs[i].C1x, cs[i].C1y, d1.Bytes())
				a1x, a1y = curve.Add(gr1x, gr1y, c1d1x, c1d1y)

				hr1x, hr1y := curve.ScalarMult(pk.Hx, pk.Hy, r1.Bytes())
				c2gx, c2gy := curve.Add(cs[i].C2x, cs[i].C2y, pk.Gx, pk.Gy)
				c2gd1x, c2gd1y := curve.ScalarMult(c2gx, c2gy, d1.Bytes())
				b1x, b1y = curve.Add(hr1x, hr1y, c2gd1x, c2gd1y)

				a2x, a2y = curve.ScalarBaseMult(w.Bytes())
				b2x, b2y = curve.ScalarMult(pk.Hx, pk.Hy, w.Bytes())

			} else {

				w = big.NewInt(1).SetBytes(newCryptoRandom(curve.Params().N.Bytes()))
				r2 = big.NewInt(1).SetBytes(newCryptoRandom(curve.Params().N.Bytes()))
				d2 = big.NewInt(1).SetBytes(newCryptoRandom(curve.Params().N.Bytes()))
				a1x, a1y = curve.ScalarBaseMult(w.Bytes())
				b1x, b1y = curve.ScalarMult(pk.Hx, pk.Hy, w.Bytes())

				gr2x, gr2y := curve.ScalarBaseMult(r2.Bytes())

				c1d2x, c1d2y := curve.ScalarMult(cs[i].C1x, cs[i].C1y, d2.Bytes())
				a2x, a2y = curve.Add(gr2x, gr2y, c1d2x, c1d2y)

				invOne := big.NewInt(1).Mod(big.NewInt(-1), curve.Params().N)
				invGx, invGy := curve.ScalarBaseMult(invOne.Bytes())

				hr2x, hr2y := curve.ScalarMult(pk.Hx, pk.Hy, r2.Bytes())
				c2invgx, c2invgy := curve.Add(cs[i].C2x, cs[i].C2y, invGx, invGy)
				c2invgd2x, c2invgd2y := curve.ScalarMult(c2invgx, c2invgy, d2.Bytes())
				b2x, b2y = curve.Add(hr2x, hr2y, c2invgd2x, c2invgd2y)
			}

			a1s[i] = &GroupElement{a1x, a1y}
			b1s[i] = &GroupElement{b1x, b1y}
			a2s[i] = &GroupElement{a2x, a2y}
			b2s[i] = &GroupElement{b2x, b2y}
			d1s[i] = d1
			d2s[i] = d2
			r1s[i] = r1
			r2s[i] = r2
			ws[i] = w
		
			<- chWorkerZKP
		}(i)
		
	}
	encSeqZKP.Wait()

	for i := range ms {
		buf.Write(a1s[i].X.Bytes())
		buf.Write(a1s[i].Y.Bytes())
		buf.Write(b1s[i].X.Bytes())
		buf.Write(b1s[i].Y.Bytes())
		buf.Write(a2s[i].X.Bytes())
		buf.Write(a2s[i].Y.Bytes())
		buf.Write(b2s[i].X.Bytes())
		buf.Write(b2s[i].Y.Bytes())
	}
	commitment := buf.Bytes()

	challenge := big.NewInt(0).SetBytes(HashSha256(commitment))
	challenge = challenge.Mod(challenge, curve.Params().N)


	chWorkerZKPr:= make(chan int, numThreads)
	defer close(chWorkerZKPr)
	for i := range ms {
		chWorkerZKPr <- 1
		encSeqZKP.Add(1)

		go func(i int) {
			defer encSeqZKP.Done()
			
			if big.NewInt(1).Cmp(ms[i]) == 0 {

				d2 := big.NewInt(0).Sub(challenge, d1s[i])
				d2 = d2.Mod(d2, curve.Params().N)
				zd2 := big.NewInt(1).Mul(zs[i], d2)
				zd2 = zd2.Mod(zd2, curve.Params().N)
				r2 := big.NewInt(0).Sub(ws[i], zd2)
				r2 = r2.Mod(r2, curve.Params().N)

				d2s[i] = d2
				r2s[i] = r2

			} else {

				d1 := big.NewInt(0).Sub(challenge, d2s[i])
				d1 = d1.Mod(d1, curve.Params().N)
				zd1 := big.NewInt(1).Mul(zs[i], d1)
				zd1 = zd1.Mod(zd1, curve.Params().N)
				r1 := big.NewInt(0).Sub(ws[i], zd1)
				r1 = r1.Mod(r1, curve.Params().N)

				d1s[i] = d1
				r1s[i] = r1

			}

			zkps[i] = &ZKP{a1s[i].X, a1s[i].Y, b1s[i].X, b1s[i].Y, a2s[i].X, a2s[i].Y, b2s[i].X, b2s[i].Y, d1s[i], d2s[i], r1s[i], r2s[i]}
			<- chWorkerZKPr
		}(i)
		
	}
	encSeqZKP.Wait()

	return cs, zkps, challenge
}

func (pk *PublicKey) VerifySeqZKP(cs []*Ciphertext, zkps []*ZKP, rcvChallenge *big.Int, numThreads int) bool {

	var vrfySeqZKP sync.WaitGroup
	numFailedTests := 0

	curve := *pk.Curve

	buf := &bytes.Buffer{}
	for i := range cs {
		buf.Write(cs[i].C1x.Bytes())
		buf.Write(cs[i].C1y.Bytes())
		buf.Write(cs[i].C2x.Bytes())
		buf.Write(cs[i].C2y.Bytes())
	}

	for i := range zkps {
		buf.Write(zkps[i].A1x.Bytes())
		buf.Write(zkps[i].A1y.Bytes())
		buf.Write(zkps[i].B1x.Bytes())
		buf.Write(zkps[i].B1y.Bytes())
		buf.Write(zkps[i].A2x.Bytes())
		buf.Write(zkps[i].A2y.Bytes())
		buf.Write(zkps[i].B2x.Bytes())
		buf.Write(zkps[i].B2y.Bytes())
	}
	commitment := buf.Bytes()

	challenge := big.NewInt(0).SetBytes(HashSha256(commitment))
	challenge = challenge.Mod(challenge, curve.Params().N)

	if challenge.Cmp(rcvChallenge) != 0 {
		fmt.Println("b1-test failed.")
		numFailedTests += 1
	}

	chWorkerVrfy := make(chan int, numThreads)
	defer close(chWorkerVrfy)

	for i := range zkps {
		chWorkerVrfy <- 1
		vrfySeqZKP.Add(1)

		go func(i int) {
			defer vrfySeqZKP.Done()
			
			c1x := cs[i].C1x
			c1y := cs[i].C1y
			c2x := cs[i].C2x
			c2y := cs[i].C2y

			a1x := zkps[i].A1x
			a1y := zkps[i].A1y
			b1x := zkps[i].B1x
			b1y := zkps[i].B1y
			a2x := zkps[i].A2x
			a2y := zkps[i].A2y
			b2x := zkps[i].B2x
			b2y := zkps[i].B2y
			d1 := zkps[i].D1
			d2 := zkps[i].D2
			r1 := zkps[i].R1
			r2 := zkps[i].R2
			
			bigOne := big.NewInt(1)
			d1PLUSd2 := bigOne.Add(d1, d2)
			d1PLUSd2 = d1PLUSd2.Mod(d1PLUSd2, curve.Params().N)
			if challenge.Cmp(d1PLUSd2) != 0 {
				fmt.Println("c-test failed.")
				numFailedTests += 1
			}

			gr1x, gr1y := curve.ScalarBaseMult(r1.Bytes())
			c1d1x, c1d1y := curve.ScalarMult(c1x, c1y, d1.Bytes())
			a1xx, a1yy := curve.Add(gr1x, gr1y, c1d1x, c1d1y)
			if a1x.Cmp(a1xx) != 0 || a1y.Cmp(a1yy) != 0 {
				fmt.Println("a1-test failed.")
				numFailedTests += 1
			}

			hr1x, hr1y := curve.ScalarMult(pk.Hx, pk.Hy, r1.Bytes())
			c2gx, c2gy := curve.Add(c2x, c2y, pk.Gx, pk.Gy)
			c2gd1x, c2gd1y := curve.ScalarMult(c2gx, c2gy, d1.Bytes())
			b1xx, b1yy := curve.Add(hr1x, hr1y, c2gd1x, c2gd1y)
			if b1x.Cmp(b1xx) != 0 || b1y.Cmp(b1yy) != 0 {
				fmt.Println("b1-test failed.")
				numFailedTests += 1
			}

			gr2x, gr2y := curve.ScalarBaseMult(r2.Bytes())
			c1d2x, c1d2y := curve.ScalarMult(c1x, c1y, d2.Bytes())
			a2xx, a2yy := curve.Add(gr2x, gr2y, c1d2x, c1d2y)
			if a2x.Cmp(a2xx) != 0 || a2y.Cmp(a2yy) != 0 {
				fmt.Println("a2-test failed.")
				numFailedTests += 1
			}

			invOne := big.NewInt(1).Mod(big.NewInt(-1), curve.Params().N)
			invGx, invGy := curve.ScalarBaseMult(invOne.Bytes())
			hr2x, hr2y := curve.ScalarMult(pk.Hx, pk.Hy, r2.Bytes())
			c2invgx, c2invgy := curve.Add(c2x, c2y, invGx, invGy)
			c2invgd2x, c2invgd2y := curve.ScalarMult(c2invgx, c2invgy, d2.Bytes())
			b2xx, b2yy := curve.Add(hr2x, hr2y, c2invgd2x, c2invgd2y)
			if b2x.Cmp(b2xx) != 0 || b2y.Cmp(b2yy) != 0 {
				fmt.Println("b2-test failed.")
				numFailedTests += 1
			}
			
			<- chWorkerVrfy
		}(i)
		
	}
	vrfySeqZKP.Wait()

	return numFailedTests == 0

}


func (pk *PublicKey) RaiseG2M(m []byte) []byte {

	curve := *pk.Curve
	m = big.NewInt(1).SetBytes(m).Mod(big.NewInt(1).SetBytes(m), curve.Params().N).Bytes()
	gmx, gmy := curve.ScalarBaseMult(m)
	res := gmx.Bytes()
	res = append(res, gmy.Bytes()...)

	return res
}


// This function, given a secret key, checks if the input ciphertext is an
// encryption of the input plaintext
func (sk *SecretKey) Decrypt(c *Ciphertext) []byte {

	curve := *sk.Curve

	invSK := big.NewInt(0).SetBytes(sk.Priv)
	invSK = invSK.Sub(curve.Params().N, invSK)

	tempx, tempy := curve.ScalarMult(c.C1x, c.C1y, invSK.Bytes())
	resx, _ := curve.Add(c.C2x, c.C2y, tempx, tempy)

	res := resx.Bytes()[:len(resx.Bytes())-PaddingBytes]

	return res
}

// This function, given a secret key, checks if the input ciphertext is an
// encryption of the input plaintext
func (sk *SecretKey) DecryptAndCheck(c *Ciphertext, test []byte) (bool) {

	curve := *sk.Curve

	tempx, tempy := curve.ScalarMult(c.C1x, c.C1y, sk.Priv)
	gmx, gmy := curve.ScalarBaseMult(test)
	resx, resy := curve.Add(tempx, tempy, gmx, gmy)
	if (resx.Cmp(c.C2x) == 0) && (resy.Cmp(c.C2y) == 0) {
		return true
	}
	return false
}


// This function, given a secret key, checks if the input ciphertext is an
// encryption of zero
func (sk *SecretKey) DecryptAndCheck0(c *Ciphertext) (bool) {

	curve := *sk.Curve

	tempx, tempy := curve.ScalarMult(c.C1x, c.C1y, sk.Priv)
	if (tempx.Cmp(c.C2x) == 0) && (tempy.Cmp(c.C2y) == 0) {
		return true
	}
	return false
}


// This function, given a public key, homomorphically add two ciphertexts
// together and returns a ciphertext of their sum. The function will re-randomize
// the resulting ciphertext (can be seen as homomorphic addition with an encryption of zero)
// if the input boolean variable "rand" is set to true.
func (pk *PublicKey) Add(cA, cB *Ciphertext, rand bool) (*Ciphertext) {
	curve := *pk.Curve
	ctemp1x, ctemp1y := curve.Add(cA.C1x, cA.C1y, cB.C1x, cB.C1y)
	ctemp2x, ctemp2y := curve.Add(cA.C2x, cA.C2y, cB.C2x, cB.C2y)

	if rand {
		zeroCT := pk.Encrypt(big.NewInt(0))
		randCtemp1x, randCtemp1y := curve.Add(ctemp1x, ctemp1y, zeroCT.C1x, zeroCT.C1y)
		randCtemp2x, randCtemp2y := curve.Add(ctemp2x, ctemp2y, zeroCT.C2x, zeroCT.C2y)
		c := &Ciphertext{randCtemp1x, randCtemp1y, randCtemp2x, randCtemp2y}
		return c
	}
	c := &Ciphertext{ctemp1x, ctemp1y, ctemp2x, ctemp2y}
	return c
}


// This function, given a public key, achieves scalar multiplication on the
// input ciphertext with a randomly chosen scalar from Zn. The function will re-randomize the 
// resulting ciphertext (can be seen as homomorphic addition with an encryption of zero) 
// if the input boolean variable "rand" is set to true.
func (pk *PublicKey) ScalarMultRandomizer(cA *Ciphertext, rand bool) (*Ciphertext) {

	curve := *pk.Curve
	scalar := newCryptoRandom(curve.Params().N.Bytes())

	ctemp1x, ctemp1y := curve.ScalarMult(cA.C1x, cA.C1y, scalar)
	ctemp2x, ctemp2y := curve.ScalarMult(cA.C2x, cA.C2y, scalar)

	if rand {
		zeroCT := pk.Encrypt(big.NewInt(0))
		randCtemp1x, randCtemp1y := curve.Add(ctemp1x, ctemp1y, zeroCT.C1x, zeroCT.C1y)
		randCtemp2x, randCtemp2y := curve.Add(ctemp2x, ctemp2y, zeroCT.C2x, zeroCT.C2y)
		c := &Ciphertext{randCtemp1x, randCtemp1y, randCtemp2x, randCtemp2y}
		return c
	}

	c := &Ciphertext{ctemp1x, ctemp1y, ctemp2x, ctemp2y}
	return c
}

// This function returns a ciphertext of the inverse of the input plaintext
func (pk *PublicKey) EncryptInv(m *big.Int) *Ciphertext {
	curve := *pk.Curve
	return pk.Encrypt(m.Sub(curve.Params().N, m))
}

// This function returns a random number smaller than max
func newCryptoRandom(max []byte) []byte {
	maxInt := big.NewInt(0).SetBytes(max)
	rand, err := rand.Int(rand.Reader, maxInt)
	if err != nil {
		log.Println(err)
	}

	return rand.Bytes()
}

// This function initializes and returns the chosen curve
func initCurve(secParam int) *elliptic.Curve {
	//curve := elliptic.P192()
	var curve elliptic.Curve

	if secParam == 224 {
		curve = elliptic.P224()
	} else if secParam == 256 {
		curve = elliptic.P256()
	} else if secParam == 384 {
		curve = elliptic.P384()
	} else if secParam == 521 {
		curve = elliptic.P521()
	} else {}

	return &curve
}

// This function initializes a curve under the public key
func (pk *PublicKey) InitCurve() {
	pk.Curve = initCurve(pk.SecParam)
}

// This function encodes a ciphertext struct to bytes
func (pk *PublicKey) Ciphertext2Bytes(ciphertext *Ciphertext, pointCompression bool) (*CiphertextByte) {
	//curve := initCurve(pk.SecParam)
	curve := *pk.Curve
	var C1, C2 []byte
	if pointCompression {
		C1 = elliptic.MarshalCompressed(curve, ciphertext.C1x, ciphertext.C1y)
		C2 = elliptic.MarshalCompressed(curve, ciphertext.C2x, ciphertext.C2y)
	} else {
		C1 = elliptic.Marshal(curve, ciphertext.C1x, ciphertext.C1y)
		C2 = elliptic.Marshal(curve, ciphertext.C2x, ciphertext.C2y)
	}

	ciphertextBytes := &CiphertextByte{C1, C2}
	return ciphertextBytes
}

// This function decodes ciphertext bytes back to a ciphertext struct
func (pk *PublicKey) Bytes2Ciphertext(ciphertextBytes *CiphertextByte, pointCompression bool) (*Ciphertext) {
	//curve := initCurve(pk.SecParam)
	curve := *pk.Curve
	var C1x, C1y, C2x, C2y *big.Int
	if pointCompression {
		C1x, C1y = elliptic.UnmarshalCompressed(curve, ciphertextBytes.C1)
		C2x, C2y = elliptic.UnmarshalCompressed(curve, ciphertextBytes.C2)
	} else {
		C1x, C1y = elliptic.Unmarshal(curve, ciphertextBytes.C1)
		C2x, C2y = elliptic.Unmarshal(curve, ciphertextBytes.C2)
	}

	ciphertext := &Ciphertext{C1x, C1y, C2x, C2y}
	// if !pk.CheckOnCurve(ciphertext) {
	// 	os.Exit(1) // ill-formed ciphertexts detected
	// }
	return ciphertext
}

// This function encodes a ciphertext struct to bytes
func (pk *PublicKey) ZKP2Bytes(zkp *ZKP, pointCompression bool) (*ZKPByte) {
	//curve := initCurve(pk.SecParam)
	curve := *pk.Curve
	var A1, A2, B1, B2 []byte
	if pointCompression {
		A1 = elliptic.MarshalCompressed(curve, zkp.A1x, zkp.A1y)
		A2 = elliptic.MarshalCompressed(curve, zkp.A2x, zkp.A2y)
		B1 = elliptic.MarshalCompressed(curve, zkp.B1x, zkp.B1y)
		B2 = elliptic.MarshalCompressed(curve, zkp.B2x, zkp.B2y)
	} else {
		A1 = elliptic.Marshal(curve, zkp.A1x, zkp.A1y)
		A2 = elliptic.Marshal(curve, zkp.A2x, zkp.A2y)
		B1 = elliptic.Marshal(curve, zkp.B1x, zkp.B1y)
		B2 = elliptic.Marshal(curve, zkp.B2x, zkp.B2y)
	}

	zkpBytes := &ZKPByte{A1, B1, A2, B2, zkp.D1.Bytes(), zkp.D2.Bytes(), zkp.R1.Bytes(), zkp.R2.Bytes()}
	return zkpBytes
}

// This function decodes ciphertext bytes back to a ciphertext struct
func (pk *PublicKey) Bytes2ZKP(zkpBytes *ZKPByte, pointCompression bool) (*ZKP) {
	//curve := initCurve(pk.SecParam)
	curve := *pk.Curve
	var A1x, A1y, A2x, A2y, B1x, B1y, B2x, B2y *big.Int
	if pointCompression {
		A1x, A1y = elliptic.UnmarshalCompressed(curve, zkpBytes.A1)
		A2x, A2y = elliptic.UnmarshalCompressed(curve, zkpBytes.A2)
		B1x, B1y = elliptic.UnmarshalCompressed(curve, zkpBytes.B1)
		B2x, B2y = elliptic.UnmarshalCompressed(curve, zkpBytes.B2)
	} else {
		A1x, A1y = elliptic.Unmarshal(curve, zkpBytes.A1)
		A2x, A2y = elliptic.Unmarshal(curve, zkpBytes.A2)
		B1x, B1y = elliptic.Unmarshal(curve, zkpBytes.B1)
		B2x, B2y = elliptic.Unmarshal(curve, zkpBytes.B2)
	}

	zkp := &ZKP{A1x, A1y, B1x, B1y, A2x, A2y, B2x, B2y, big.NewInt(1).SetBytes(zkpBytes.D1), big.NewInt(1).SetBytes(zkpBytes.D2), big.NewInt(1).SetBytes(zkpBytes.R1), big.NewInt(1).SetBytes(zkpBytes.R2)} 

	return zkp }

// This function checks if a given ciphertext is a well-formed ciphertext
func (pk *PublicKey) CheckOnCurve(ciphertext *Ciphertext) bool {
	curve := *pk.Curve
	return curve.IsOnCurve(ciphertext.C1x, ciphertext.C1y) && curve.IsOnCurve(ciphertext.C2x, ciphertext.C2y)
}

func HashSha256(input []byte) []byte {
	hash := sha256.New()
	hash.Write(input)
	output := hash.Sum(nil)
	return output
}