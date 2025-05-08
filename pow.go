package blockchain

import (
	"fmt"
	"math"
	"math/big"
)

const maxNonce = math.MaxUint32

type ProofOfWork struct {
	block  *Block
	target *big.Int
}

func NewProofOfWork(block *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-block.Difficulty))
	return &ProofOfWork{
		block:  block,
		target: target,
	}
}

func (pow *ProofOfWork) Run() (uint32, [32]byte, error) {
	var (
		hash    [32]byte
		hashInt big.Int
		nonce   uint32 = 0
	)

	fmt.Printf("Start mining...\n")

	for nonce < maxNonce {
		pow.block.Nonce = nonce
		serialized, err := pow.block.SerializeHeader()
		if err != nil {
			return 0, [32]byte{}, err
		}
		hash = Hash(serialized)
		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(pow.target) == -1 {
			fmt.Printf("Found a valid hash: %x\n", hash)
			break
		}
		nonce++
		if nonce%100000 == 0 {
			fmt.Printf("Nonce: %d\n", nonce)
		}
	}
	return nonce, hash, nil
}

func (pow *ProofOfWork) Validate() bool {
	serialized, err := pow.block.SerializeHeader()
	if err != nil {
		return false
	}
	hash := Hash(serialized)
	var hashInt big.Int
	hashInt.SetBytes(hash[:])
	return hashInt.Cmp(pow.target) == -1
}
