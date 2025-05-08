package blockchain

import (
	"errors"
	"fmt"
)

const (
	TargetBlockTime = 600

	MaxDifficultyAdjustmentFactor = 4

	InitialDifficulty = 16
)

var (
	DifficultyAdjustmentInterval = 10
)

type Blockchain struct {
	blocks []*Block
}

func NewBlockchain() *Blockchain {
	genesisBlock := createGenesisBlock()
	return &Blockchain{
		blocks: []*Block{genesisBlock},
	}
}

func createGenesisBlock() *Block {
	var prevHash [32]byte

	block := NewBlock(
		[]byte("Genesis Block, hi"),
		prevHash,
		InitialDifficulty,
	)

	pow := NewProofOfWork(block)
	nonce, hash, err := pow.Run()
	if err != nil {
		panic(err)
	}
	block.Nonce = nonce
	block.Hash = hash

	return block
}

func (bc *Blockchain) AddBlock(data []byte) (*Block, error) {
	prevBlock := bc.blocks[len(bc.blocks)-1]

	nextDifficulty := bc.calculateNextDifficulty()

	newBlock := NewBlock(data, prevBlock.Hash, nextDifficulty)

	pow := NewProofOfWork(newBlock)
	nonce, hash, err := pow.Run()
	if err != nil {
		return nil, err
	}
	newBlock.Nonce = nonce
	newBlock.Hash = hash

	bc.blocks = append(bc.blocks, newBlock)

	return newBlock, nil
}

func (bc *Blockchain) calculateNextDifficulty() uint32 {
	if len(bc.blocks)%DifficultyAdjustmentInterval != 0 {
		return bc.getCurrentDifficulty()
	}

	prevAdjustmentBlock := bc.blocks[len(bc.blocks)-DifficultyAdjustmentInterval]

	expectedTime := TargetBlockTime * DifficultyAdjustmentInterval

	latestBlock := bc.blocks[len(bc.blocks)-1]
	actualTime := int64(latestBlock.Timestamp - prevAdjustmentBlock.Timestamp)

	currentDifficulty := bc.getCurrentDifficulty()

	if int(actualTime) < expectedTime/MaxDifficultyAdjustmentFactor {
		fmt.Printf("Block generation too fast, increasing difficulty: %d -> %d\n", currentDifficulty, currentDifficulty+1)
		return currentDifficulty + 1
	}

	if int(actualTime) > expectedTime*MaxDifficultyAdjustmentFactor {
		if currentDifficulty > 1 {
			fmt.Printf("Block generation too slow, decreasing difficulty: %d -> %d\n", currentDifficulty, currentDifficulty-1)
			return currentDifficulty - 1
		}
	}

	return currentDifficulty
}

func (bc *Blockchain) getCurrentDifficulty() uint32 {
	return bc.blocks[len(bc.blocks)-1].Difficulty
}

func (bc *Blockchain) ValidateChain() (bool, error) {
	if !bc.blocks[0].IsGenesis() {
		return false, errors.New("invalid genesis block")
	}

	for i := 1; i < len(bc.blocks); i++ {
		current := bc.blocks[i]
		previous := bc.blocks[i-1]

		if current.PrevBlockHash != previous.Hash {
			return false, fmt.Errorf("unverified block link at height %d", i)
		}

		calculatedRoot := Hash(current.Data)
		if calculatedRoot != current.MerkleRoot {
			return false, fmt.Errorf("unverified merkle root at height %d", i)
		}

		pow := NewProofOfWork(current)
		if !pow.Validate() {
			return false, fmt.Errorf("unverified proof of work at height %d", i)
		}
	}

	return true, nil
}

func (bc *Blockchain) GetLatestBlock() (*Block, error) {
	return bc.blocks[len(bc.blocks)-1], nil
}

func (bc *Blockchain) GetHeight() int {
	return len(bc.blocks) - 1 // 高度從0開始
}
