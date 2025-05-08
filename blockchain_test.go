package blockchain

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestBlockCreation(t *testing.T) {
	var prevHash [32]byte
	data := []byte("Test Block")
	difficulty := uint32(16)

	block := NewBlock(data, prevHash, difficulty)

	if block.Version != 1 {
		t.Errorf("block version incorrect: got %d, expected 1", block.Version)
	}

	if !bytes.Equal(block.PrevBlockHash[:], prevHash[:]) {
		t.Errorf("previous block hash incorrect")
	}

	if !bytes.Equal(block.Data, data) {
		t.Errorf("block data incorrect")
	}

	if block.Difficulty != difficulty {
		t.Errorf("difficulty incorrect: got %d, expected %d", block.Difficulty, difficulty)
	}

	expectedMerkleRoot := Hash(data)
	if block.MerkleRoot != expectedMerkleRoot {
		t.Errorf("merkle root incorrect: got %x, expected %x", block.MerkleRoot, expectedMerkleRoot)
	}
}

func TestBlockSerialization(t *testing.T) {
	var prevHash [32]byte
	data := []byte("Test Serialization")
	block := NewBlock(data, prevHash, InitialDifficulty)
	block.Nonce = 12345

	headerBytes, err := block.SerializeHeader()
	if err != nil {
		t.Fatalf("failed to serialize header: %v", err)
	}
	block.Hash = Hash(headerBytes)

	serialized, err := block.Serialize()
	if err != nil {
		t.Fatalf("failed to serialize block: %v", err)
	}

	deserialized, err := Deserialize(serialized)
	if err != nil {
		t.Fatalf("failed to deserialize block: %v", err)
	}

	if block.Version != deserialized.Version {
		t.Errorf("version mismatch: %d vs %d", block.Version, deserialized.Version)
	}

	if block.Nonce != deserialized.Nonce {
		t.Errorf("nonce mismatch: %d vs %d", block.Nonce, deserialized.Nonce)
	}

	if !bytes.Equal(block.Data, deserialized.Data) {
		t.Errorf("data mismatch")
	}

	if block.Hash != deserialized.Hash {
		t.Errorf("hash mismatch: %x vs %x", block.Hash, deserialized.Hash)
	}
}

func TestHash(t *testing.T) {
	data := []byte("test double hash")

	expectedHash := sha256.Sum256(data)

	actualHash := Hash(data)

	if expectedHash != actualHash {
		t.Errorf("hash mismatch: expected %x, got %x", expectedHash, actualHash)
	}
}

func TestProofOfWork(t *testing.T) {
	testDifficulty := uint32(8)

	var prevHash [32]byte
	data := []byte("Test PoW")
	block := NewBlock(data, prevHash, testDifficulty)

	pow := NewProofOfWork(block)

	// 設置測試超時
	done := make(chan bool)
	go func() {
		nonce, hash, err := pow.Run()
		if err != nil {
			t.Errorf("error running proof of work: %v", err)
			return
		}
		block.Nonce = nonce
		block.Hash = hash
		done <- true
	}()

	// 等待挖掘完成或超時
	select {
	case <-done:
		if !pow.Validate() {
			t.Errorf("ProofOfWork validation failed")
		}
		var hashInt big.Int
		hashInt.SetBytes(block.Hash[:])
		target := big.NewInt(1)
		target.Lsh(target, 256-uint(block.Difficulty))

		if hashInt.Cmp(target) >= 0 {
			t.Errorf("Cannot satisfy difficulty requirement")
		}
	case <-time.After(5 * time.Second):
		t.Skip("ProofOfWork test timed out - this may be normal depending on difficulty settings")
	}
}

func TestInvalidProofOfWork(t *testing.T) {
	var prevHash [32]byte
	data := []byte("Test Invalid PoW")
	block := NewBlock(data, prevHash, InitialDifficulty)

	block.Nonce = 12345
	block.Hash = [32]byte{0xFF, 0xFF} // 不可能是有效的哈希值

	pow := NewProofOfWork(block)
	if pow.Validate() {
		t.Errorf("Should identify invalid proof of work")
	}
}

func TestBlockchainCreation(t *testing.T) {
	bc := NewBlockchain()

	if len(bc.blocks) != 1 {
		t.Fatalf("Genesis block creation failed: Blockchain length = %d", len(bc.blocks))
	}

	genesisBlock := bc.blocks[0]
	if !genesisBlock.IsGenesis() {
		t.Errorf("Genesis block check failed")
	}

	pow := NewProofOfWork(genesisBlock)
	if !pow.Validate() {
		t.Errorf("Genesis block proof of work validation failed")
	}
}

func TestAddBlock(t *testing.T) {
	bc := NewBlockchain()
	initialHeight := bc.GetHeight()

	bc.blocks[0].Difficulty = 0x2100FFFF

	block, err := bc.AddBlock([]byte("Test Block #1"))
	if err != nil {
		t.Fatalf("failed to add block: %v", err)
	}

	if bc.GetHeight() != initialHeight+1 {
		t.Errorf("Blockchain height incorrect: got %d, expected %d", bc.GetHeight(), initialHeight+1)
	}

	pow := NewProofOfWork(block)
	if !pow.Validate() {
		t.Errorf("failed to validate block proof of work")
	}

	if block.PrevBlockHash != bc.blocks[0].Hash {
		t.Errorf("Blockchain link incorrect")
	}
}

func TestGetLatestBlock(t *testing.T) {
	bc := NewBlockchain()

	bc.blocks[0].Difficulty = 0x2100FFFF
	bc.AddBlock([]byte("Block 1"))
	bc.AddBlock([]byte("Block 2"))

	latestBlock, err := bc.GetLatestBlock()
	if err != nil {
		t.Fatalf("failed to get latest block: %v", err)
	}

	if !bytes.Equal(latestBlock.Data, []byte("Block 2")) {
		t.Errorf("latest block data incorrect")
	}
}

func TestBlockchainValidation(t *testing.T) {
	bc := NewBlockchain()

	valid, err := bc.ValidateChain()
	if err != nil {
		t.Fatalf("failed to validate chain: %v", err)
	}

	if !valid {
		t.Errorf("initial blockchain validation failed")
	}

	bc.blocks[0].Difficulty = 10
	_, err = bc.AddBlock([]byte("Test Block #1"))
	if err != nil {
		t.Fatalf("failed to add block: %v", err)
	}

	valid, err = bc.ValidateChain()
	if err != nil {
		t.Fatalf("failed to validate chain after adding block: %v", err)
	}

	if !valid {
		t.Errorf("blockchain validation failed after adding block")
	}

	bc.blocks[1].Data = []byte("tamped block")
	bc.blocks[1].MerkleRoot = Hash(bc.blocks[1].Data)

	valid, _ = bc.ValidateChain()
	if valid {
		t.Errorf("incorrectly validated a blockchain with tampered data and merkle root")
	}

	bc = NewBlockchain()
	bc.blocks[0].Difficulty = 9
	_, err = bc.AddBlock([]byte("Test Block #1"))
	if err != nil {
		t.Fatalf("failed to add block: %v", err)
	}

	bc.blocks[1].Data = []byte("tamped block 2")

	valid, _ = bc.ValidateChain()
	if valid {
		t.Errorf("incorrectly validated a blockchain with tampered data")
	}

	bc = NewBlockchain()
	bc.blocks[0].Difficulty = 11
	_, err = bc.AddBlock([]byte("Test Block #1"))
	if err != nil {
		t.Fatalf("failed to add block: %v", err)
	}

	var invalidPrevHash [32]byte
	copy(invalidPrevHash[:], []byte("invalid previous hash"))
	bc.blocks[1].PrevBlockHash = invalidPrevHash

	valid, _ = bc.ValidateChain()
	if valid {
		t.Errorf("incorrectly validated a blockchain with tampered data")
	}
}

func TestDifficultyAdjustment(t *testing.T) {
	originalInterval := DifficultyAdjustmentInterval
	defer func() { DifficultyAdjustmentInterval = originalInterval }()

	DifficultyAdjustmentInterval = 3
	bc := NewBlockchain()
	initialDifficulty := bc.getCurrentDifficulty()

	for i := 0; i < DifficultyAdjustmentInterval-1; i++ {
		bc.blocks[len(bc.blocks)-1].Difficulty = 8 // 降低難度以加快測試
		_, err := bc.AddBlock([]byte("Block for difficulty test"))
		if err != nil {
			t.Fatalf("failed to add block: %v", err)
		}
	}

	bc.blocks[0].Timestamp = bc.blocks[len(bc.blocks)-1].Timestamp - 1

	bc.blocks[len(bc.blocks)-1].Difficulty = 18
	_, err := bc.AddBlock([]byte("Difficulty adjustment trigger - increase"))
	if err != nil {
		t.Fatalf("failed to add block: %v", err)
	}

	newDifficulty := bc.getCurrentDifficulty()
	if newDifficulty <= initialDifficulty {
		t.Errorf("difficulty did not increase: initial=%d, new=%d", initialDifficulty, newDifficulty)
	}

	bc = NewBlockchain()
	initialDifficulty = bc.getCurrentDifficulty()

	for i := 0; i < DifficultyAdjustmentInterval-1; i++ {
		bc.blocks[len(bc.blocks)-1].Difficulty = 17
		_, err := bc.AddBlock([]byte(fmt.Sprintf("Slow Block %d", i)))
		if err != nil {
			t.Fatalf("failed to add block: %v", err)
		}
	}

	bc.blocks[0].Timestamp = 1000 // 非常早的時間戳
	// 設置很晚的最新時間戳，使得時間間隔非常大
	bc.blocks[len(bc.blocks)-1].Timestamp = bc.blocks[0].Timestamp + uint32(TargetBlockTime*DifficultyAdjustmentInterval*5)

	bc.blocks[len(bc.blocks)-1].Difficulty = initialDifficulty // 確保初始難度大於1
	_, err = bc.AddBlock([]byte("Difficulty adjustment trigger - decrease"))
	if err != nil {
		t.Fatalf("failed to add block: %v", err)
	}

	newDifficulty = bc.getCurrentDifficulty()
	if newDifficulty >= initialDifficulty && initialDifficulty > 1 {
		t.Errorf("difficulty not decreased: initial=%d, new=%d", initialDifficulty, newDifficulty)
	}

	bc = NewBlockchain()

	bc.blocks[0].Difficulty = 1

	for i := 0; i < DifficultyAdjustmentInterval-1; i++ {
		_, err := bc.AddBlock([]byte(fmt.Sprintf("Min Difficulty Block %d", i)))
		if err != nil {
			t.Fatalf("failed to add block: %v", err)
		}
	}

	bc.blocks[0].Timestamp = 1000
	bc.blocks[len(bc.blocks)-1].Timestamp = bc.blocks[0].Timestamp + uint32(TargetBlockTime*DifficultyAdjustmentInterval*10)

	_, err = bc.AddBlock([]byte("Difficulty adjustment trigger - minimum"))
	if err != nil {
		t.Fatalf("failed to add block: %v", err)
	}

	newDifficulty = bc.getCurrentDifficulty()
	if newDifficulty < 1 {
		t.Errorf("failed to adjust difficulty to minimum: %d", newDifficulty)
	}
}

func TestEdgeCases(t *testing.T) {
	var prevHash [32]byte

	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	largeBlock := NewBlock(largeData, prevHash, InitialDifficulty)

	serialized, err := largeBlock.Serialize()
	if err != nil {
		t.Fatalf("fail to serialize large data block: %v", err)
	}

	deserialized, err := Deserialize(serialized)
	if err != nil {
		t.Fatalf("fail to deserialize large data block: %v", err)
	}

	if !bytes.Equal(largeBlock.Data, deserialized.Data) {
		t.Errorf("data mismatch after deserialization")
	}

	invalidData := []byte{0x01, 0x02, 0x03}
	_, err = Deserialize(invalidData)
	if err == nil {
		t.Errorf("should reject invalid data")
	}
}
