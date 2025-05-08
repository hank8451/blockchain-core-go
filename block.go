package blockchain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

type Block struct {
	Version       uint32
	PrevBlockHash [32]byte
	MerkleRoot    [32]byte
	Timestamp     uint32
	Difficulty    uint32
	Nonce         uint32
	Data          []byte
	Hash          [32]byte
}

func NewBlock(data []byte, prevBlockHash [32]byte, difficulty uint32) *Block {
	block := &Block{
		Version:       1,
		PrevBlockHash: prevBlockHash,
		Timestamp:     uint32(time.Now().Unix()),
		Difficulty:    difficulty,
		Data:          data,
	}

	block.MerkleRoot = block.CalculateMerkleRoot(data)
	return block
}

func (b *Block) CalculateMerkleRoot(data []byte) [32]byte {
	return Hash(data)
}

func (b *Block) IsGenesis() bool {
	emptyHash := [32]byte{}
	return b.PrevBlockHash == emptyHash
}

func (b *Block) SerializeHeader() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 80))

	if err := binary.Write(buf, binary.LittleEndian, b.Version); err != nil {
		return nil, fmt.Errorf("failed to serialize block version: %w", err)
	}

	buf.Write(b.PrevBlockHash[:])
	buf.Write(b.MerkleRoot[:])

	if err := binary.Write(buf, binary.LittleEndian, b.Timestamp); err != nil {
		return nil, fmt.Errorf("failed to serialize block timestamp: %w", err)
	}

	if err := binary.Write(buf, binary.LittleEndian, b.Difficulty); err != nil {
		return nil, fmt.Errorf("failed to serialize block difficulty: %w", err)
	}

	if err := binary.Write(buf, binary.LittleEndian, b.Nonce); err != nil {
		return nil, fmt.Errorf("failed to serialize block nonce: %w", err)
	}

	serialized := buf.Bytes()
	if len(serialized) != 80 {
		return nil, fmt.Errorf("serialized block header length is not 80 bytes")
	}
	return serialized, nil
}

func (b *Block) Serialize() ([]byte, error) {
	header, err := b.SerializeHeader()
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	buf.Write(header)
	err = binary.Write(&buf, binary.LittleEndian, uint64(len(b.Data)))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize block data: %w", err)
	}

	buf.Write(b.Data)

	return buf.Bytes(), nil
}

func Deserialize(data []byte) (*Block, error) {
	if len(data) < 80 {
		return nil, fmt.Errorf("data length is insufficient to deserialize block")
	}

	var block Block
	buf := bytes.NewReader(data)

	if err := binary.Read(buf, binary.LittleEndian, &block.Version); err != nil {
		return nil, fmt.Errorf("failed to deserialize version: %w", err)
	}

	if _, err := buf.Read(block.PrevBlockHash[:]); err != nil {
		return nil, fmt.Errorf("failed to deserialize previous block hash: %w", err)
	}

	if _, err := buf.Read(block.MerkleRoot[:]); err != nil {
		return nil, fmt.Errorf("failed to deserialize merkle root: %w", err)
	}

	if err := binary.Read(buf, binary.LittleEndian, &block.Timestamp); err != nil {
		return nil, fmt.Errorf("failed to deserialize timestamp: %w", err)
	}

	if err := binary.Read(buf, binary.LittleEndian, &block.Difficulty); err != nil {
		return nil, fmt.Errorf("failed to deserialize difficulty: %w", err)
	}

	if err := binary.Read(buf, binary.LittleEndian, &block.Nonce); err != nil {
		return nil, fmt.Errorf("failed to deserialize nonce: %w", err)
	}

	var dataLen uint64
	if err := binary.Read(buf, binary.LittleEndian, &dataLen); err != nil {
		return nil, fmt.Errorf("failed to deserialize data length: %w", err)
	}

	block.Data = make([]byte, dataLen)
	if _, err := buf.Read(block.Data); err != nil {
		return nil, fmt.Errorf("failed to deserialize data: %w", err)
	}

	headerBytes, err := block.SerializeHeader()
	if err != nil {
		return nil, err
	}

	block.Hash = Hash(headerBytes)

	return &block, nil
}
