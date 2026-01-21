package shared

import (
	"encoding/binary"
	"errors"
	"math"
	"sync"
)

// Griseo RH (Guard of anti-Replay by Incremental Seq and Epoch Order (with) Rotation Helper)

// About additional key-rotation helper feature:
//
// You can set an interval, which is a power of 2, if seq % interval == 0,
// Related functions will return a true. That means, after you process this
// message, you should rotate the key.
//
// Warning: you need a reliable and ordered stream like TCP or WSS to use it,
// or your key rotation process will be totally a mess!

// AntiReplayHeader should be transport in Big-Endian (a.k.a. Network Bytes Order).
//
// Format of data using this:
//
// [Epoch (4B Big-Endian Uint)][Seq (8B Big-Endian Uint)][Protected Data]
//
// Use it with AEAD is STRONGLY RECOMMENDED.
type AntiReplayHeader struct {
	Epoch uint32
	Seq   uint64
}

func (header *AntiReplayHeader) Marshal() []byte {
	bin := make([]byte, 12)
	binary.BigEndian.PutUint32(bin[:4], header.Epoch)
	binary.BigEndian.PutUint64(bin[4:12], header.Seq)
	return bin
}

var ErrDataTooShort = errors.New("anti-replay header requires at least 12 bytes")
var ErrEpochIsTooLarge = errors.New("epoch is too large")

func SplitAntiReplayHeader(data []byte) (AntiReplayHeader, []byte, error) {
	if len(data) < 12 {
		return AntiReplayHeader{}, nil, ErrDataTooShort
	}
	return AntiReplayHeader{
		Epoch: binary.BigEndian.Uint32(data[:4]),
		Seq:   binary.BigEndian.Uint64(data[4:12]),
	}, data[12:], nil
}

type AntiReplayChecker struct {
	minValidEpoch       uint32
	minValidSeq         uint64
	keyRotationInterval uint64 // Must be power of 2. 0 = disabled. As "message count".
	mu                  sync.Mutex
}

var ErrInvalidKeyRotationInterval = errors.New("invalid key rotation interval")

func NewAntiReplayChecker(keyRotationInterval uint64) (*AntiReplayChecker, error) {
	if keyRotationInterval != 0 && ((keyRotationInterval-1)&keyRotationInterval) != 0 {
		return nil, ErrInvalidKeyRotationInterval
	}
	return &AntiReplayChecker{
		minValidEpoch:       0,
		minValidSeq:         0,
		keyRotationInterval: keyRotationInterval,
	}, nil
}

func NewAntiReplayCheckerWithStart(minValidEpoch uint32, minValidSeq uint64, keyRotationInterval uint64) (*AntiReplayChecker, error) {
	checker, err := NewAntiReplayChecker(keyRotationInterval)
	if err != nil {
		return nil, err
	}
	checker.minValidEpoch = minValidEpoch
	checker.minValidSeq = minValidSeq
	return checker, nil
}

func (checker *AntiReplayChecker) State() (uint32, uint64, uint64) {
	checker.mu.Lock()
	defer checker.mu.Unlock()
	return checker.minValidEpoch, checker.minValidSeq, checker.keyRotationInterval
}

// Do not add mu.Lock here!
func (checker *AntiReplayChecker) maybeIncEpoch(header AntiReplayHeader) (bool, bool, error) {
	if header.Seq == math.MaxUint64 {
		if header.Epoch == math.MaxUint32 {
			return false, false, ErrEpochIsTooLarge
		}
		checker.minValidEpoch += 1
	}
	checker.minValidSeq = header.Seq + 1 // If header.Seq == math.MaxUint64, +1 will overflow to 0.
	return true, checker.keyRotationInterval != 0 && header.Seq&(checker.keyRotationInterval-1) == 0, nil
}

// Returns: Pass or not, Need key rotation or not, Error.
func (checker *AntiReplayChecker) Check(header AntiReplayHeader) (bool, bool, error) {
	checker.mu.Lock()
	defer checker.mu.Unlock()
	switch {
	case header.Epoch > checker.minValidEpoch:
		checker.minValidEpoch = header.Epoch
		return checker.maybeIncEpoch(header)

	case header.Epoch < checker.minValidEpoch:
		return false, false, nil

	case header.Epoch == checker.minValidEpoch:
		if header.Seq >= checker.minValidSeq {
			return checker.maybeIncEpoch(header)
		}
		return false, false, nil
	}
	return false, false, nil
}

// Returns Splited data, Pass or not, Needs key rotation or not.
func (checker *AntiReplayChecker) CheckData(data []byte) ([]byte, bool, bool) {
	header, payload, err := SplitAntiReplayHeader(data)
	if err != nil {
		return nil, false, false
	}
	if ok, keyRotationNeeded, err := checker.Check(header); err == nil && ok {
		return payload, true, keyRotationNeeded
	}
	return nil, false, false
}

type AntiReplayGenerator struct {
	nextEpoch           uint32
	nextSeq             uint64
	keyRotationInterval uint64 // Must be power of 2. 0 = disabled. As "message count".
	mu                  sync.Mutex
}

func NewAntiReplayGenerator(keyRotationInterval uint64) (*AntiReplayGenerator, error) {
	if keyRotationInterval != 0 && ((keyRotationInterval-1)&keyRotationInterval) != 0 {
		return nil, ErrInvalidKeyRotationInterval
	}
	return &AntiReplayGenerator{
		nextEpoch:           0,
		nextSeq:             0,
		keyRotationInterval: keyRotationInterval,
	}, nil
}

func NewAntiReplayGeneratorWithStart(nextEpoch uint32, nextSeq uint64, keyRotationInterval uint64) (*AntiReplayGenerator, error) {
	generator, err := NewAntiReplayGenerator(keyRotationInterval)
	if err != nil {
		return nil, err
	}
	generator.nextEpoch = nextEpoch
	generator.nextSeq = nextSeq
	return generator, nil
}

// Returns generator.nextEpoch, generator.nextSeq, generator.keyRotationInterval.
func (generator *AntiReplayGenerator) State() (uint32, uint64, uint64) {
	generator.mu.Lock()
	defer generator.mu.Unlock()
	return generator.nextEpoch, generator.nextSeq, generator.keyRotationInterval
}

func (generator *AntiReplayGenerator) NextHeader() (AntiReplayHeader, bool, error) {
	generator.mu.Lock()
	defer generator.mu.Unlock()
	header := AntiReplayHeader{Epoch: generator.nextEpoch, Seq: generator.nextSeq}
	if generator.nextSeq == math.MaxUint64 {
		if generator.nextEpoch == math.MaxUint32 {
			return header, false, ErrEpochIsTooLarge
		}
		generator.nextEpoch += 1
	}
	generator.nextSeq += 1 // If generator.nextSeq == math.MaxUint64, +1 will overflow to 0.
	return header, generator.keyRotationInterval != 0 && header.Seq&(generator.keyRotationInterval-1) == 0, nil
}

func (generator *AntiReplayGenerator) NextAttachToData(data []byte) ([]byte, bool, error) {
	header, keyRotationNeeded, err := generator.NextHeader()
	if err != nil {
		return nil, false, err
	}
	return append(header.Marshal(), data...), keyRotationNeeded, nil
}
