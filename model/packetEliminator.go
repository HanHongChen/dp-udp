package model

import (
	"fmt"
	"sync"
	"time"
)

type PacketEliminator struct {
	mutex       sync.Mutex
	seenPackets map[uint64]time.Time
	cleanupSize int
}

func NewPacketEliminator(size int) *PacketEliminator {
	return &PacketEliminator{
		seenPackets: make(map[uint64]time.Time),
		cleanupSize: size,
	}
}

func (pe *PacketEliminator) CheckAndMark(seqNum uint64) bool {
	pe.mutex.Lock()
	defer pe.mutex.Unlock()

	// check if already seen
	if _, exists := pe.seenPackets[seqNum]; exists {
		return true
	}

	// mark as seen
	pe.seenPackets[seqNum] = time.Now()

	// Periodic cleanup
	if len(pe.seenPackets) > pe.cleanupSize {
		pe.cleanup()
	}

	return false
}

func (pe *PacketEliminator) cleanup() {
	expireTime := time.Now().Add(-30 * time.Second)
	cleanedCount := 0

	for seqNum, timestamp := range pe.seenPackets {
		if timestamp.Before(expireTime) {
			delete(pe.seenPackets, seqNum)
			cleanedCount++
		}
	}

	if cleanedCount > 0 {
		fmt.Printf("PacketEliminator cleaned %d expired entries, remaining: %d\n",
			cleanedCount, len(pe.seenPackets))
	}
}

func (pe *PacketEliminator) ForceCleanup() {
	pe.mutex.Lock()
	defer pe.mutex.Unlock()
	pe.cleanup()
}
