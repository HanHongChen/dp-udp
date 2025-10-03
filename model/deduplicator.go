package model

import (
	"sync"
	"time"
)

// PacketDeduplicator manages packet deduplication using iperf3 sequence numbers
type PacketDeduplicator struct {
	seenPackets   map[uint64]time.Time // sequence number -> received time
	maxSeqNum     uint64               // highest sequence number seen
	outOfOrder    uint64               // count of out-of-order packets
	duplicates    uint64               // count of duplicate packets
	lost          uint64               // count of lost packets (gaps in sequence)
	mutex         sync.RWMutex
	cleanupPeriod time.Duration        // how often to clean old entries
	entryTTL      time.Duration        // how long to keep entries
	lastCleanup   time.Time
}

// NewPacketDeduplicator creates a new packet deduplicator
func NewPacketDeduplicator() *PacketDeduplicator {
	return &PacketDeduplicator{
		seenPackets:   make(map[uint64]time.Time),
		cleanupPeriod: 30 * time.Second,
		entryTTL:      5 * time.Minute,
		lastCleanup:   time.Now(),
	}
}

// ProcessPacket processes a packet and returns whether it should be forwarded
// Returns true if packet is new and should be processed, false if duplicate
func (pd *PacketDeduplicator) ProcessPacket(seqNum uint64) (shouldProcess bool, stats PacketStats) {
	pd.mutex.Lock()
	defer pd.mutex.Unlock()

	now := time.Now()
	
	// Clean up old entries periodically
	if now.Sub(pd.lastCleanup) > pd.cleanupPeriod {
		pd.cleanup(now)
	}

	// Check if we've seen this packet before
	if lastSeen, exists := pd.seenPackets[seqNum]; exists {
		pd.duplicates++
		stats = PacketStats{
			SeqNum:        seqNum,
			IsDuplicate:   true,
			IsOutOfOrder:  false,
			MaxSeqNum:     pd.maxSeqNum,
			Duplicates:    pd.duplicates,
			OutOfOrder:    pd.outOfOrder,
			Lost:          pd.lost,
			LastSeen:      lastSeen,
		}
		return false, stats
	}

	// Record this packet
	pd.seenPackets[seqNum] = now

	// Check if this is out of order or creates gaps
	isOutOfOrder := false
	if seqNum < pd.maxSeqNum {
		// Out of order packet
		pd.outOfOrder++
		isOutOfOrder = true
	} else if seqNum > pd.maxSeqNum+1 {
		// Gap detected - count as lost packets
		gap := seqNum - pd.maxSeqNum - 1
		pd.lost += gap
		pd.maxSeqNum = seqNum
	} else {
		// Sequential packet
		pd.maxSeqNum = seqNum
	}

	stats = PacketStats{
		SeqNum:       seqNum,
		IsDuplicate:  false,
		IsOutOfOrder: isOutOfOrder,
		MaxSeqNum:    pd.maxSeqNum,
		Duplicates:   pd.duplicates,
		OutOfOrder:   pd.outOfOrder,
		Lost:         pd.lost,
		LastSeen:     now,
	}

	return true, stats
}

// cleanup removes old entries to prevent memory leaks
func (pd *PacketDeduplicator) cleanup(now time.Time) {
	cutoff := now.Add(-pd.entryTTL)
	for seqNum, timestamp := range pd.seenPackets {
		if timestamp.Before(cutoff) {
			delete(pd.seenPackets, seqNum)
		}
	}
	pd.lastCleanup = now
}

// GetStats returns current deduplication statistics
func (pd *PacketDeduplicator) GetStats() PacketStats {
	pd.mutex.RLock()
	defer pd.mutex.RUnlock()

	return PacketStats{
		MaxSeqNum:  pd.maxSeqNum,
		Duplicates: pd.duplicates,
		OutOfOrder: pd.outOfOrder,
		Lost:       pd.lost,
	}
}

// Reset clears all deduplication state
func (pd *PacketDeduplicator) Reset() {
	pd.mutex.Lock()
	defer pd.mutex.Unlock()

	pd.seenPackets = make(map[uint64]time.Time)
	pd.maxSeqNum = 0
	pd.outOfOrder = 0
	pd.duplicates = 0
	pd.lost = 0
	pd.lastCleanup = time.Now()
}

// PacketStats contains statistics about packet processing
type PacketStats struct {
	SeqNum       uint64
	IsDuplicate  bool
	IsOutOfOrder bool
	MaxSeqNum    uint64
	Duplicates   uint64
	OutOfOrder   uint64
	Lost         uint64
	LastSeen     time.Time
}