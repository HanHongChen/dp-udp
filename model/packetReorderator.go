package model

import (
	"fmt"
	"sync"
)

type PacketReorderator struct {
	mutex        sync.Mutex
	buffer       map[uint64][]byte
	expectedSeq  uint64
	readyChan    chan [][]byte
	maxBuffer    int    // set max buffer size
	maxWaitGap   uint64 // set max wait gap
	droppedCount uint64 // count of dropped packets
}

func NewPacketReorderator(maxBuffer int, maxWaitGap uint64) *PacketReorderator {
	return &PacketReorderator{
		buffer:      make(map[uint64][]byte),
		expectedSeq: 1,
		readyChan:   make(chan [][]byte, 1000),
		maxBuffer:   maxBuffer,
		maxWaitGap:  maxWaitGap,
	}
}

func (pr *PacketReorderator) AddPacket(seqNum uint64, data []byte) {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()

	if seqNum == pr.expectedSeq {
		// it is the expected packet, handle immediately
		readyPackets := [][]byte{data}
		pr.expectedSeq++

		// check for subsequent ordered packets in the buffer
		for {
			if nextData, exists := pr.buffer[pr.expectedSeq]; exists {
				readyPackets = append(readyPackets, nextData)
				delete(pr.buffer, pr.expectedSeq)
				pr.expectedSeq++
			} else {
				break
			}
		}

		select {
		case pr.readyChan <- readyPackets:
		default:
			fmt.Printf("PacketReorderator readyChan is full, dropping packets\n")
		}
	} else if seqNum > pr.expectedSeq {
		// seqNum > pr.expectedSeq, out-of-order packet

		// check if the gap is too large (possibly an old connection's packet)
		if seqNum > pr.expectedSeq+pr.maxWaitGap {
			pr.droppedCount++
			fmt.Printf("PacketReorderator: dropping packet seq=%d, too far ahead (expected=%d, gap=%d)\n",
				seqNum, pr.expectedSeq, seqNum-pr.expectedSeq)
			return
		}

		// check buffer size
		if len(pr.buffer) >= pr.maxBuffer {
			// drop the oldest packet
			pr.dropOldestPacket()
		}

		// store out-of-order packet
		pr.buffer[seqNum] = data

	} else {
		// seqNum < pr.expectedSeq, dropped packet
		pr.droppedCount++
		fmt.Printf("PacketReorderator: dropping old packet seq=%d (expected=%d)\n",
			seqNum, pr.expectedSeq)
	}
}

func (pr *PacketReorderator) dropOldestPacket() {
	var oldestSeq uint64
	var found bool

	// find the smallest sequence number
	for seqNum := range pr.buffer {
		if !found || seqNum < oldestSeq {
			oldestSeq = seqNum
			found = true
		}
	}

	if found {
		delete(pr.buffer, oldestSeq)
		pr.droppedCount++
		fmt.Printf("PacketReorderator: buffer full, dropped packet seq=%d\n", oldestSeq)
	}
}

func (pr *PacketReorderator) GetReadyChan() <-chan [][]byte {
	return pr.readyChan
}

func (pr *PacketReorderator) Stats() (expected uint64, buffered int, dropped uint64) {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()
	return pr.expectedSeq, len(pr.buffer), pr.droppedCount
}

// ForceDropOld removes packets that are too old from the buffer
func (pr *PacketReorderator) ForceDropOld() {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()

	threshold := pr.expectedSeq + 50 // skip packets older than 50

	droppedInCleanup := 0
	for seqNum := range pr.buffer {
		if seqNum < threshold {
			delete(pr.buffer, seqNum)
			droppedInCleanup++
		}
	}

	if droppedInCleanup > 0 {
		pr.droppedCount += uint64(droppedInCleanup)
		fmt.Printf("PacketReorderator: force cleanup dropped %d old packets\n", droppedInCleanup)
	}
}
