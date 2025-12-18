package mounts

import (
	"bytes"
	"log"
	"os"
	"sync"
	"time"
)

// MountWatcher monitors /proc/mounts for changes
type MountWatcher struct {
	interval     time.Duration
	lastContent  []byte
	callbacks    []func(map[uint64]MountInfo)
	mu           sync.RWMutex
	stopChan     chan struct{}
	stoppedChan  chan struct{}
	currentMounts map[uint64]MountInfo
}

// NewMountWatcher creates a new mount watcher
func NewMountWatcher(interval time.Duration) *MountWatcher {
	return &MountWatcher{
		interval:    interval,
		callbacks:   make([]func(map[uint64]MountInfo), 0),
		stopChan:    make(chan struct{}),
		stoppedChan: make(chan struct{}),
	}
}

// OnChange registers a callback for mount changes
func (w *MountWatcher) OnChange(callback func(map[uint64]MountInfo)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.callbacks = append(w.callbacks, callback)
}

// GetCurrentMounts returns the current NFS mounts
func (w *MountWatcher) GetCurrentMounts() map[uint64]MountInfo {
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	// Return a copy
	result := make(map[uint64]MountInfo)
	for k, v := range w.currentMounts {
		result[k] = v
	}
	return result
}

// Start begins watching for mount changes
func (w *MountWatcher) Start() error {
	// Initial read
	content, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return err
	}
	w.lastContent = content

	// Initial mount detection
	mounts, err := DetectNFSMounts()
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.currentMounts = mounts
	w.mu.Unlock()

	// Start watching
	go w.watch()
	return nil
}

// Stop stops the watcher
func (w *MountWatcher) Stop() {
	close(w.stopChan)
	<-w.stoppedChan
}

func (w *MountWatcher) watch() {
	defer close(w.stoppedChan)
	
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopChan:
			return
		case <-ticker.C:
			w.checkForChanges()
		}
	}
}

func (w *MountWatcher) checkForChanges() {
	content, err := os.ReadFile("/proc/mounts")
	if err != nil {
		log.Printf("Error reading /proc/mounts: %v", err)
		return
	}

	// Check if content changed
	if bytes.Equal(content, w.lastContent) {
		return
	}
	w.lastContent = content

	// Re-detect NFS mounts
	newMounts, err := DetectNFSMounts()
	if err != nil {
		log.Printf("Error detecting NFS mounts: %v", err)
		return
	}

	// Check for actual NFS mount changes
	w.mu.Lock()
	oldMounts := w.currentMounts
	w.currentMounts = newMounts
	w.mu.Unlock()

	// Compare old and new
	if !mountsEqual(oldMounts, newMounts) {
		// Log changes
		added, removed := diffMounts(oldMounts, newMounts)
		for _, m := range added {
			log.Printf("New NFS mount detected: %s on %s (device_id: %d)",
				m.Device, m.Mountpoint, m.DeviceID)
		}
		for _, m := range removed {
			log.Printf("NFS mount removed: %s on %s (device_id: %d)",
				m.Device, m.Mountpoint, m.DeviceID)
		}

		// Notify callbacks
		w.mu.RLock()
		callbacks := w.callbacks
		w.mu.RUnlock()

		for _, cb := range callbacks {
			cb(newMounts)
		}
	}
}

func mountsEqual(a, b map[uint64]MountInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv.Mountpoint != v.Mountpoint {
			return false
		}
	}
	return true
}

func diffMounts(old, new map[uint64]MountInfo) (added, removed []MountInfo) {
	for k, v := range new {
		if _, ok := old[k]; !ok {
			added = append(added, v)
		}
	}
	for k, v := range old {
		if _, ok := new[k]; !ok {
			removed = append(removed, v)
		}
	}
	return
}
