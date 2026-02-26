package policy

import (
	"log"
	"os"
	"sync"
	"time"
)

// WatchingCache monitors a policy file and reloads on changes.
type WatchingCache struct {
	engine   *Engine
	path     string
	modTime  time.Time
	mu       sync.RWMutex
	stopCh   chan struct{}
}

// NewWatchingCache creates a cache that polls the policy file for changes.
func NewWatchingCache(engine *Engine, path string) *WatchingCache {
	c := &WatchingCache{
		engine: engine,
		path:   path,
		stopCh: make(chan struct{}),
	}

	if path != "" {
		if info, err := os.Stat(path); err == nil {
			c.modTime = info.ModTime()
		}
		go c.watch()
	}

	return c
}

// Engine returns the current policy engine.
func (c *WatchingCache) Engine() *Engine {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.engine
}

func (c *WatchingCache) watch() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.checkReload()
		}
	}
}

func (c *WatchingCache) checkReload() {
	if c.path == "" {
		return
	}

	info, err := os.Stat(c.path)
	if err != nil {
		return
	}

	if !info.ModTime().After(c.modTime) {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	newEngine, err := NewEngine(c.path)
	if err != nil {
		log.Printf("policy reload failed: %v", err)
		return
	}

	c.engine = newEngine
	c.modTime = info.ModTime()
	log.Printf("policy hot-reloaded from %s", c.path)
}

// Stop terminates the file watcher.
func (c *WatchingCache) Stop() {
	close(c.stopCh)
}
