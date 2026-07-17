package storage

import (
	"errors"
	"strings"
	"sync"
)

// implements Storage interface
type InMemoryStorage struct {
	*InProcessWatcher
	mu sync.RWMutex
	db map[string]*Device
}

func NewMemoryStorage() *InMemoryStorage {
	db := make(map[string]*Device)
	return &InMemoryStorage{
		InProcessWatcher: NewInProcessWatcher(),
		db:               db,
	}
}

func (s *InMemoryStorage) Open() error {
	return nil
}

func (s *InMemoryStorage) Close() error {
	return nil
}

func (s *InMemoryStorage) Save(device *Device) error {
	s.mu.Lock()
	s.db[key(device)] = device
	s.mu.Unlock()
	s.EmitAdd(device)
	return nil
}

func (s *InMemoryStorage) List(username string) ([]*Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.list(username), nil
}

// list returns all devices for the given username (or all devices if
// username is empty). Callers must hold s.mu.
func (s *InMemoryStorage) list(username string) []*Device {
	devices := []*Device{}
	prefix := func() string {
		if username != "" {
			return keyStr(username, "")
		}
		return ""
	}()
	for key, device := range s.db {
		if strings.HasPrefix(key, prefix) {
			devices = append(devices, device)
		}
	}
	return devices
}

func (s *InMemoryStorage) Get(owner string, name string) (*Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	device, ok := s.db[keyStr(owner, name)]
	if !ok {
		return nil, errors.New("device doesn't exist")
	}
	return device, nil
}

func (s *InMemoryStorage) GetByPublicKey(publicKey string) (*Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, device := range s.list("") {
		if device.PublicKey == publicKey {
			return device, nil
		}
	}
	return nil, errors.New("device doesn't exist")
}

func (s *InMemoryStorage) Delete(device *Device) error {
	s.mu.Lock()
	delete(s.db, key(device))
	s.mu.Unlock()
	s.EmitDelete(device)
	return nil
}

func (s *InMemoryStorage) Ping() error {
	return nil
}
