package storage

import (
	"errors"
	"sync"
)

// implements Storage interface
type InMemoryStorage struct {
	*InProcessWatcher
	mu sync.RWMutex
	// allocationMu is separate from mu because the function run under it
	// calls List and Save, which take mu themselves.
	allocationMu sync.Mutex
	db           map[string]*Device
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

func (s *InMemoryStorage) RecordMetadata(updates []MetadataUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	byPublicKey := make(map[string]*Device, len(s.db))
	for _, device := range s.db {
		byPublicKey[device.PublicKey] = device
	}

	for _, update := range updates {
		device, ok := byPublicKey[update.PublicKey]
		if !ok {
			// the device was deleted in the meantime; don't resurrect it
			continue
		}
		device.ReceiveBytes += update.ReceiveBytes
		device.TransmitBytes += update.TransmitBytes
		if update.Connection != nil {
			handshake := update.Connection.LastHandshakeTime
			device.Endpoint = update.Connection.Endpoint
			device.LastHandshakeTime = &handshake
		}
	}
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
	for _, device := range s.db {
		if username == "" || device.Owner == username {
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

func (s *InMemoryStorage) Rename(device *Device, newName string) (*Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, ok := s.db[key(device)]
	if !ok {
		return nil, errors.New("device doesn't exist")
	}

	renamed := *stored
	renamed.Name = newName
	delete(s.db, key(stored))
	s.db[key(&renamed)] = &renamed
	return &renamed, nil
}

func (s *InMemoryStorage) Ping() error {
	return nil
}

// WithAllocationLock serializes device creation. An in-memory store only ever
// has one server instance, so a process lock is enough.
func (s *InMemoryStorage) WithAllocationLock(fn func() error) error {
	s.allocationMu.Lock()
	defer s.allocationMu.Unlock()
	return fn()
}
