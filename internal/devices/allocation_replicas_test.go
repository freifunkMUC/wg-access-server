package devices

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
)

const (
	replicaWorkerEnv  = "WG_TEST_ALLOCATION_WORKER"
	replicaStartEnv   = "WG_TEST_ALLOCATION_START"
	devicesPerReplica = 30
	replicaOwner      = "allocation-test-replica-"
	replicaCount      = 3
)

// Several server replicas share one Postgres database and create devices at
// the same time. Each replica is a separate process with its own connection
// pool and its own in-process locks - exactly what a test inside a single
// process cannot model, because it would share every package-level mutex.
// No two devices may end up with the same tunnel address.
//
// Needs a real server: WG_TEST_POSTGRES_URI=postgresql://user:pass@host/db?sslmode=disable
func TestAllocationAcrossReplicas(t *testing.T) {
	uri := os.Getenv("WG_TEST_POSTGRES_URI")
	if uri == "" {
		t.Skip("WG_TEST_POSTGRES_URI not set")
	}

	s := openStorage(t, uri)
	clearReplicaDevices(t, s)
	t.Cleanup(func() { clearReplicaDevices(t, s) })

	// start all replicas at the same instant so their allocations overlap
	start := time.Now().Add(3 * time.Second).UnixNano()
	var wg sync.WaitGroup
	outputs := make([]string, replicaCount)
	errs := make([]error, replicaCount)
	for i := 0; i < replicaCount; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestAllocationWorker$", "-test.v")
			cmd.Env = append(os.Environ(),
				replicaWorkerEnv+"="+strconv.Itoa(i),
				replicaStartEnv+"="+strconv.FormatInt(start, 10),
			)
			out, err := cmd.CombinedOutput()
			outputs[i], errs[i] = string(out), err
		}(i)
	}
	wg.Wait()
	for i := range errs {
		require.NoError(t, errs[i], "replica %d failed:\n%s", i, outputs[i])
	}

	all, err := s.List("")
	require.NoError(t, err)
	var devices []*storage.Device
	for _, device := range all {
		if strings.HasPrefix(device.Owner, replicaOwner) {
			devices = append(devices, device)
		}
	}
	require.Len(t, devices, replicaCount*devicesPerReplica, "every replica must have created all its devices")

	owners := map[string][]string{}
	for _, device := range devices {
		for _, addr := range strings.Split(device.Address, ",") {
			addr = strings.TrimSpace(addr)
			owners[addr] = append(owners[addr], device.Owner+"/"+device.Name)
		}
	}
	var duplicates []string
	for addr, holders := range owners {
		if len(holders) > 1 {
			duplicates = append(duplicates, fmt.Sprintf("%s -> %v", addr, holders))
		}
	}
	require.Empty(t, duplicates, "%d tunnel addresses were handed out more than once", len(duplicates))
}

// TestAllocationWorker is one replica of TestAllocationAcrossReplicas. It only
// runs when started by that test.
func TestAllocationWorker(t *testing.T) {
	id := os.Getenv(replicaWorkerEnv)
	if id == "" {
		t.Skip("only runs as a subprocess of TestAllocationAcrossReplicas")
	}
	startNanos, err := strconv.ParseInt(os.Getenv(replicaStartEnv), 10, 64)
	require.NoError(t, err)

	// Open the storage one replica after another: pg-events installs its
	// trigger with CREATE OR REPLACE FUNCTION, and replicas doing that at the
	// same moment fail with "tuple concurrently updated". Allocation, which is
	// what this test is about, still starts at the same instant below.
	n, err := strconv.Atoi(id)
	require.NoError(t, err)
	time.Sleep(time.Duration(n) * 400 * time.Millisecond)
	s := openStorage(t, os.Getenv("WG_TEST_POSTGRES_URI"))
	manager := New(wgembed.NewNoOpInterface(), s, "10.99.0.0/16", "")
	identity := &authsession.Identity{Subject: replicaOwner + id}

	time.Sleep(time.Until(time.Unix(0, startNanos)))
	for n := 0; n < devicesPerReplica; n++ {
		key, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)
		_, err = manager.AddDevice(identity, fmt.Sprintf("device-%d", n), key.PublicKey().String(), "", false, "", "")
		require.NoError(t, err)
	}
}

func openStorage(t *testing.T, uri string) storage.Storage {
	t.Helper()
	s, err := storage.NewStorage(uri)
	require.NoError(t, err)
	require.NoError(t, s.Open())
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// clearReplicaDevices removes the devices this test creates. The database is
// shared with other test packages running in parallel, so leave theirs alone.
func clearReplicaDevices(t *testing.T, s storage.Storage) {
	t.Helper()
	devices, err := s.List("")
	require.NoError(t, err)
	for _, device := range devices {
		if strings.HasPrefix(device.Owner, replicaOwner) {
			require.NoError(t, s.Delete(device))
		}
	}
}
