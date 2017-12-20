package tls13measurements

import (
	"net"
	"reflect"
	"sync"
)

var (
	locks sync.Map
)

///////////////////////////////////////////////////////////////////////////////////
// Serializes concurrent accesses to the GrabTarget
// This removes the need to lock a db document during an update run
// as long theres not multiple zgrab instances running concurrently

func ExecuteLocked(mtx *sync.Mutex, obj interface{}, f func(interface{}) interface{}) interface{} {
	type keyEntry struct {
		ip  string
		dom string
	}
	ip := reflect.ValueOf(obj).FieldByName("Addr").Interface().(net.IP)
	dom := reflect.ValueOf(obj).FieldByName("Domain").Interface().(string)
	k := keyEntry{ip: ip.String(), dom: dom}
	for {
		v, loaded := locks.LoadOrStore(k, mtx)
		vmtx := v.(*sync.Mutex)
		vmtx.Lock()
		if !loaded {
			break
		}
		vmtx.Unlock()
	}
	// execute the payload
	res := f(obj)
	locks.Delete(k)
	// right here another goroutine may store a new lock to the map
	// before resuming all frozen goroutines.
	// this is not a problem however, because they will keep waiting on the new lock
	// within their LoadOrStore loop after rewaking them
	mtx.Unlock()
	return res
}
