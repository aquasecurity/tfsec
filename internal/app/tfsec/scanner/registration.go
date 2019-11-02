package scanner

import (
	"sync"
)

var checkLock sync.Mutex
var registeredChecks []Check

// RegisterCheck registers a new Check which should be run on future scans
func RegisterCheck(check Check) {
	if check.Code == "" {
		panic("check code was not set")
	}
	checkLock.Lock()
	defer checkLock.Unlock()
	registeredChecks = append(registeredChecks, check)
}

// GetRegisteredChecks provides all Checks which have been registered with this package
func GetRegisteredChecks() []Check {
	return registeredChecks
}
