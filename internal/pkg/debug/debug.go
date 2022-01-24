package debug

import (
	"fmt"
	"time"
)

var Enabled bool

func Log(format string, args ...interface{}) {
	if !Enabled {
		return
	}
	line := fmt.Sprintf(format, args...)
	fmt.Printf("[DEBUG][%s] %s\n", time.Now(), line)
}
