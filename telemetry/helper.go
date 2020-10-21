package telemetry

import (
	"fmt"
	"time"
)

func GetIndex(start, now time.Time, intervalMS int) (int, error) {
	if now.Before(start) {
		return -1, fmt.Errorf("current time before start")
	}
	idx := int(now.Sub(start) / (time.Millisecond * time.Duration(intervalMS)))

	return idx, nil
}
