package oidc

import (
	"fmt"
	"log/slog"
	"sync"
)

var (
	validAudience func(audiences []string) bool
	muxAud        sync.RWMutex
)

func SetValidAudience(f func(audiences []string) bool) {
	muxAud.Lock()
	validAudience = f
	muxAud.Unlock()
}

func validateAudience(audiences []string, aud string) error {
	if aud == "" && validAudience == nil {
		slog.Warn("strongly recommend checking the Audience using SetValidAudience or WithAudience option")
		return nil
	}

	if aud != "" {
		if !cotainsAudience(audiences, aud) {
			return fmt.Errorf("invalid audience (option): want=%s, got=%s", aud, audiences)
		}

		return nil
	}

	var ok bool

	muxAud.RLock()
	if validAudience != nil {
		ok = validAudience(audiences)
	}
	muxAud.RUnlock()

	if !ok {
		return fmt.Errorf("invalid audience (func): got=%v", audiences)
	}

	return nil
}

func cotainsAudience(list []string, aud string) bool {
	for _, v := range list {
		if v == aud {
			return true
		}
	}

	return false
}
