package main

import "math/rand"

func generateToken() string {
	token := rand.Intn(999999)
	return fmt.Sprintf("%06d", token)
}
