package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/subscribe", handleSubscribe)
	http.HandleFunc("/publish", handlePublish)

	http.ListenAndServe(":8080", nil)

	fmt.Println("Started server")
}

func handleSubscribe(w http.ResponseWriter, r *http.Request) {
	// Handle sub registration
	// Verify intent
	// Respond correctly

	if r.Method != "POST" {
		http.Error(w, "This method is not allowed", http.StatusMethodNotAllowed)
		return
	}

	/*
			if err := r.ParseForm(); err != nil {
		        http.Error(w, "Invalid form data", http.StatusBadRequest)
		        return
		    }
	*/

	mode := r.FormValue("hub.mode")
	topic := r.FormValue("hub.topic")
	callback := r.FormValue("hub.callback")

	if mode == "subscribe" {

	} else if mode == "unsubscribe" {

	} else {
		http.Error(w, "Invalid mode", http.StatusBadRequest)
	}

}

func handlePublish(w http.ResponseWriter, r *http.Request) {
	// Generate JSON data
	// Sign message
	// Post to all subscribers
}

// Use this signature to create X-hub signature header for outgoing
// post requests to subscriber
func generateSignature(data, secret string) string {
	hmac := hmac.New(sha256.New, []byte(secret))
	hmac.Write([]byte(data))
	return hex.EncodeToString(hmac.Sum(nil))
}
