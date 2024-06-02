package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
)

type Subscriber struct {
	Callback string
	Secret   string
	Topic    string
}

// Currently only locally stored map of subscribers, needs to be more sophisticated later on
var subscribers = make(map[string]Subscriber)

// Mutex for possible async accesses of subscribers
var mutex = &sync.Mutex{}

func addSubscriber(callback string, secret string, topic string) {
	sub := Subscriber{
		Callback: callback,
		Secret:   secret,
		Topic:    topic,
	}

	// Lock access to map containing subscribers
	mutex.Lock()
	defer mutex.Unlock()
	subscribers[callback] = sub
}

func removeSubscriber(callback string) {
	// Lock access to map containing subscribers
	mutex.Lock()
	defer mutex.Unlock()
	delete(subscribers, callback)
}

func printSubscribers() {
	mutex.Lock()
	defer mutex.Unlock()

	fmt.Println("Current Subscribers:")
	for id, subscriber := range subscribers {
		fmt.Printf("ID: %s, Callback: %s, Secret: %s, Topic: %s\n", id, subscriber.Callback, subscriber.Secret, subscriber.Topic)
	}
}

func randomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// Allocated dynamic slice with specified length, using slice due to not knowing length
	// until runtime
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}
	return string(bytes), nil
}

func generateSignature(data []byte, secret string) string {
	hmac := hmac.New(sha256.New, []byte(secret))
	hmac.Write(data)
	return hex.EncodeToString(hmac.Sum(nil))
}

func assertError(err error) bool {
	if err != nil {
		fmt.Println(err)
		return true
	} else {
		return false
	}
}

func getBody(fullURL string) ([]byte, error) {
	// Create a new HTTP client
	client := &http.Client{}
	// Create a new HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if assertError(err) {
		return nil, err
	}

	// Perform the HTTP request
	resp, err := client.Do(req)
	if assertError(err) {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if assertError(err) {
		return nil, err
	}
	return body, nil
}

func constructFullURL(topic string, callback string, challenge string) string {
	lease_seconds := string(5 * 60)
	// Construct the query parameters
	queryParams := url.Values{}
	queryParams.Add("hub.mode", "subscribe")
	queryParams.Add("hub.topic", topic)
	queryParams.Add("hub.callback", callback)
	queryParams.Add("hub.challenge", challenge)
	queryParams.Add("hub.lease_seconds", lease_seconds)

	// Append the query parameters to the hub URL
	fullURL := fmt.Sprintf("%s?%s", callback, queryParams.Encode())
	return fullURL
}

func verifyIntent(callback string, topic string, w http.ResponseWriter) {
	// The secret must be less than 200 bytes in length,
	// (https://www.w3.org/TR/websub/#x5-1-subscriber-sends-subscription-request)
	challenge, err := randomString(100)
	if assertError(err) {
		return
	}

	fullURL := constructFullURL(topic, callback, challenge)

	body, err := getBody(fullURL)
	if assertError(err) {
		return
	}

	// Print the response body
	if challenge == string(body) {
		fmt.Println("Challenge completed.")
	} else {
		http.Error(w, "Challenge incorrect", http.StatusBadRequest)
		return
	}
}
func handleRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		mode := r.FormValue("hub.mode")
		callback := r.FormValue("hub.callback")
		topic := r.FormValue("hub.topic")
		secret := r.FormValue("hub.secret")

		if mode == "subscribe" {
			if topic == "a-topic" {
				addSubscriber(callback, secret, topic)
			} else {
				http.Error(w, "Invalid subscription topic", http.StatusBadRequest)
				return
			}

			verifyIntent(callback, topic, w)

			fmt.Printf("Mode: %s, topic: %s, callback: %s\n", mode, r.FormValue("hub.topic"), r.FormValue("hub.callback"))

		} else if mode == "unsubscribe" {
			removeSubscriber(callback)
		}
	} else {
		http.Error(w, "Invalid operation", http.StatusBadRequest)
	}
}

func publish(callbackURL string, secret string, data []byte) {
	req, err := http.NewRequest("POST", callbackURL, bytes.NewBuffer(data))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	signature := generateSignature(data, secret)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hub-Signature", "sha256="+signature)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request to %s: %v\n", callbackURL, err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Sent publish message to %s, response status: %s\n", callbackURL, resp.Status)
}

func handlePublish(w http.ResponseWriter, r *http.Request) {
	for _, subscriber := range subscribers {
		messageData := []byte(`{"title":"Payload to subscribers","message":"Hi everyone"}`)
		publish(subscriber.Callback, subscriber.Secret, messageData)
	}
}

func main() {
	http.HandleFunc("/publish", handlePublish)
	http.HandleFunc("/", handleRequests)

	fmt.Println("Started server")

	// Last thing to do:
	http.ListenAndServe(":8080", nil)
}
