/*

	This is an implementation of a hub according to websub protocol: https://www.w3.org/TR/websub/
	using docker. It does not include an implementation for the publisher and the hub merely
	sends a "dummy" message acting as a publisher to ensure functionality.

	Written by Axel Lystam, 2024-06-12

*/

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

var client = &http.Client{
	Timeout: time.Second * 10, // If server takes longer than 10 seconds to response, return error
}

type Subscriber struct {
	Callback string
	Secret   string
	Topic    string
}

// Currently only locally stored map of subscribers, should probably be more sophisticated for release
var subscribers = make(map[string]Subscriber)

// Mutex for possible async accesses of subscribers
var mutex = &sync.Mutex{}

/*
	Add new subscriber on successful subscription
*/

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

/*
	Remove subscriber on unsubscription event
*/

func removeSubscriber(callback string) {
	// Lock access to map containing subscribers
	mutex.Lock()
	defer mutex.Unlock()
	delete(subscribers, callback)
}

/*
	Print all current active subscriptions
*/

func printSubscribers() {
	// Lock access to map containing subscribers
	mutex.Lock()
	defer mutex.Unlock()

	fmt.Println("Current Subscribers:")
	for id, subscriber := range subscribers {
		fmt.Printf("ID: %s, Callback: %s, Secret: %s, Topic: %s\n", id, subscriber.Callback, subscriber.Secret, subscriber.Topic)
	}
}

/*
	Generates random string based on predefined charset.
	Uses dynamic slice with specified length, due to not knowing length until runtime.
	Uses values from rand.reader modulo with charset to get random values for characters,
	instead of just random integer values.
*/

func randomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}
	return string(bytes), nil
}

/*
	Uses sha256 to generate signature based on payload and the corresponding secret of the
	subscriber.
*/

func generateSignature(data []byte, secret string) string {
	hmac := hmac.New(sha256.New, []byte(secret))
	hmac.Write(data)
	return hex.EncodeToString(hmac.Sum(nil))
}

/*
	Send GET request to subscriber
*/

func getBody(fullURL string) ([]byte, error) {
	// Create a new HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating GET request: %w", err)
	}
	// Perform the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing GET request: %w", err)
	}
	defer resp.Body.Close()
	// Validate response code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("received invalid response status: %s", resp.Status)
	}
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}
	return body, nil
}

/*
	Construct the URL for verifying intent of subscriber. Challenge is a random string that
	should be returned by subscriber. "leaseSeconds" specifies the number of seconds the
	subscription is active.
*/

func constructFullURL(topic string, callback string, challenge string) string {
	leaseSeconds := strconv.Itoa(5 * 60)
	// Construct the query parameters
	queryParams := url.Values{}
	queryParams.Add("hub.mode", "subscribe")
	queryParams.Add("hub.topic", topic)
	queryParams.Add("hub.callback", callback)
	queryParams.Add("hub.challenge", challenge)
	queryParams.Add("hub.lease_seconds", leaseSeconds)

	// Append the query parameters to the hub URL
	fullURL := fmt.Sprintf("%s?%s", callback, queryParams.Encode())
	return fullURL
}

/*
	Used to verify the intent of the subscriber by the hub. Expects a challenge
	identical to the randomly generated one that the hub created.
*/

func verifyIntent(callback string, topic string, w http.ResponseWriter) (bool, error) {
	// The secret must be less than 200 bytes in length,
	// (https://www.w3.org/TR/websub/#x5-1-subscriber-sends-subscription-request)
	secretLength := 100
	challenge, err := randomString(secretLength)
	if err != nil {
		return false, fmt.Errorf("error generating challenge: %w", err)
	}

	// Construct GET URL
	fullURL := constructFullURL(topic, callback, challenge)

	// Get response from subscriber, which should be challenge in this case
	body, err := getBody(fullURL)
	if err != nil {
		return false, fmt.Errorf("error getting response from subscriber: %w", err)
	}

	// Primitive comparison, but the premise is that the body will only contain the challenge
	if challenge != string(body) {
		return false, fmt.Errorf("received incorrect challenge")
	}

	return true, nil
}

/*
	Handles subscriptions and unsubscriptions from subscribers
*/

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

		// Ensure all required form values are provided
		if mode == "" || callback == "" || topic == "" || secret == "" {
			http.Error(w, "Missing required form values", http.StatusBadRequest)
			return
		}

		switch mode {
		case "subscribe":
			if topic != "a-topic" {
				http.Error(w, "Invalid subscription topic", http.StatusBadRequest)
				return
			}
			addSubscriber(callback, secret, topic)
			if success, err := verifyIntent(callback, topic, w); !success {
				log.Printf("Error verifying intent: %v\n", err)
				http.Error(w, "Intent not successfully verified", http.StatusNotFound)
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Subscribed successfully"))

		case "unsubscribe":
			removeSubscriber(callback)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Unsubscribed successfully"))

		default:
			http.Error(w, "Invalid mode value", http.StatusBadRequest)
		}
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

/*
	Constructs POST request sent to all subscribers that are currently registered
*/

func publish(callbackURL string, secret string, data []byte) error {
	req, err := http.NewRequest("POST", callbackURL, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	signature := generateSignature(data, secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hub-Signature", "sha256="+signature)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request to %s: %w", callbackURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("received invalid response status: %s", resp.Status)
	}

	log.Printf("Sent publish message to %s, response status: %s\n", callbackURL, resp.Status)
	return nil
}

/*
	Sends a dummy payload to all the subscribers
*/

func handlePublish(w http.ResponseWriter, r *http.Request) {

	for _, subscriber := range subscribers {
		messageData := []byte(`{"title":"Payload to subscribers","message":"Hi everyone"}`)

		if err := publish(subscriber.Callback, subscriber.Secret, messageData); err != nil {
			log.Printf("Error publishing to subscriber %s: %v\n", subscriber.Callback, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func main() {
	http.HandleFunc("/publish", handlePublish)
	http.HandleFunc("/", handleRequests)

	fmt.Println("Started server")

	http.ListenAndServe(":8080", nil)
}
