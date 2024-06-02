package main

import (
	"bytes"
	"crypto/rand"
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

var subscribers = make(map[string]Subscriber)

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
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}
	return string(bytes), nil
}

func main() {
	http.HandleFunc("/publish", handlePublish)
	http.HandleFunc("/", handleRequests)

	fmt.Println("Started server")

	// Last thing to do:
	http.ListenAndServe(":8080", nil)
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

func verifyIntent(callback string, topic string) {
	// Define the base URL for the hub
	hubURL := callback // Replace with the actual hub URL

	// Construct the query parameters
	challenge, err := randomString(32)
	if assertError(err) {
		return
	}

	lease_seconds := string(5 * 60)

	queryParams := url.Values{}
	queryParams.Add("hub.mode", "subscribe")
	queryParams.Add("hub.topic", topic)
	queryParams.Add("hub.callback", callback)
	queryParams.Add("hub.challenge", challenge)
	queryParams.Add("hub.lease_seconds", lease_seconds)
	// Add more query parameters here if needed

	// Append the query parameters to the hub URL
	fullURL := fmt.Sprintf("%s?%s", hubURL, queryParams.Encode())

	body, err := getBody(fullURL)
	if assertError(err) {
		return
	}

	// Print the response body
	if challenge == string(body) {
		fmt.Println("Correct challenge in response.")
	} else {
		fmt.Println("Incorrect challenge in response.")
		//http.Error(w, "Invalid form data", http.StatusBadRequest)
		//return
	}
}
func handleRequests(w http.ResponseWriter, r *http.Request) {
	//fmt.Println("\n\nHej nu hanldar vi\n\n")
	switch r.Method {
	case http.MethodGet:

	case http.MethodPost: // Initial subscription request

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		mode := r.FormValue("hub.mode")
		callback := r.FormValue("hub.callback")
		topic := r.FormValue("hub.topic")

		if mode == "subscribe" {
			if topic == "a-topic" {
				addSubscriber(callback, "secret", topic)
			} else {
				// 400 bad request
				http.Error(w, "Invalid subscription topic", http.StatusBadRequest)
				return
			}

			verifyIntent(callback, topic)

			fmt.Println("Mode, topic, callback: ", mode, r.FormValue("hub.topic"), r.FormValue("hub.callback"))
			printSubscribers()
		} else if mode == "unsubscribe" {
			removeSubscriber(callback)
		}
	}
}

func sendPostRequest(callbackURL string, data []byte) {
	req, err := http.NewRequest("POST", callbackURL, bytes.NewBuffer(data))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

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
		messageData := []byte(`{"title":"New Article","url":"http://example.com/new-article"}`)
		sendPostRequest(subscriber.Callback, messageData)
	}
}

// If for example subscriber attempts to subscribe to unexisting topic: "400 bad request"
// If hub accepts request: "202 accepted"

//1.  Subscriber will send "form-encoded POST request to the hub with:"
/*
hub.mode = "subscribe"
hub.topic = "URL with content subscribers are subscribing to 'a-topic'"
hub.callback = "URL that subscribers want hub to send notifications to, so must be
publicly accesible"

Q: Must URLs be full-length? Yes seems like it
*/

//2. Hub sends vericification by a GET request BACK to subscriber with:
/*
hub.mode = "subscribe"
hub.topic = "Topic URL from subscription request"
hub.challenge = "Hub-generated 'random' string that must be echoed by subscriber"
hub.lease_seconds = "Hub-determined number of secs that subscription will stay alive,
after which a resub is needed."

*/

//3. Subscriber confirms with a 200 OK and a "request body" of the exact same string
// generated in "hub.challenge", not anyhting else and not form encoded
