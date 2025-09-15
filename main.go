package main

import (
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type GravatarResponse struct {
	Entry []struct {
		Hash              string `json:"hash"`
		RequestHash       string `json:"requestHash"`
		ProfileURL        string `json:"profileUrl"`
		PreferredUsername string `json:"preferredUsername"`
		ThumbnailURL      string `json:"thumbnailUrl"`
		Photos            []struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"photos"`
		DisplayName string `json:"displayName"`
		AboutMe     string `json:"aboutMe"`
	} `json:"entry"`
}

type Result struct {
	Username      string
	Hash          string
	ProfileURL    string
	DisplayName   string
	AboutMe       string
	ThumbnailURL  string
}

type Stats struct {
	totalChecked   int64
	foundUsers     int64
	startTime      time.Time
	totalUsernames int64
}

var userAgents = []string{
	"curl/7.68.0", "curl/7.81.0", "curl/8.0.1", "curl/8.4.0", "curl/7.74.0",
	"curl/7.88.1", "curl/8.2.1", "curl/7.64.1", "curl/7.58.0", "curl/8.5.0",
	"Wget/1.21.2", "Wget/1.20.3", "Wget/1.21.3", "Wget/1.19.4", "Wget/1.21.1",
	"GNU Wget/1.21.2", "GNU Wget/1.20.3", "GNU Wget/1.21.3",
	"HTTPie/3.2.0", "HTTPie/3.1.0", "HTTPie/2.6.0", "HTTPie/3.0.2",
	"python-requests/2.28.1", "python-requests/2.31.0", "python-requests/2.25.1",
	"python-requests/2.27.1", "python-requests/2.29.0",
	"Go-http-client/1.1", "Go-http-client/2.0",
	"Apache-HttpClient/4.5.13", "okhttp/4.9.3", "okhttp/4.10.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15",
	"Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/117.0",
	"PostmanRuntime/7.32.3", "PostmanRuntime/7.29.2", "PostmanRuntime/7.28.4",
	"Insomnia/2023.5.8", "Paw/3.4.0", "Advanced REST client/17.0.9",
}

var acceptLanguages = []string{
	"en-US,en;q=0.9",
	"en-GB,en;q=0.9,en-US;q=0.8",
	"en-US,en;q=0.8,es;q=0.6",
	"en-CA,en;q=0.9,fr;q=0.8",
	"en-AU,en;q=0.9",
	"en,en-US;q=0.9",
}

var acceptEncodings = []string{
	"gzip, deflate, br",
	"gzip, deflate",
	"gzip, deflate, br, zstd",
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func getRandomAcceptLanguage() string {
	return acceptLanguages[rand.Intn(len(acceptLanguages))]
}

func getRandomAcceptEncoding() string {
	return acceptEncodings[rand.Intn(len(acceptEncodings))]
}

var allCipherSuites = [][]uint16{
	{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256},
	{tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_AES_128_GCM_SHA256},
	{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_AES_128_GCM_SHA256},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 
	 tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
	{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	 tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	 tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
	{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384},
	{tls.TLS_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
}

var allCurvePreferences = [][]tls.CurveID{
	{tls.X25519, tls.CurveP256, tls.CurveP384},
	{tls.CurveP256, tls.CurveP384, tls.X25519},
	{tls.CurveP256, tls.X25519},
	{tls.X25519, tls.CurveP256},
	{tls.CurveP256, tls.CurveP384},
	{tls.CurveP384, tls.CurveP256},
	{tls.X25519},
	{tls.CurveP256},
}

var tlsVersionCombos = [][2]uint16{
	{tls.VersionTLS12, tls.VersionTLS13},
	{tls.VersionTLS12, tls.VersionTLS12},
	{tls.VersionTLS13, tls.VersionTLS13},
	{tls.VersionTLS10, tls.VersionTLS12},
	{tls.VersionTLS11, tls.VersionTLS13},
}

func getRandomTLSConfig() *tls.Config {
	versions := tlsVersionCombos[rand.Intn(len(tlsVersionCombos))]
	ciphers := allCipherSuites[rand.Intn(len(allCipherSuites))]
	curves := allCurvePreferences[rand.Intn(len(allCurvePreferences))]
	
	config := &tls.Config{
		MinVersion:         versions[0],
		MaxVersion:         versions[1],
		CipherSuites:       ciphers,
		CurvePreferences:   curves,
		InsecureSkipVerify: false,
	}
	
	if rand.Intn(10) == 0 {
		config.PreferServerCipherSuites = true
	}
	
	return config
}

func main() {
	const (
		minLength   = 3
		maxLength   = 12
		numWorkers  = 5000
		timeout     = 5 * time.Second
	)

	rand.Seed(time.Now().UnixNano())

	stats := &Stats{
		startTime: time.Now(),
	}

	stats.totalUsernames = calculateTotalUsernamesRange(minLength, maxLength)
	fmt.Printf("Scanning usernames from %d to %d characters\n", minLength, maxLength)
	fmt.Printf("Total usernames to check: %d\n", stats.totalUsernames)
	fmt.Printf("Estimated time (conservative): %.2f hours\n", estimateTime(stats.totalUsernames, numWorkers))

	csvFile, err := os.Create("gravatar_results_3to12.csv")
	if err != nil {
		panic(fmt.Sprintf("Failed to create CSV file: %v", err))
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()

	csvWriter.Write([]string{"Username", "Hash", "ProfileURL", "DisplayName", "AboutMe", "ThumbnailURL"})

	tr := &http.Transport{
		TLSClientConfig:    getRandomTLSConfig(),
		DisableKeepAlives:  true,
		ForceAttemptHTTP2:  rand.Intn(2) == 0,
		DisableCompression: rand.Intn(3) == 0,
		MaxIdleConns:       rand.Intn(10) + 1,
		IdleConnTimeout:    time.Duration(rand.Intn(60)+30) * time.Second,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	usernameChan := make(chan string, numWorkers*2)
	resultChan := make(chan Result, 100)
	done := make(chan bool)

	var csvMutex sync.Mutex

	go progressReporter(stats)

	go func() {
		for result := range resultChan {
			csvMutex.Lock()
			csvWriter.Write([]string{
				result.Username,
				result.Hash,
				result.ProfileURL,
				result.DisplayName,
				result.AboutMe,
				result.ThumbnailURL,
			})
			csvWriter.Flush()
			csvMutex.Unlock()
			
			atomic.AddInt64(&stats.foundUsers, 1)
			fmt.Printf("Found user: %s (%s)\n", result.Username, result.DisplayName)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(client, usernameChan, resultChan, &wg, stats)
	}

	go func() {
		defer close(usernameChan)
		generateUsernamesRange(minLength, maxLength, usernameChan)
	}()

	go func() {
		wg.Wait()
		close(resultChan)
		done <- true
	}()

	<-done
	
	elapsed := time.Since(stats.startTime)
	fmt.Printf("\nCompleted in: %v\n", elapsed)
	fmt.Printf("Total checked: %d\n", atomic.LoadInt64(&stats.totalChecked))
	fmt.Printf("Users found: %d\n", atomic.LoadInt64(&stats.foundUsers))
	fmt.Printf("Results saved to: gravatar_results_3to12.csv\n")
}

func worker(client *http.Client, usernameChan <-chan string, resultChan chan<- Result, wg *sync.WaitGroup, stats *Stats) {
	defer wg.Done()
	
	requestCount := 0
	for username := range usernameChan {
		if requestCount > 0 && requestCount%(50+rand.Intn(100)) == 0 {
			tr := &http.Transport{
				TLSClientConfig:    getRandomTLSConfig(),
				DisableKeepAlives:  true,
				ForceAttemptHTTP2:  rand.Intn(2) == 0,
				DisableCompression: rand.Intn(3) == 0,
				MaxIdleConns:       rand.Intn(10) + 1,
				IdleConnTimeout:    time.Duration(rand.Intn(60)+30) * time.Second,
			}
			client.Transport = tr
		}
		
		checkGravatar(client, username, resultChan)
		atomic.AddInt64(&stats.totalChecked, 1)
		requestCount++
	}
}

func checkGravatar(client *http.Client, username string, resultChan chan<- Result) {
	url := fmt.Sprintf("https://gravatar.com/%s.json", username)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}
	
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
	req.Header.Set("Accept", "*/*")
	
	if rand.Intn(3) == 0 {
		req.Header.Set("Accept-Encoding", "gzip, deflate")
	}
	if rand.Intn(4) == 0 {
		req.Header.Set("Connection", "close")
	}
	if rand.Intn(5) == 0 {
		req.Header.Set("Cache-Control", "no-cache")
	}
	
	if rand.Intn(10) == 0 {
		req.Proto = "HTTP/1.0"
		req.ProtoMajor = 1
		req.ProtoMinor = 0
	}
	
	time.Sleep(time.Duration(5+rand.Intn(95)) * time.Millisecond)
	
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 404 {
		return
	}
	
	if resp.StatusCode != 200 {
		return
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	
	bodyStr := string(body)
	if strings.Contains(bodyStr, "<title>403 Forbidden</title>") || 
	   strings.Contains(bodyStr, "<h1>403 Forbidden</h1>") ||
	   strings.Contains(bodyStr, "<center>nginx</center>") {
		fmt.Printf("⚠️  Request blocked (403 HTML) for username: %s\n", username)
		return
	}
	
	if strings.Contains(bodyStr, "User not found") {
		return
	}
	
	var gravatarResp GravatarResponse
	if err := json.Unmarshal(body, &gravatarResp); err != nil {
		return
	}
	
	if len(gravatarResp.Entry) > 0 {
		entry := gravatarResp.Entry[0]
		result := Result{
			Username:     username,
			Hash:         entry.Hash,
			ProfileURL:   entry.ProfileURL,
			DisplayName:  entry.DisplayName,
			AboutMe:      entry.AboutMe,
			ThumbnailURL: entry.ThumbnailURL,
		}
		
		resultChan <- result
	}
}

func generateUsernames(current string, maxLength int, usernameChan chan<- string) {
	if current != "" {
		usernameChan <- current
	}
	
	if len(current) >= maxLength {
		return
	}
	
	for c := 'a'; c <= 'z'; c++ {
		next := current + string(c)
		generateUsernames(next, maxLength, usernameChan)
	}
}

func generateUsernamesRange(minLength, maxLength int, usernameChan chan<- string) {
	for length := minLength; length <= maxLength; length++ {
		generateUsernamesOfLength("", length, usernameChan)
	}
}

func generateUsernamesOfLength(current string, targetLength int, usernameChan chan<- string) {
	if len(current) == targetLength {
		usernameChan <- current
		return
	}
	
	if len(current) > targetLength {
		return
	}
	
	for c := 'a'; c <= 'z'; c++ {
		next := current + string(c)
		generateUsernamesOfLength(next, targetLength, usernameChan)
	}
}

func calculateTotalUsernames(maxLength int) int64 {
	var total int64 = 0
	
	for length := 1; length <= maxLength; length++ {
		total += int64(math.Pow(26, float64(length)))
	}
	
	return total
}

func calculateTotalUsernamesRange(minLength, maxLength int) int64 {
	var total int64 = 0
	
	for length := minLength; length <= maxLength; length++ {
		total += int64(math.Pow(26, float64(length)))
	}
	
	return total
}

func estimateTime(totalUsernames int64, numWorkers int) float64 {
	requestsPerSecond := float64(numWorkers) / 0.1
	totalSeconds := float64(totalUsernames) / requestsPerSecond
	return totalSeconds / 3600
}

func progressReporter(stats *Stats) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			checked := atomic.LoadInt64(&stats.totalChecked)
			found := atomic.LoadInt64(&stats.foundUsers)
			elapsed := time.Since(stats.startTime)
			
			if checked > 0 {
				rate := float64(checked) / elapsed.Seconds()
				remaining := stats.totalUsernames - checked
				etaSeconds := float64(remaining) / rate
				
				progress := float64(checked) / float64(stats.totalUsernames) * 100
				
				var etaStr string
				if etaSeconds < 3600 {
					etaStr = fmt.Sprintf("%.0fm", etaSeconds/60)
				} else if etaSeconds < 86400 {
					etaStr = fmt.Sprintf("%.1fh", etaSeconds/3600)
				} else if etaSeconds < 31536000 {
					etaStr = fmt.Sprintf("%.1fd", etaSeconds/86400)
				} else {
					etaStr = fmt.Sprintf("%.1fy", etaSeconds/31536000)
				}
				
				fmt.Printf("Progress: %.2f%% (%d/%d) | Found: %d | Rate: %.1f/s | ETA: %s\n",
					progress, checked, stats.totalUsernames, found, rate, etaStr)
			}
		}
	}
} 