package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// XUI_SIGNATURES 存放了用于识别 x-ui 面板的特征字符串
var XUI_SIGNATURES = []string{
	`src="/assets/js/model/xray.js`,
	`href="/assets/ant-design-vue`,
	`location.href = basePath + 'panel/'`,
	`location.href = basePath + 'xui/'`,
	`-Login</title>`,
	`<title>登录</title>`,
	`<div id="app">`,
}

// AppConfig 结构体用于存储应用程序的配置
type AppConfig struct {
	FilePath       string
	OutputFilePath string
	Concurrency    int
	Timeout        time.Duration
}

// main 是程序的入口函数
func main() {
	log.SetFlags(0) // 不打印默认的时间前缀
	config, err := getUserConfig()
	if err != nil {
		log.Fatalf("配置错误: %v", err)
	}

	var workerWg, writerWg sync.WaitGroup
	jobs := make(chan string, config.Concurrency)
	results := make(chan string, config.Concurrency)
	var processedCounter, dispatchedCounter, successCounter int64

	outputFile, err := os.OpenFile(config.OutputFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("无法打开结果文件: %v", err)
	}
	defer outputFile.Close()

	writerWg.Add(1)
	go fileWriter(&writerWg, results, outputFile, &successCounter)

	log.Printf("启动 %d 个扫描协程...", config.Concurrency)
	for i := 1; i <= config.Concurrency; i++ {
		workerWg.Add(1)
		go worker(&workerWg, jobs, results, config.Timeout, &processedCounter)
	}

	go func() {
		defer close(jobs)
		inputFile, err := os.Open(config.FilePath)
		if err != nil {
			log.Printf("\n错误: 无法打开文件 '%s': %v", config.FilePath, err)
			return
		}
		defer inputFile.Close()

		scanner := bufio.NewScanner(inputFile)
		const maxCapacity = 1024 * 1024 // 1MB
		buf := make([]byte, maxCapacity)
		scanner.Buffer(buf, maxCapacity)

		for scanner.Scan() {
			line := scanner.Text()
			target := parseLine(line)
			if target != "" {
				jobs <- target
				atomic.AddInt64(&dispatchedCounter, 1)
			}
		}

		if err := scanner.Err(); err != nil {
			log.Printf("\n[文件读取错误]: %v. 请检查文件格式或权限。", err)
		}
	}()

	log.Println("扫描已开始...")
	done := make(chan struct{})
	go func() {
		workerWg.Wait()
		close(results)
		close(done)
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			writerWg.Wait()
			fmt.Println()
			processed := atomic.LoadInt64(&processedCounter)
			dispatched := atomic.LoadInt64(&dispatchedCounter)
			success := atomic.LoadInt64(&successCounter)
			log.Printf("扫描完成。从文件解析并分发 %d 个目标，实际处理 %d 个，成功 %d 个。", dispatched, processed, success)
			if dispatched > 0 {
				log.Printf("成功的结果已保存到 %s", config.OutputFilePath)
			} else {
				log.Println("警告：未从输入文件中解析出任何有效目标。")
			}
			return
		case <-ticker.C:
			// 实时显示进度
			fmt.Printf("\r进度: 已处理 %d / 已分发 %d | 成功: %d",
				atomic.LoadInt64(&processedCounter),
				atomic.LoadInt64(&dispatchedCounter),
				atomic.LoadInt64(&successCounter))
		}
	}
}

func fileWriter(wg *sync.WaitGroup, results <-chan string, file *os.File, counter *int64) {
	defer wg.Done()
	for result := range results {
		atomic.AddInt64(counter, 1)
		_, err := file.WriteString(result + "\n")
		if err != nil {
			log.Printf("\n[文件写入错误]: %v", err)
		}
	}
}

// parseLine 智能解析输入行，兼容多种 masscan 格式
func parseLine(line string) string {
	line = strings.TrimSpace(line)

	// 忽略空行和以'#'开头的注释行
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}

	// --- 核心修正：更健壮的 masscan 格式解析 ---
	// 只要行内包含 "Host:" 和 "Ports:" 关键字，就尝试解析
	if strings.Contains(line, "Host:") && strings.Contains(line, "Ports:") {
		fields := strings.Fields(line)
		var ip, port string
		for i, field := range fields {
			if field == "Host:" && i+1 < len(fields) {
				ip = fields[i+1]
			}
			if field == "Ports:" && i+1 < len(fields) {
				// 从 "2053/open/tcp//..." 中提取端口号
				port = strings.Split(fields[i+1], "/")[0]
			}
		}
		if ip != "" && port != "" {
			return fmt.Sprintf("%s:%s", ip, port)
		}
	}

	// 如果不是 masscan 格式，则假定为 ip:port 格式
	// (可以增加更严格的验证，例如检查是否包含':')
	if strings.Contains(line, ":") {
		return line
	}

	return ""
}

func getUserConfig() (AppConfig, error) {
	config := AppConfig{}
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("请输入包含目标列表的文件路径 (ip:port 或 masscan 格式): ")
	filePath, _ := reader.ReadString('\n')
	config.FilePath = strings.TrimSpace(filePath)

	fmt.Print("请输入结果保存文件名 (默认 results.txt): ")
	outputFilePath, _ := reader.ReadString('\n')
	outputFilePath = strings.TrimSpace(outputFilePath)
	if outputFilePath == "" {
		config.OutputFilePath = "results.txt"
	} else {
		config.OutputFilePath = outputFilePath
	}

	fmt.Print("请输入并发协程数 (默认 30): ")
	concurrencyStr, _ := reader.ReadString('\n')
	concurrencyStr = strings.TrimSpace(concurrencyStr)
	if concurrencyStr == "" {
		config.Concurrency = 30
	} else {
		concurrency, err := strconv.Atoi(concurrencyStr)
		if err != nil || concurrency <= 0 {
			return config, fmt.Errorf("无效的并发数: %s", concurrencyStr)
		}
		config.Concurrency = concurrency
	}

	fmt.Print("请输入网络超时时间（秒，默认 10）: ")
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)
	if timeoutStr == "" {
		config.Timeout = 10 * time.Second
	} else {
		timeoutSec, err := strconv.Atoi(timeoutStr)
		if err != nil || timeoutSec <= 0 {
			return config, fmt.Errorf("无效的超时时间: %s", timeoutStr)
		}
		config.Timeout = time.Duration(timeoutSec) * time.Second
	}

	fmt.Println("------------------------------------")
	return config, nil
}

func worker(wg *sync.WaitGroup, jobs <-chan string, results chan<- string, timeout time.Duration, counter *int64) {
	defer wg.Done()
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for target := range jobs {
		checkTarget(target, client, results)
		atomic.AddInt64(counter, 1)
	}
}

func checkTarget(target string, client *http.Client, results chan<- string) {
	if target == "" {
		return
	}
	if checkProtocol("https", target, client, results) {
		return
	}
	checkProtocol("http", target, client, results)
}

func checkProtocol(protocol, target string, client *http.Client, results chan<- string) bool {
	url := fmt.Sprintf("%s://%s", protocol, target)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("\n[请求创建错误] %s: %v", url, err)
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		// 不再打印普通网络错误，因为数量可能非常大，只在调试时开启
		// fmt.Printf("\r[网络错误] %s: %v\n", url, err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		limitedReader := io.LimitReader(resp.Body, 4*1024)
		body, err := ioutil.ReadAll(limitedReader)
		if err != nil {
			log.Printf("\n[响应读取错误] %s: %v\n", url, err)
			return false
		}

		content := string(body)
		for _, signature := range XUI_SIGNATURES {
			if strings.Contains(content, signature) {
				fmt.Printf("\r[成功] 发现x-ui面板: %s (特征: %s)\n", url, signature)
				results <- target
				return true
			}
		}
	}
	return false
}
