package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil" // 引入 ioutil 包以兼容旧版 Go
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
// 修正了特征码，移除了末尾的双引号以提高匹配灵活性，使其与原始 Python 脚本行为一致
var XUI_SIGNATURES = []string{
	`src="/assets/js/model/xray.js`,
	`href="/assets/ant-design-vue`,
	`location.href = basePath + 'panel/'`,
	`location.href = basePath + 'xui/'`,
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
	// 设置日志格式，不显示日期和时间
	log.SetFlags(0)

	// 获取用户配置
	config, err := getUserConfig()
	if err != nil {
		log.Fatalf("配置错误: %v", err)
	}

	// --- 设置并发任务和结果通道 ---
	var workerWg sync.WaitGroup
	var writerWg sync.WaitGroup
	jobs := make(chan string, config.Concurrency)
	results := make(chan string, config.Concurrency)
	var processedCounter int64

	// --- 启动文件写入协程 ---
	outputFile, err := os.OpenFile(config.OutputFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("无法打开结果文件: %v", err)
	}
	defer outputFile.Close()

	writerWg.Add(1)
	go fileWriter(&writerWg, results, outputFile)

	// --- 启动扫描工作协程 ---
	log.Printf("启动 %d 个扫描协程...", config.Concurrency)
	for i := 1; i <= config.Concurrency; i++ {
		workerWg.Add(1)
		go worker(&workerWg, jobs, results, config.Timeout, &processedCounter)
	}

	// --- 读取输入文件并分发任务 ---
	go func() {
		inputFile, err := os.Open(config.FilePath)
		if err != nil {
			log.Printf("错误: 无法打开文件 '%s': %v", config.FilePath, err)
			close(jobs)
			return
		}
		defer inputFile.Close()

		scanner := bufio.NewScanner(inputFile)
		for scanner.Scan() {
			line := scanner.Text()
			target := parseLine(line)
			if target != "" {
				jobs <- target
			}
		}

		if err := scanner.Err(); err != nil {
			log.Printf("读取文件时发生错误: %v", err)
		}
		close(jobs) // 文件读取完毕，关闭 jobs channel
	}()

	// --- 等待与进度报告 ---
	log.Println("扫描已开始...")
	done := make(chan struct{})
	go func() {
		workerWg.Wait() // 等待所有扫描任务完成
		close(results)  // 关闭结果通道，通知写入协程可以结束
		close(done)
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			writerWg.Wait() // 确保文件写入已全部完成
			fmt.Println()   // 换行以避免覆盖最终的完成信息
			log.Printf("已处理 %d 个目标。扫描完成。", atomic.LoadInt64(&processedCounter))
			log.Printf("成功的结果已保存到 %s", config.OutputFilePath)
			return
		case <-ticker.C:
			fmt.Printf("\r已处理: %d", atomic.LoadInt64(&processedCounter))
		}
	}
}

// fileWriter 从结果通道读取数据并写入文件
func fileWriter(wg *sync.WaitGroup, results <-chan string, file *os.File) {
	defer wg.Done()
	for result := range results {
		_, err := file.WriteString(result + "\n")
		if err != nil {
			log.Printf("\n写入文件错误: %v", err)
		}
	}
}

// parseLine 解析输入行，支持 'ip:port' 和 masscan 格式
func parseLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	if strings.HasPrefix(line, "Host:") {
		parts := strings.Fields(line)
		if len(parts) >= 5 && parts[3] == "Ports:" {
			ip := parts[1]
			portPart := strings.Split(parts[4], "/")[0]
			return fmt.Sprintf("%s:%s", ip, portPart)
		}
		return ""
	}
	return line
}

// getUserConfig 通过交互式提示获取用户输入并返回配置
func getUserConfig() (AppConfig, error) {
	config := AppConfig{}
	reader := bufio.NewReader(os.Stdin)

	// 1. 获取输入文件路径
	fmt.Print("请输入包含目标列表的文件路径 (ip:port 或 masscan 格式): ")
	filePath, err := reader.ReadString('\n')
	if err != nil {
		return config, fmt.Errorf("读取文件路径失败: %w", err)
	}
	config.FilePath = strings.TrimSpace(filePath)

	// 2. 获取输出文件路径
	fmt.Print("请输入结果保存文件名 (默认 results.txt): ")
	outputFilePath, err := reader.ReadString('\n')
	if err != nil {
		return config, fmt.Errorf("读取文件名失败: %w", err)
	}
	outputFilePath = strings.TrimSpace(outputFilePath)
	if outputFilePath == "" {
		config.OutputFilePath = "results.txt"
	} else {
		config.OutputFilePath = outputFilePath
	}

	// 3. 获取并发数
	fmt.Print("请输入并发协程数 (默认 100): ")
	concurrencyStr, err := reader.ReadString('\n')
	if err != nil {
		return config, fmt.Errorf("读取并发数失败: %w", err)
	}
	concurrencyStr = strings.TrimSpace(concurrencyStr)
	if concurrencyStr == "" {
		config.Concurrency = 100
	} else {
		concurrency, err := strconv.Atoi(concurrencyStr)
		if err != nil || concurrency <= 0 {
			return config, fmt.Errorf("无效的并发数: %s", concurrencyStr)
		}
		config.Concurrency = concurrency
	}

	// 4. 获取超时时间
	fmt.Print("请输入网络超时时间（秒，默认 5）: ")
	timeoutStr, err := reader.ReadString('\n')
	if err != nil {
		return config, fmt.Errorf("读取超时时间失败: %w", err)
	}
	timeoutStr = strings.TrimSpace(timeoutStr)
	if timeoutStr == "" {
		config.Timeout = 5 * time.Second
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

// worker 是执行扫描任务的协程
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

// checkTarget 对单个目标进行 HTTP 请求并检查响应内容
func checkTarget(target string, client *http.Client, results chan<- string) {
	if target == "" {
		return
	}
	checkProtocol("http", target, client, results)
}

// checkProtocol 封装了检查特定协议的逻辑
func checkProtocol(protocol, target string, client *http.Client, results chan<- string) {
	url := fmt.Sprintf("%s://%s", protocol, target)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		limitedReader := &io.LimitedReader{R: resp.Body, N: 4096}
		body, err := ioutil.ReadAll(limitedReader)
		if err != nil {
			return
		}
		content := string(body)
		for _, signature := range XUI_SIGNATURES {
			if strings.Contains(content, signature) {
				fmt.Println()
				log.Printf("[成功] 发现x-ui面板: %s (特征: %s)", url, signature)
				results <- target // 将成功结果发送到文件写入通道
				return
			}
		}
	}
}
