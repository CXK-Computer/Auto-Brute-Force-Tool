package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
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
}

// AppConfig 结构体用于存储应用程序的配置
type AppConfig struct {
	FilePath    string
	Concurrency int
	Timeout     time.Duration
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

	var wg sync.WaitGroup
	// 创建一个带缓冲的 channel 用于分发任务。
	// 这确保了程序在低内存环境下也能高效运行，因为任务是流式处理的，
	// 不会将整个文件加载到内存中。
	jobs := make(chan string, config.Concurrency)
	var processedCounter int64

	// 启动指定数量的 worker goroutine
	log.Printf("启动 %d 个扫描协程...", config.Concurrency)
	for i := 1; i <= config.Concurrency; i++ {
		wg.Add(1)
		go worker(i, &wg, jobs, config.Timeout, &processedCounter)
	}

	// 在一个单独的 goroutine 中读取文件并发送任务，这样主 goroutine 可以用于显示进度
	go func() {
		file, err := os.Open(config.FilePath)
		if err != nil {
			log.Printf("错误: 无法打开文件 '%s': %v", config.FilePath, err)
			close(jobs) // 发生错误时关闭 channel，以允许程序退出
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
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

		// 文件读取完毕，关闭 jobs channel，通知 worker 没有更多任务
		close(jobs)
	}()

	// 进度报告逻辑
	log.Println("扫描已开始...")
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			// 换行以避免覆盖最终的完成信息
			fmt.Println()
			log.Printf("已处理 %d 个目标。扫描完成。", atomic.LoadInt64(&processedCounter))
			return
		case <-ticker.C:
			// 使用 \r 回车符将光标移到行首，实现单行动态刷新进度
			fmt.Printf("\r已处理: %d", atomic.LoadInt64(&processedCounter))
		}
	}
}

// parseLine 解析输入行，支持 'ip:port' 和 masscan 格式
func parseLine(line string) string {
	line = strings.TrimSpace(line)
	// 忽略空行和注释行
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}

	// 检查是否为 Masscan 格式
	if strings.HasPrefix(line, "Host:") {
		parts := strings.Fields(line)
		// "Host:", "1.2.3.4", "()", "Ports:", "54321/open/tcp////"
		if len(parts) >= 5 && parts[3] == "Ports:" {
			ip := parts[1]
			portPart := strings.Split(parts[4], "/")[0]
			return fmt.Sprintf("%s:%s", ip, portPart)
		}
		return ""
	}

	// 否则，假定为 'ip:port' 格式
	return line
}

// getUserConfig 通过交互式提示获取用户输入并返回配置
func getUserConfig() (AppConfig, error) {
	config := AppConfig{}
	reader := bufio.NewReader(os.Stdin)

	// 1. 获取文件路径
	fmt.Print("请输入包含目标列表的文件路径 (ip:port 或 masscan 格式): ")
	filePath, err := reader.ReadString('\n')
	if err != nil {
		return config, fmt.Errorf("读取文件路径失败: %w", err)
	}
	config.FilePath = strings.TrimSpace(filePath)

	// 2. 获取并发数 (即用户理解的“线程数”)
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

	// 3. 获取超时时间
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
func worker(id int, wg *sync.WaitGroup, jobs <-chan string, timeout time.Duration, counter *int64) {
	defer wg.Done()

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for target := range jobs {
		checkTarget(target, client)
		// 使用原子操作安全地增加计数器
		atomic.AddInt64(counter, 1)
	}
}

// checkTarget 对单个目标进行 HTTP 请求并检查响应内容
func checkTarget(target string, client *http.Client) {
	if target == "" {
		return
	}
	checkProtocol("http", target, client)
}

// checkProtocol 封装了检查特定协议的逻辑
func checkProtocol(protocol, target string, client *http.Client) {
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
		body, err := io.ReadAll(limitedReader)
		if err != nil {
			return
		}

		content := string(body)
		for _, signature := range XUI_SIGNATURES {
			if strings.Contains(content, signature) {
				// 成功找到后换行打印，避免被进度条覆盖
				fmt.Println()
				log.Printf("[成功] 发现x-ui面板: %s (特征: %s)", url, signature)
				return
			}
		}
	}
}
