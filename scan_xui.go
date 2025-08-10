package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
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

// bufferPool 使用 sync.Pool 来复用读取响应体时所需的内存缓冲区。
// 这能极大减少内存分配和GC压力。
var bufferPool = sync.Pool{
	New: func() interface{} {
		// 分配一个4KB的缓冲区，对于读取HTML头部进行特征匹配足够了。
		b := make([]byte, 4*1024)
		return &b
	},
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
	log.SetFlags(0)
	config, err := getUserConfig()
	if err != nil {
		log.Fatalf("配置错误: %v", err)
	}

	var workerWg, writerWg sync.WaitGroup
	jobs := make(chan string, config.Concurrency)
	results := make(chan string, config.Concurrency)
	var processedCounter int64

	outputFile, err := os.OpenFile(config.OutputFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("无法打开结果文件: %v", err)
	}
	defer outputFile.Close()

	writerWg.Add(1)
	go fileWriter(&writerWg, results, outputFile)

	log.Printf("启动 %d 个扫描协程...", config.Concurrency)
	for i := 1; i <= config.Concurrency; i++ {
		workerWg.Add(1)
		go worker(&workerWg, jobs, results, config.Timeout, &processedCounter)
	}

	go func() {
		defer close(jobs)
		inputFile, err := os.Open(config.FilePath)
		if err != nil {
			log.Printf("错误: 无法打开文件 '%s': %v", config.FilePath, err)
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
			log.Printf("已处理 %d 个目标。扫描完成。", atomic.LoadInt64(&processedCounter))
			log.Printf("成功的结果已保存到 %s", config.OutputFilePath)
			return
		case <-ticker.C:
			fmt.Printf("\r已处理: %d", atomic.LoadInt64(&processedCounter))
		}
	}
}

func fileWriter(wg *sync.WaitGroup, results <-chan string, file *os.File) {
	defer wg.Done()
	for result := range results {
		_, err := file.WriteString(result + "\n")
		if err != nil {
			log.Printf("\n写入文件错误: %v", err)
		}
	}
}

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

	fmt.Print("请输入并发协程数 (默认 100): ")
	concurrencyStr, _ := reader.ReadString('\n')
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

	fmt.Print("请输入网络超时时间（秒，默认 5）: ")
	timeoutStr, _ := reader.ReadString('\n')
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

func worker(wg *sync.WaitGroup, jobs <-chan string, results chan<- string, timeout time.Duration, counter *int64) {
	defer wg.Done()
	// 优化HTTP客户端：自定义Transport以复用更多TCP连接
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   20, // 增加每个主机的空闲连接数
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	for target := range jobs {
		checkTarget(target, client, results)
		atomic.AddInt64(counter, 1)
	}
}

// checkTarget 依次尝试 HTTPS 和 HTTP
func checkTarget(target string, client *http.Client, results chan<- string) {
	if target == "" {
		return
	}
	if checkProtocol("https", target, client, results) {
		return
	}
	checkProtocol("http", target, client, results)
}

// checkProtocol 检查特定协议，如果成功则返回 true
func checkProtocol(protocol, target string, client *http.Client, results chan<- string) bool {
	url := fmt.Sprintf("%s://%s", protocol, target)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		// 从池中获取一个缓冲区
		bufPtr := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(bufPtr) // 确保缓冲区被归还
		buf := *bufPtr

		// 使用我们从池中获取的缓冲区来读取响应体
		n, err := io.ReadFull(io.LimitReader(resp.Body, int64(len(buf))), buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return false
		}
		if n == 0 {
			return false
		}

		content := string(buf[:n])
		for _, signature := range XUI_SIGNATURES {
			if strings.Contains(content, signature) {
				fmt.Println()
				log.Printf("[成功] 发现x-ui面板: %s (特征: %s)", url, signature)
				results <- target
				return true
			}
		}
	}
	return false
}
