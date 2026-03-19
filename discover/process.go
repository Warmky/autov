package discover

import (
	"autov/models"
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ScanTask 用于在 Channel 中传递域名和它对应的行号
type ScanTask struct {
	Domain string
	Index  int
}

func Process() {
	// 配置参数
	// csvFile := "/home/wzq/project/autov/tranco_KW6JW.csv"
	// outputFile := "init.jsonl"
	// concurrency := 200 // 原来使用 semaphore 控制的并发数，现在作为 Worker 池的大小
	csvFile := "test_5000.csv"              // 指向刚才截取的小文件
	outputFile := "data/results_test.jsonl" // 存放到 data 目录下
	concurrency := 50                       // 测试阶段开 50 个并发就足够快了
	// ========================

	fmt.Printf("Starting scan with %d concurrent workers...\n", concurrency)

	fmt.Printf("Starting scan with %d concurrent workers...\n", concurrency)
	startTime := time.Now()

	// 1. 创建任务和结果的缓冲通道 (Buffer 设为并发数的 2 倍，保证流水线顺畅)
	tasksChan := make(chan ScanTask, concurrency*2)
	resultsChan := make(chan models.DomainResult, concurrency*2)

	var workerWG sync.WaitGroup
	var writerWG sync.WaitGroup

	// ==========================================
	// 2. 启动单一消费者：专属的磁盘写入协程
	// 优势：完全无锁，天生线程安全，利用 bufio 极速落盘
	// ==========================================
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()

		file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Printf("Error opening output file: %v\n", err)
			return
		}
		defer file.Close()

		// 保持你原本优秀的 64KB 缓冲写入设计
		writer := bufio.NewWriterSize(file, 64*1024)
		defer writer.Flush() // 确保退出前最后的数据被刷入磁盘

		// 不断从结果通道读取数据，直到通道被关闭
		for result := range resultsChan {
			jsonBytes, err := json.Marshal(result)
			if err != nil {
				fmt.Printf("Error marshaling JSON for %s: %v\n", result.Domain, err)
				continue
			}
			writer.Write(jsonBytes)
			writer.WriteByte('\n')
		}
	}()

	// ==========================================
	// 3. 启动固定数量的 Worker 协程池
	// ==========================================
	for i := 0; i < concurrency; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()

			// Worker 不断从任务通道领取域名
			for task := range tasksChan {
				// 执行你的核心扫描逻辑
				domainResult := ProcessDomain(task.Domain)
				domainResult.Domain_id = task.Index + 1

				// 将结果丢入通道，无需加任何锁！
				resultsChan <- domainResult
			}
		}()
	}

	// ==========================================
	// 4. 读取 CSV 并下发任务 (生产者)
	// ==========================================
	file, err := os.Open(csvFile)
	if err != nil {
		fmt.Printf("Failed to open CSV file: %v\n", err)
		close(tasksChan)
		return
	}

	reader := csv.NewReader(file)
	// reader.FieldsPerRecord = -1 // 如果 CSV 有的行长短不一，可以解除这行注释
	lineIndex := 0
	count := 0

	for {
		record, err := reader.Read()
		if err != nil {
			break // EOF
		}

		if len(record) > 1 {
			domain := strings.TrimSpace(record[1]) // 取第二列，对应你原本的逻辑
			if domain != "" {
				// 将提取的域名放入任务通道
				tasksChan <- ScanTask{Domain: domain, Index: lineIndex}
				count++

				// 简单的进度打印，防止跑起来感觉像卡死了
				if count%1000 == 0 {
					fmt.Printf("[Status] Pushed %d domains to queue...\n", count)
				}
			}
		}
		lineIndex++
	}
	file.Close()

	// 任务全部下发完毕，关闭任务通道，告诉 Worker 们没有新活儿了
	close(tasksChan)

	// ==========================================
	// 5. 优雅关闭与资源清理
	// ==========================================
	// 等待所有 Worker 消化完通道里剩余的任务
	workerWG.Wait()
	fmt.Println("All workers finished. Closing results channel...")

	// Worker 全部完工后，关闭结果通道，告诉 Writer 可以收尾了
	close(resultsChan)

	// 等待 Writer 把最后在内存 buffer 里的数据刷入磁盘
	writerWG.Wait()

	elapsed := time.Since(startTime)
	fmt.Printf("Scan completed! Results successfully saved to %s in %s\n", outputFile, elapsed)
}
