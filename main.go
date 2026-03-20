package main

import (
	"autov/measurement"
)

func main() {
	// // 确保存放结果和异常的 data 文件夹存在
	// os.MkdirAll("data/anomalies_test", 0755)
	// // os.MkdirAll("data/anomalies", 0755)

	// fmt.Println("🚀 准备开始大规模邮件自动化配置测量...")

	// // 调用 discover 包里的 Process 函数
	// discover.Process()

	// fmt.Println("✅ 本次扫描任务全部完成！")
	//==========================================================
	measurement.CountDomainsWithValidConfig("/home/wzq/project/autov/data/results_test.jsonl")
}
