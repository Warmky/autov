package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

// SaveAnomalyXML 用于将异常的原始 XML/HTML 写入特定分类文件夹，完美替代老版的 saveXMLToFile 等函数
func SaveAnomalyXML(domain string, statusTag string, method string, index int, rawBody string) {
	if rawBody == "" {
		return
	}

	// 自动创建按错误类型分类的目录，比如：data/anomalies/REDIRECT_URL_FAILED/
	dir := filepath.Join("data", "anomalies", statusTag)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("Error creating anomaly directory %s: %v\n", dir, err)
		return
	}

	// 文件名格式，如: example.com_post_1.xml
	filename := fmt.Sprintf("%s_%s_%d.xml", domain, method, index)
	filePath := filepath.Join(dir, filename)

	err := os.WriteFile(filePath, []byte(rawBody), 0644)
	if err != nil {
		fmt.Printf("Error writing anomaly file for %s: %v\n", domain, err)
	}
}
