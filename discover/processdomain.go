package discover

import (
	"autov/models"
	"autov/utils"
	"fmt"
	"time"
)

// 处理单个域名
func ProcessDomain(domain string) models.DomainResult {
	domainResult := models.DomainResult{
		Domain:        domain,
		Timestamp:     time.Now().Format(time.RFC3339),
		ErrorMessages: []string{},
	}

	//处理每个域名的一开始就查询CNAME字段
	email := "info@" + domain
	cnameRecords, err := utils.LookupCNAME(domain)
	if err != nil {
		domainResult.ErrorMessages = append(domainResult.ErrorMessages, fmt.Sprintf("CNAME lookup error: %v", err))
	}
	domainResult.CNAME = cnameRecords

	// ==== Autodiscover 查询 ====
	autodiscoverResults := QueryAutodiscover(domain, email)

	// 新增逻辑：遍历查询结果，分离异常数据并保存
	for i := range autodiscoverResults {
		res := &autodiscoverResults[i]

		// 提取出所有需要留存记录的异常状态
		if res.StatusTag == "REDIRECT_URL_FAILED" ||
			res.StatusTag == "REDIRECT_ADDR_FAILED" ||
			res.StatusTag == "INVALID_RESPONSE_ELEMENT" ||
			res.StatusTag == "MALFORMED_XML" {

			// 调用工具类写入单独的文件，这样旧版的功能就不会丢失！
			utils.SaveAnomalyXML(domain, "AUTODISCOVER_"+res.StatusTag, res.Method, res.Index, res.RawBody)
		}

		// 成功的情况，或者已经存为了实体的文件的情况，可以把原始数据清空
		// 以免最后输出的 jsonl 文件过于庞大导致内存泄漏
		if res.StatusTag == "SUCCESS" {
			res.RawBody = ""
		}
	}
	domainResult.Autodiscover = autodiscoverResults

	// ==== Autoconfig 查询 ====
	autoconfigResults := QueryAutoconfig(domain, email)

	// 遍历查询结果，分离异常数据并保存
	for i := range autoconfigResults {
		res := &autoconfigResults[i]

		// 只要遇到词法错误 (MALFORMED_XML)，就单独写成文件保存到 data/anomalies/AUTOCONFIG_MALFORMED_XML/ 下
		if res.StatusTag == "MALFORMED_XML" {
			// 为了区分是 autodiscover 还是 autoconfig 的错误，我们在目录名加个前缀
			utils.SaveAnomalyXML(domain, "AUTOCONFIG_"+res.StatusTag, res.Method, res.Index, res.RawBody)
		}

		// 成功时清空 RawBody 以节省内存
		if res.StatusTag == "SUCCESS" {
			res.RawBody = ""
		}
	}
	domainResult.Autoconfig = autoconfigResults

	// ==== SRV 查询 ====
	srvconfigResults := QuerySRV(domain)
	domainResult.SRV = srvconfigResults

	// ==== GUESS 9.13 ====
	guessResults := GuessMailServer(domain, 2*time.Second, 20)
	domainResult.GUESS = guessResults

	return domainResult
}
