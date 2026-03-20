package measurement

import (
	"autov/models"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/beevik/etree"
)

func CountDomainsWithValidConfig(inputFile string) {
	file, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	sem := make(chan struct{}, 50) // 控制并发数
	var wg sync.WaitGroup

	// 统计变量
	var (
		domainProcessed                int64
		validAutodiscoverDomains       = make(map[string]struct{})
		autodiscoverFromPost           = make(map[string]struct{})
		autodiscoverFromSrvpost        = make(map[string]struct{})
		autodiscoverFromGetpost        = make(map[string]struct{})
		autodiscoverFromDirectGet      = make(map[string]struct{})
		autodiscover_has_cname         = make(map[string]struct{}) //3.12
		autodiscover_cname_and_config  = make(map[string]struct{}) //3.12
		validAutoconfigDomains         = make(map[string]struct{})
		autoconfigFromDirecturl        = make(map[string]struct{})
		autoconfigFromISPDB            = make(map[string]struct{})
		autoconfigFromMXSameDomain     = make(map[string]struct{})
		autoconfigFromMX               = make(map[string]struct{})
		validSRVDomains                = make(map[string]struct{})
		srvDNSSECPassed                = make(map[string]struct{})
		validOnlyAutodiscover          = make(map[string]struct{})
		validOnlyAutoconfig            = make(map[string]struct{})
		validOnlySRV                   = make(map[string]struct{})
		validAutodiscoverAndAutoconfig = make(map[string]struct{})
		validAutodiscoverAndSRV        = make(map[string]struct{})
		validAutoconfigAndSRV          = make(map[string]struct{})
		validThreeAll                  = make(map[string]struct{})
		validNone                      = make(map[string]struct{})
		validGuessDomains              = make(map[string]struct{}) //9.22
		validNoneFour                  = make(map[string]struct{}) //9.22

		// 定义 SRV 协议分类统计
		srvIMAPDomains        = make(map[string]struct{})
		srvIMAPSUDomains      = make(map[string]struct{})
		srvPOP3Domains        = make(map[string]struct{})
		srvPOP3SDomains       = make(map[string]struct{})
		srvSubmissionDomains  = make(map[string]struct{})
		srvSubmissionsDomains = make(map[string]struct{})
	)

	// 互斥锁保护共享变量
	var mu sync.Mutex

	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Error reading line: %v", err)
		}

		var obj models.DomainResult
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			log.Printf("❌ JSON 解析失败，跳过此行: %v", err)
			continue
		}

		sem <- struct{}{} // 占位
		wg.Add(1)
		go func(obj models.DomainResult) {
			defer wg.Done()
			defer func() { <-sem }()

			domain := obj.Domain
			atomic.AddInt64(&domainProcessed, 1)

			// ==========================================
			// 1. 局部变量记录，避免在此阶段频繁加锁
			// ==========================================
			hasAutoconfig := false
			acMethods := make(map[string]bool)

			hasAutodiscover := false
			adHasCNAME := false
			adMethods := make(map[string]bool)

			hasSRV := false
			isDNSSECPassed := false
			srvTypes := make(map[string]bool)

			hasGUESS := false

			// --- Autoconfig 统计 ---
			for _, entry := range obj.Autoconfig {
				if entry.Config != "" {
					// 优先利用 StatusTag 加速，如果没 Tag 才使用 etree 解析，大幅节省 CPU
					isValid := false
					if entry.StatusTag == "SUCCESS" {
						isValid = true
					} else {
						doc := etree.NewDocument()
						if err := doc.ReadFromString(entry.Config); err == nil && doc.SelectElement("clientConfig") != nil {
							isValid = true
						}
					}

					if isValid {
						hasAutoconfig = true
						acMethods[entry.Method] = true
					}
				}
			}

			// --- Autodiscover 统计 ---
			for _, entry := range obj.Autodiscover {
				if len(entry.AutodiscoverCNAME) > 0 {
					adHasCNAME = true
				}
				if entry.Config != "" && !strings.HasPrefix(entry.Config, "Bad") && !strings.HasPrefix(entry.Config, "Errorcode") && !strings.HasPrefix(entry.Config, "Non-valid") {
					isValid := false
					if entry.StatusTag == "SUCCESS" {
						isValid = true
					} else {
						doc := etree.NewDocument()
						if err := doc.ReadFromString(entry.Config); err == nil {
							isValid = true
						}
					}

					if isValid {
						hasAutodiscover = true
						adMethods[entry.Method] = true
					}
				}
			}

			// --- SRV 统计 ---
			if len(obj.SRV.RecvRecords) > 0 || len(obj.SRV.SendRecords) > 0 {
				hasSRV = true
				for _, record := range obj.SRV.RecvRecords {
					service := strings.ToLower(record.Service)
					if strings.HasPrefix(service, "_imap.") { srvTypes["IMAP"] = true }
					if strings.HasPrefix(service, "_imaps.") { srvTypes["IMAPS"] = true }
					if strings.HasPrefix(service, "_pop3.") { srvTypes["POP3"] = true }
					if strings.HasPrefix(service, "_pop3s.") { srvTypes["POP3S"] = true }
				}
				for _, record := range obj.SRV.SendRecords {
					service := strings.ToLower(record.Service)
					if strings.HasPrefix(service, "_submission.") { srvTypes["SUBMISSION"] = true }
					if strings.HasPrefix(service, "_submissions.") { srvTypes["SUBMISSIONS"] = true }
				}

				// DNSSEC
				if obj.SRV.DNSRecord != nil {
					dnssecPassed := true
					dnsRecord := obj.SRV.DNSRecord
					existingFields := []*bool{
						dnsRecord.ADbit_imap, dnsRecord.ADbit_imaps,
						dnsRecord.ADbit_pop3, dnsRecord.ADbit_pop3s,
						dnsRecord.ADbit_smtp, dnsRecord.ADbit_smtps,
					}
					hasCheckedFields := false
					for _, field := range existingFields {
						if field != nil {
							hasCheckedFields = true
							if !*field {
								dnssecPassed = false
								break
							}
						}
					}
					if dnssecPassed && hasCheckedFields {
						isDNSSECPassed = true
					}
				}
			}

			// --- GUESS 统计 ---
			for _, entry := range obj.GUESS {
				if len(entry) != 0 {
					hasGUESS = true
					break // 只要有一条有效即可
				}
			}

			// ==========================================
			// 2. 统一写入全局 Map（单一域名仅锁定一次）
			// ==========================================
			mu.Lock()

			// Autoconfig
			if hasAutoconfig {
				validAutoconfigDomains[domain] = struct{}{}
				if acMethods["directurl"] { autoconfigFromDirecturl[domain] = struct{}{} }
				if acMethods["ISPDB"] { autoconfigFromISPDB[domain] = struct{}{} }
				if acMethods["MX_samedomain"] { autoconfigFromMXSameDomain[domain] = struct{}{} }
				if acMethods["MX"] { autoconfigFromMX[domain] = struct{}{} }
			}

			// Autodiscover
			if adHasCNAME {
				autodiscover_has_cname[domain] = struct{}{}
			}
			if hasAutodiscover {
				validAutodiscoverDomains[domain] = struct{}{}
				if adHasCNAME { autodiscover_cname_and_config[domain] = struct{}{} }
				if adMethods["POST"] { autodiscoverFromPost[domain] = struct{}{} }
				if adMethods["srv-post"] { autodiscoverFromSrvpost[domain] = struct{}{} }
				if adMethods["get-post"] || adMethods["get_post"] { autodiscoverFromGetpost[domain] = struct{}{} }
				if adMethods["direct_get"] { autodiscoverFromDirectGet[domain] = struct{}{} }
			}

			// SRV
			if hasSRV {
				validSRVDomains[domain] = struct{}{}
				if srvTypes["IMAP"] { srvIMAPDomains[domain] = struct{}{} }
				if srvTypes["IMAPS"] { srvIMAPSUDomains[domain] = struct{}{} }
				if srvTypes["POP3"] { srvPOP3Domains[domain] = struct{}{} }
				if srvTypes["POP3S"] { srvPOP3SDomains[domain] = struct{}{} }
				if srvTypes["SUBMISSION"] { srvSubmissionDomains[domain] = struct{}{} }
				if srvTypes["SUBMISSIONS"] { srvSubmissionsDomains[domain] = struct{}{} }
				if isDNSSECPassed { srvDNSSECPassed[domain] = struct{}{} }
			}

			// Guess
			if hasGUESS {
				validGuessDomains[domain] = struct{}{}
			}

			// 交集统计
			if hasAutoconfig && hasAutodiscover && hasSRV { validThreeAll[domain] = struct{}{} }
			if hasAutoconfig && hasAutodiscover { validAutodiscoverAndAutoconfig[domain] = struct{}{} }
			if hasAutoconfig && hasSRV { validAutoconfigAndSRV[domain] = struct{}{} }
			if hasAutodiscover && hasSRV { validAutodiscoverAndSRV[domain] = struct{}{} }
			if hasAutoconfig && !hasAutodiscover && !hasSRV { validOnlyAutoconfig[domain] = struct{}{} }
			if hasAutodiscover && !hasAutoconfig && !hasSRV { validOnlyAutodiscover[domain] = struct{}{} }
			if hasSRV && !hasAutoconfig && !hasAutodiscover { validOnlySRV[domain] = struct{}{} }
			if !hasAutoconfig && !hasAutodiscover && !hasSRV { validNone[domain] = struct{}{} }
			if !hasGUESS && !hasAutoconfig && !hasAutodiscover && !hasSRV { validNoneFour[domain] = struct{}{} }

			mu.Unlock()
		}(obj)
	}

	wg.Wait()

	// ==========================================
	// 3. 输出统计结果 (此时 wg.Wait() 已结束，不再需要 mu.Lock)
	// ==========================================
	fmt.Printf("✅ 通过 Autodiscover 可以获取配置信息的域名数量: %d\n", len(validAutodiscoverDomains))
	fmt.Printf("✅ 通过 Autodiscover_post 可以获取配置信息的域名数量: %d\n", len(autodiscoverFromPost))
	fmt.Printf("✅ 通过 Autodiscover_srvpost 可以获取配置信息的域名数量: %d\n", len(autodiscoverFromSrvpost))
	fmt.Printf("✅ 通过 Autodiscover_getpost 可以获取配置信息的域名数量: %d\n", len(autodiscoverFromGetpost))
	fmt.Printf("✅ 通过 Autodiscover_direct_get 可以获取配置信息的域名数量: %d\n", len(autodiscoverFromDirectGet))
	fmt.Printf("✅ Autodiscover有CNAME记录的域名数量: %d\n", len(autodiscover_has_cname))
	fmt.Printf("✅ Autodiscover有CNAME记录且可以获得配置的域名数量: %d\n", len(autodiscover_cname_and_config))

	fmt.Printf("✅ 通过 Autoconfig 可以获取配置信息的域名数量: %d\n", len(validAutoconfigDomains))
	fmt.Printf("✅ 通过 Autoconfig_directurl 可以获取配置信息的域名数量: %d\n", len(autoconfigFromDirecturl))
	fmt.Printf("✅ 通过 Autoconfig_ISPDB 可以获取配置信息的域名数量: %d\n", len(autoconfigFromISPDB))
	fmt.Printf("✅ 通过 Autoconfig_MX_samedomain 可以获取配置信息的域名数量: %d\n", len(autoconfigFromMXSameDomain))
	fmt.Printf("✅ 通过 Autoconfig_MX 可以获取配置信息的域名数量: %d\n", len(autoconfigFromMX))

	fmt.Printf("✅ 通过 SRV 可以获取配置信息的域名数量: %d\n", len(validSRVDomains))
	fmt.Printf("✅ 通过 SRV 可以获取配置信息且 DNSSEC 检查通过的域名数量: %d\n", len(srvDNSSECPassed))

	fmt.Printf("✅ 可以通过 Autodiscover、Autoconfig、SRV 获取配置信息的域名数量: %d\n", len(validThreeAll))
	fmt.Printf("✅ 可以通过 Autodiscover、Autoconfig 获取配置信息的域名数量: %d\n", len(validAutodiscoverAndAutoconfig))
	fmt.Printf("✅ 可以通过 Autodiscover、SRV 获取配置信息的域名数量: %d\n", len(validAutodiscoverAndSRV))
	fmt.Printf("✅ 可以通过 Autoconfig、SRV 获取配置信息的域名数量: %d\n", len(validAutoconfigAndSRV))
	fmt.Printf("✅ 仅可以通过 Autodiscover 获取配置信息的域名数量: %d\n", len(validOnlyAutodiscover))
	fmt.Printf("✅ 仅可以通过 Autoconfig 获取配置信息的域名数量: %d\n", len(validOnlyAutoconfig))
	fmt.Printf("✅ 仅可以通过 SRV 获取配置信息的域名数量: %d\n", len(validOnlySRV))
	fmt.Printf("✅ 无法通过前三种任意方法获取配置信息的域名数量: %d\n", len(validNone))
	fmt.Printf("✅ 无法通过四种任意方法获取配置信息的域名数量: %d\n", len(validNoneFour))
	fmt.Printf("✅ 可以通过GUESS获取配置信息的域名数量: %d\n", len(validGuessDomains))
	fmt.Printf("📌 SRV(IMAP) 域名数量: %d\n", len(srvIMAPDomains))
	fmt.Printf("📌 SRV(IMAPS) 域名数量: %d\n", len(srvIMAPSUDomains))
	fmt.Printf("📌 SRV(POP3) 域名数量: %d\n", len(srvPOP3Domains))
	fmt.Printf("📌 SRV(POP3S) 域名数量: %d\n", len(srvPOP3SDomains))
	fmt.Printf("📌 SRV(Submission) 域名数量: %d\n", len(srvSubmissionDomains))
	fmt.Printf("📌 SRV(Submissions) 域名数量: %d\n", len(srvSubmissionsDomains))

	fmt.Printf("✅ 一共处理了域名数量: %d\n", domainProcessed)

	// 将 autoconfig_from_ISPDB 写入文件
	autoconfigFromISPDBList := mapToSlice(autoconfigFromISPDB)
	if err := saveToJSON("data/autoconfig_from_ISPDB.json", autoconfigFromISPDBList); err != nil {
		log.Printf("Error saving autoconfig_from_ISPDB: %v", err)
	}

	// 将 domain_stats 写入文件
	dataToSave := map[string]interface{}{
		"valid_autodiscover_domains":        mapToSlice(validAutodiscoverDomains),
		"autodiscover_from_post":            mapToSlice(autodiscoverFromPost),
		"autodiscover_from_srvpost":         mapToSlice(autodiscoverFromSrvpost),
		"autodiscover_from_getpost":         mapToSlice(autodiscoverFromGetpost),
		"autodiscover_from_direct_get":      mapToSlice(autodiscoverFromDirectGet),
		"valid_autoconfig_domains":          mapToSlice(validAutoconfigDomains),
		"autoconfig_from_directurl":         mapToSlice(autoconfigFromDirecturl),
		"autoconfig_from_ISPDB":             mapToSlice(autoconfigFromISPDB),
		"autoconfig_from_MX_samedomain":     mapToSlice(autoconfigFromMXSameDomain),
		"autoconfig_from_MX":                mapToSlice(autoconfigFromMX),
		"valid_srv_domains":                 mapToSlice(validSRVDomains),
		"srv_dnssec_passed":                 mapToSlice(srvDNSSECPassed),
		"valid_three_all":                   mapToSlice(validThreeAll),
		"valid_autodiscover_and_autoconfig": mapToSlice(validAutodiscoverAndAutoconfig),
		"valid_autodiscover_and_srv":        mapToSlice(validAutodiscoverAndSRV),
		"valid_autoconfig_and_srv":          mapToSlice(validAutoconfigAndSRV),
		"valid_only_autodiscover":           mapToSlice(validOnlyAutodiscover),
		"valid_only_autoconfig":             mapToSlice(validOnlyAutoconfig),
		"valid_only_srv":                    mapToSlice(validOnlySRV),
		"valid_none":                        mapToSlice(validNone),
		"valid_none_four":                   mapToSlice(validNoneFour),
		"valid_guess":                       mapToSlice(validGuessDomains),
	}

	if err := saveToJSON("data/domain_stats.json", dataToSave); err != nil {
		log.Fatalf("Error saving domain_stats: %v", err)
	}
}

func mapToSlice(m map[string]struct{}) []string {
	slice := make([]string, 0, len(m))
	for key := range m {
		slice = append(slice, key)
	}
	return slice
}

func saveToJSON(filename string, data interface{}) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ") // 设置缩进为 4 个空格
	encoder.SetEscapeHTML(false)  // 不转义 HTML 字符

	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode data to JSON: %v", err)
	}

	fmt.Printf("✅ 统计结果已成功保存到 '%s'.\n", filename)
	return nil
}