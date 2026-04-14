package measurement

import (
	"autov/models"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/beevik/etree"
)

//生成提取了配置信息中关键字段的JSONL,并且有比较机制内和机制间的关键字段配置信息差异
// 9.14

// type MethodConfig struct {
// 	Method       string         `json:"Method"`
// 	Protocols    []ProtocolInfo `json:"Protocols"`
// 	OverallCheck string         `json:"OverallCheck"`
// }
// type DomainCheckResult struct {
// 	Domain                   string          `json:"Domain"`
// 	AutodiscoverCheckResult  []*MethodConfig `json:"AutodiscoverCheckResult,omitempty"` //以防有不同path的config不一致的情况，用数组表示
// 	AutoconfigCheckResult    []*MethodConfig `json:"AutoconfigCheckResult,omitempty"`
// 	SRVCheckResult           *MethodConfig   `json:"SRVCheckResult,omitempty"`
// 	AutodiscoverInconsistent bool            `json:"AutodiscoverInconsistent,omitempty"` // 只针对 Autodiscover
// 	AutoconfigInconsistent   bool            `json:"AutoconfigInconsistent,omitempty"`   // 只针对 Autoconfig
// 	Inconsistent             bool            `json:"Inconsistent,omitempty"`             // 记录是否有不一致的情况
// } //9.14

// 尝试保留原配置中的数据结构以供推荐时使用
type PortUsageDetail struct {
	Protocol       string `json:"protocol"`
	Port           string `json:"port"`
	SecurityStatus string `json:"security_status"` // 分析加密状态: "secure" / "insecure" / "unknown"
	LexicalStatus  string `json:"lexical_status"`  // 分析词法规范: "standard" / "nonstandard"
	Host           string `json:"host"`
	SSL            string `json:"ssl"` // 保留原始字符串，方便你在论文中举例分析畸形词法
}

type DomainCheckDifResult struct {
	Domain                   string                 `json:"domain"`
	AutodiscoverPortUsage    any                    `json:"autodiscover_check_result,omitempty"`
	AutoconfigPortUsage      any                    `json:"autoconfig_check_result,omitempty"`
	SRVPortUsage             any                    `json:"srv_check_result,omitempty"`
	AutodiscoverInconsistent bool                   `json:"autodiscover_inconsistent"`
	AutoconfigInconsistent   bool                   `json:"autoconfig_inconsistent"`
	MechanismDiff            bool                   `json:"mechanism_diff"`
	Inconsistent             bool                   `json:"inconsistent"`
	Extra                    map[string]interface{} `json:"extra,omitempty"` // 保留原始字段
}

// ---- 内部比较：机制内路径差异（协议+端口级别）----
func checkInternalDiff(validResults []map[string]interface{}) bool {
	if len(validResults) == 0 {
		return false
	}

	// 1. 收集所有路径的 ports_usage
	allPorts := []struct {
		Ports []PortUsageDetail
	}{}
	for _, item := range validResults {
		if ports, ok := item["ports_usage"].([]PortUsageDetail); ok {
			allPorts = append(allPorts, struct{ Ports []PortUsageDetail }{Ports: ports})
		}
	}

	// 2. 获取所有协议-端口组合
	protoPortGroups := make(map[string][][]string)
	for idx, item := range allPorts {
		for _, p := range item.Ports {
			key := fmt.Sprintf("%s-%s", strings.ToUpper(p.Protocol), p.Port)
			if _, exists := protoPortGroups[key]; !exists {
				protoPortGroups[key] = make([][]string, len(allPorts))
			}
			entry := fmt.Sprintf("%s:%s (%s)", p.Host, p.Port, strings.ToUpper(p.SSL))
			protoPortGroups[key][idx] = append(protoPortGroups[key][idx], entry)
		}
	}

	// 3. 比较每个协议端口的配置集合是否一致
	diffMap := make(map[string]bool)
	for protoPort, group := range protoPortGroups {
		var setValues []string
		for _, arr := range group {
			sort.Strings(arr)
			setValues = append(setValues, strings.Join(arr, ";"))
		}
		unique := make(map[string]struct{})
		for _, v := range setValues {
			unique[v] = struct{}{}
		}
		if len(unique) > 1 {
			diffMap[protoPort] = true
		}
	}

	// 4. 检查是否有路径缺少某个协议端口
	allKeys := make([]string, 0, len(protoPortGroups))
	for key := range protoPortGroups {
		allKeys = append(allKeys, key)
	}
	for _, item := range allPorts {
		for _, key := range allKeys {
			found := false
			for _, p := range item.Ports {
				k := fmt.Sprintf("%s-%s", strings.ToUpper(p.Protocol), p.Port)
				if k == key {
					found = true
					break
				}
			}
			if !found {
				diffMap[key] = true
			}
		}
	}

	// 5. 返回是否存在任何差异
	for _, v := range diffMap {
		if v {
			return true
		}
	}
	return false
}

// ---- 机制间比较 ----
func comparePortsUsage(autodiscover, autoconfig []map[string]interface{}, srv map[string]interface{}) map[string]map[string]PortUsageDetail {
	comparisonMap := make(map[string]map[string]PortUsageDetail)

	normalize := func(mech string, results []map[string]interface{}) []PortUsageDetail {
		var out []PortUsageDetail
		for _, item := range results {
			if ports, ok := item["ports_usage"].([]PortUsageDetail); ok {
				for _, p := range ports {
					ssl := p.SSL
					if ssl == "on" || ssl == "ssl" || ssl == "tls" || ssl == "STARTTLS" {
						ssl = "SSL"
					} else if ssl == "off" || ssl == "plain" {
						ssl = "PLAIN"
					}
					out = append(out, PortUsageDetail{
						Protocol: strings.ToUpper(p.Protocol),
						Port:     p.Port,
						Host:     p.Host,
						SSL:      ssl,
					})
				}
			}
		}
		return out
	}

	all := map[string][]PortUsageDetail{
		"autodiscover": normalize("autodiscover", autodiscover),
		"autoconfig":   normalize("autoconfig", autoconfig),
	}

	// SRV
	if srv != nil {
		srvRecords, ok := srv["srv_records"].(map[string]interface{})
		if ok {
			var combined []PortUsageDetail
			for _, typ := range []string{"recv", "send"} {
				if arr, ok := srvRecords[typ].([]interface{}); ok {
					for _, r := range arr {
						rec, _ := r.(map[string]interface{})
						service, _ := rec["Service"].(string)
						target, _ := rec["Target"].(string)
						port := fmt.Sprintf("%v", rec["Port"])

						proto := ""
						ssl := ""
						// if strings.Contains(service, "_imaps") {
						// 	proto, ssl = "IMAP", "SSL"
						// } else if strings.Contains(service, "_imap") {
						// 	proto, ssl = "IMAP", "STARTTLS"
						// } else if strings.Contains(service, "_pop3s") {
						// 	proto, ssl = "POP3", "SSL"
						// } else if strings.Contains(service, "_pop3") {
						// 	proto, ssl = "POP3", "STARTTLS"
						// } else if strings.Contains(service, "_submissions") {
						// 	proto, ssl = "SMTP", "SSL"
						// } else if strings.Contains(service, "_submission") {
						// 	proto, ssl = "SMTP", "STARTTLS"
						// }
						if strings.Contains(service, "_imaps") {
							proto, ssl = "IMAP", "on"
						} else if strings.Contains(service, "_imap") {
							proto, ssl = "IMAP", "off"
						} else if strings.Contains(service, "_pop3s") {
							proto, ssl = "POP3", "on"
						} else if strings.Contains(service, "_pop3") {
							proto, ssl = "POP3", "off"
						} else if strings.Contains(service, "_submissions") {
							proto, ssl = "SMTP", "on"
						} else if strings.Contains(service, "_submission") {
							proto, ssl = "SMTP", "off"
						}

						combined = append(combined, PortUsageDetail{
							Protocol: proto,
							Port:     port,
							Host:     strings.TrimSuffix(target, "."),
							SSL:      ssl,
						})
					}
				}
			}
			all["srv"] = combined
		}
	}

	// 组合比较
	for mech, ports := range all {
		for _, item := range ports {
			key := fmt.Sprintf("%s-%s", item.Protocol, item.Port)
			if _, exists := comparisonMap[key]; !exists {
				comparisonMap[key] = make(map[string]PortUsageDetail)
			}
			comparisonMap[key][mech] = item
		}
	}

	return comparisonMap
}

// ---- 机制间/机制内综合分析 ----
func analyzeConsistency(validResults, validacResults []map[string]interface{}, validsrvResult map[string]interface{}) (bool, bool, bool) {
	internalAutoDiff := checkInternalDiff(validResults)
	internalAcDiff := checkInternalDiff(validacResults)

	comparisonMap := comparePortsUsage(validResults, validacResults, validsrvResult)

	mechDiff := false
	for _, mechData := range comparisonMap {
		fields := []string{"Host", "SSL"}
		for _, field := range fields {
			values := []string{}
			for _, v := range mechData {
				switch field {
				case "Host":
					values = append(values, v.Host)
				case "SSL":
					values = append(values, v.SSL)
				}
			}
			if len(values) > 1 {
				allEqual := true
				for i := 1; i < len(values); i++ {
					if values[i] != values[0] {
						allEqual = false
						break
					}
				}
				if !allEqual {
					mechDiff = true
					break
				}
			}
		}
		if mechDiff {
			break
		}
	}

	return internalAutoDiff, internalAcDiff, mechDiff
}

func processDomainResult2(obj models.DomainResult, tracker *StatsTracker) *DomainCheckDifResult {
	domain := obj.Domain
	var autodiscoverConfigs []*models.MethodConfig
	var autoconfigConfigs []*models.MethodConfig
	var srvConfig *models.MethodConfig

	// 遍历 Autodiscover 配置
	var validResults []map[string]interface{}
	for _, entry := range obj.Autodiscover {
		if entry.Config != "" && !strings.HasPrefix(entry.Config, "Bad") && !strings.HasPrefix(entry.Config, "Errorcode") && !strings.HasPrefix(entry.Config, "Non-valid") {
			r, _ := parseXMLConfig_Autodiscover(entry.Config)

			if r != nil {
				autodiscoverConfigs = append(autodiscoverConfigs, r)

				// 🔴 1. 记录 Invalid 的具体域名
				if r.OverallCheck != "Valid" {
					tracker.Increment("AutoDisc_Err_" + r.OverallCheck)
					errMsg := fmt.Sprintf("[%s] Domain: %s", r.OverallCheck, obj.Domain)
					save_content_tofile("./AutoDisc_Error_Domains.txt", "", errMsg)
				}
			}

			PortsUsage := calculatePort_Autodiscover(entry.Config)

			for _, p := range PortsUsage {
				tracker.Increment(fmt.Sprintf("AutoDisc_%s_%s", p.Protocol, p.Port))
				tracker.Increment(fmt.Sprintf("AutoDisc_SSL_%s", p.SSL)) // 这里的 p.SSL 在非标准时保留了原始字符串

				// 🔴 2. 记录端口缺失 / undefined 的具体域名
				if p.Port == "" || p.Port == "undefined" {
					tracker.Increment("AutoDisc_" + p.Protocol + "_undefined")
					portMsg := fmt.Sprintf("Domain: %s | Protocol: %s | Issue: Port is empty/undefined", obj.Domain, p.Protocol)
					save_content_tofile("./Undefined_Ports.txt", "", portMsg)
				}

				// 🔴 3. 记录具体的奇葩 SSL/Encryption 值和域名
				if p.LexicalStatus == "nonstandard" {
					anomalyMsg := fmt.Sprintf("Domain: %s | Protocol: %s | Port: %s | Raw_Encryption_Value: [%s]", obj.Domain, p.Protocol, p.Port, p.SSL)
					save_content_tofile("./Lexical_Anomalies_SSL.txt", "", anomalyMsg)
				}

				// 记录非标准端口
				if p.SecurityStatus == "nonstandard_port" || p.SecurityStatus == "nonstandard" {
					save_content_tofile("./Autodiscover_unexp_port_results.txt", p.Port, "unexp "+p.Protocol+" port in domain "+obj.Domain+","+p.Host+",")
				}
			}

			validResults = append(validResults, map[string]interface{}{
				"index":       entry.Index,
				"uri":         entry.URI,
				"method":      entry.Method,
				"ports_usage": PortsUsage,
			})
		}
	}
	// 遍历 Autoconfig 配置
	var validacResults []map[string]interface{}
	for _, entry := range obj.Autoconfig {
		if entry.Config != "" {
			s, _ := parseXMLConfig_Autoconfig(entry.Config)
			if s != nil {
				autoconfigConfigs = append(autoconfigConfigs, s)

				// 🔴 1. 记录 Invalid 的具体域名
				if s.OverallCheck != "Valid" {
					tracker.Increment("AutoConf_Err_" + s.OverallCheck)
					errMsg := fmt.Sprintf("[%s] Domain: %s", s.OverallCheck, obj.Domain)
					save_content_tofile("./AutoConf_Error_Domains.txt", "", errMsg)
				}
			}
			PortsUsage := calculatePort_Autoconfig(entry.Config)

			for _, p := range PortsUsage {
				tracker.Increment(fmt.Sprintf("AutoConf_%s_%s", p.Protocol, p.Port))
				tracker.Increment(fmt.Sprintf("AutoConf_SSL_%s", p.SSL))

				// 🔴 2. 记录端口缺失 / undefined 的具体域名
				if p.Port == "" || p.Port == "undefined" {
					tracker.Increment("AutoConf_" + p.Protocol + "_undefined")
					portMsg := fmt.Sprintf("Domain: %s | Protocol: %s | Issue: Port is empty/undefined", obj.Domain, p.Protocol)
					save_content_tofile("./Undefined_Ports.txt", "", portMsg)
				}

				// 🔴 3. 记录具体的奇葩 SSL/SocketType 值和域名
				if p.LexicalStatus == "nonstandard" {
					anomalyMsg := fmt.Sprintf("Domain: %s | Protocol: %s | Port: %s | Raw_SocketType_Value: [%s]", obj.Domain, p.Protocol, p.Port, p.SSL)
					save_content_tofile("./Lexical_Anomalies_SSL.txt", "", anomalyMsg)
				}

				if p.SecurityStatus == "nonstandard_port" || p.SecurityStatus == "nonstandard" {
					save_content_tofile("./Autoconfig_unexp_port_results.txt", p.Port, "unexp "+p.Protocol+" port in domain "+obj.Domain+","+p.Host+",")
				}
			}

			validacResults = append(validacResults, map[string]interface{}{
				"index":       entry.Index,
				"uri":         entry.URI,
				"method":      entry.Method,
				"ports_usage": PortsUsage,
			})
		}
	}

	// 解析 SRV 记录
	var validsrvResult map[string]interface{}
	if obj.SRV.RecvRecords != nil || obj.SRV.SendRecords != nil {
		srvConfig, _ = parseConfig_SRV(&obj.SRV)

		// 📊 统计 SRV 错误
		if srvConfig != nil && srvConfig.OverallCheck != "Valid" {
			tracker.Increment("SRV_Err_" + srvConfig.OverallCheck)
		}

		srvPortsUsage := calculate_SRV(obj.SRV)

		// 📊 动态统计 SRV 端口
		for _, p := range srvPortsUsage {
			tracker.Increment(fmt.Sprintf("SRV_%s_%s", p.Protocol, p.Port))

			if p.LexicalStatus == "nonstandard" {
				save_content_tofile("./SRV_unexp_port_results.txt", p.Port, "unexp "+p.Protocol+" port in domain "+obj.Domain+","+p.Host+",")
			}
		}

		validsrvResult = map[string]interface{}{
			"ports_usage": srvPortsUsage,
		}
	}
	// 判断是否所有结果都为空
	if len(autodiscoverConfigs) == 0 && len(autoconfigConfigs) == 0 && srvConfig == nil {
		return nil
	}

	//比较所有字段
	// // 比较 Autodiscover 结果
	// autodiscoverConsistent, finalAutodiscover := compareMethodConfigs(autodiscoverConfigs)
	// // 比较 Autoconfig 结果
	// autoconfigConsistent, finalAutoconfig := compareMethodConfigs(autoconfigConfigs)

	//比较关键字段
	// autodiscoverConsistent, finalAutodiscover := compareMethodConfigs_autodiscover(autodiscoverConfigs)
	// autoconfigConsistent, finalAutoconfig := compareMethodConfigs_autoconfig(autoconfigConfigs)
	internalAdDiff, internalAcDiff, mechDiff := analyzeConsistency(validResults, validacResults, validsrvResult)
	// 总体不一致标志 = 任一机制内不一致 或 机制间不一致
	inconsistent := internalAdDiff || internalAcDiff || mechDiff

	// 记录最终结果
	data := &DomainCheckDifResult{
		Domain:                   domain,
		AutodiscoverPortUsage:    validResults,
		AutoconfigPortUsage:      validacResults,
		SRVPortUsage:             validsrvResult,
		AutodiscoverInconsistent: internalAdDiff,
		AutoconfigInconsistent:   internalAcDiff,
		MechanismDiff:            mechDiff,
		Inconsistent:             inconsistent,
	}

	// // 记录不一致的情况
	// if data.Inconsistent {
	// 	fmt.Printf("Inconsistent Config for Domain: %s\n", domain)
	// }

	return data
}

// 将差异分析结果写入 JSONL 文件
func saveCheckDifResultAsJSONL(result *DomainCheckDifResult, outputFile string) error {
	if result == nil {
		return fmt.Errorf("nil result")
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal error: %v", err)
	}

	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open file error: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	if _, err := writer.Write(jsonData); err != nil {
		return fmt.Errorf("write error: %v", err)
	}
	if _, err := writer.Write([]byte("\n")); err != nil {
		return fmt.Errorf("newline write error: %v", err)
	}
	writer.Flush()

	return nil
}

func calculatePort_Autodiscover(config string) []PortUsageDetail {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(config); err != nil {
		return nil
	}
	//这里是评分规则
	root := doc.SelectElement("Autodiscover")
	if root == nil {

		return nil
	}
	responseElem := root.SelectElement("Response")
	if responseElem == nil {

		return nil
	}
	accountElem := responseElem.SelectElement("Account")
	if accountElem == nil {
		return nil
	}
	accountTypeElem := accountElem.SelectElement("AccountType")
	if accountTypeElem == nil || accountTypeElem.Text() != "email" {
		return nil
	}
	actionElem := accountElem.SelectElement("Action")
	if actionElem == nil || actionElem.Text() != "settings" {
		return nil
	}

	var portsUsage []PortUsageDetail
	// 记录使用的端口情况
	securePorts := map[string]bool{
		"SMTP": false,
		"IMAP": false,
		"POP3": false,
	}
	insecurePorts := map[string]bool{
		"SMTP": false,
		"IMAP": false,
		"POP3": false,
	}
	nonStandardPorts := map[string]bool{
		"SMTP": false,
		"IMAP": false,
		"POP3": false,
	}
	//var protocols []ProtocolInfo
	for _, protocolElem := range accountElem.SelectElements("Protocol") {
		//protocol := ProtocolInfo{}
		protocolType := ""
		port := ""
		host := ""
		ssl := ""
		// 检查每个子元素是否存在再获取其内容
		if typeElem := protocolElem.SelectElement("Type"); typeElem != nil {
			protocolType = typeElem.Text()
		}
		if serverElem := protocolElem.SelectElement("Server"); serverElem != nil {
			host = serverElem.Text() //7.27
		}
		if portElem := protocolElem.SelectElement("Port"); portElem != nil {
			port = portElem.Text()
		}
		if encElem := protocolElem.SelectElement("Encryption"); encElem != nil {
			ssl = encElem.Text()
		} else if sslElem := protocolElem.SelectElement("SSL"); sslElem != nil {
			ssl = sslElem.Text()
		} else {
			ssl = "N/A"
		} //7.27
		// if protocol.SSL != "SSL" {
		// 	scores["SSL"] = "HHH"
		// 	//return scores
		// }
		// if protocol.Type == "SMTP" && protocol.Port == "465" {
		// 	scores["SMTPS"] = "yes"
		// }
		// if protocol.Type == "IMAP" && protocol.Port == "993" {
		// 	scores["IMAPS"] = "yes"
		// }
		lexicalstatus := "nonstandard"
		securitystatus := "unknown"

		//9.15_5
		if encElem := protocolElem.SelectElement("Encryption"); encElem != nil {
			switch ssl {
			case "NONE":
				lexicalstatus = "standard"
			case "SSL":
				lexicalstatus = "standard"
			case "TLS":
				lexicalstatus = "standard"
			case "Auto":
				lexicalstatus = "standard"
			default:
				lexicalstatus = "nonstandard"
			}

		} else if sslElem := protocolElem.SelectElement("SSL"); sslElem != nil {
			switch ssl {
			case "on":
				lexicalstatus = "standard"
			case "off":
				lexicalstatus = "standard"
			default:
				lexicalstatus = "nonstandard"
			}
		}
		// 分类端口
		switch protocolType {
		case "SMTP":
			if port == "465" {
				securitystatus = "secure" //9.15_5
				securePorts["SMTP"] = true
			} else if port == "25" || port == "587" {
				securitystatus = "insecure"
				insecurePorts["SMTP"] = true
			} else {
				nonStandardPorts["SMTP"] = true
			}
		case "IMAP":
			if port == "993" {
				securitystatus = "secure"
				securePorts["IMAP"] = true
			} else if port == "143" {
				securitystatus = "insecure"
				insecurePorts["IMAP"] = true
			} else {
				nonStandardPorts["IMAP"] = true
			}
		case "POP3":
			if port == "995" {
				securitystatus = "secure"
				securePorts["POP3"] = true
			} else if port == "110" {
				securitystatus = "insecure"
				insecurePorts["POP3"] = true
			} else {
				nonStandardPorts["POP3"] = true
			}
		}
		if protocolType != "" && port != "" {
			portsUsage = append(portsUsage, PortUsageDetail{
				Protocol:       protocolType,
				Port:           port,
				LexicalStatus:  lexicalstatus,
				SecurityStatus: securitystatus,
				Host:           host,
				SSL:            ssl,
			})
		} //全部记录到新增结构中
	}

	return portsUsage
}

func calculatePort_Autoconfig(config string) []PortUsageDetail {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(config); err != nil {
		return nil
	}
	//这里是评分规则
	root := doc.SelectElement("clientConfig")
	if root == nil {
		return nil
	}
	emailProviderElem := root.SelectElement("emailProvider")
	if emailProviderElem == nil {
		return nil
	}
	var portsUsage []PortUsageDetail
	// 记录使用的端口情况
	securePorts := map[string]bool{
		"SMTP": false,
		"IMAP": false,
		"POP3": false,
	}
	insecurePorts := map[string]bool{
		"SMTP": false,
		"IMAP": false,
		"POP3": false,
	}
	nonStandardPorts := map[string]bool{
		"SMTP": false,
		"IMAP": false,
		"POP3": false,
	}
	//var protocols []ProtocolInfo
	for _, protocolElem := range emailProviderElem.SelectElements("incomingServer") {
		//protocol := ProtocolInfo{}
		protocolType := ""
		port := ""
		host := ""
		ssl := ""
		// 检查每个子元素是否存在再获取其内容
		if typeELem := protocolElem.SelectAttr("type"); typeELem != nil {
			protocolType = typeELem.Value //? type属性 -> <Type>
		}
		if serverElem := protocolElem.SelectElement("hostname"); serverElem != nil {
			host = serverElem.Text() //<hostname> -> <Server>
		}
		if portElem := protocolElem.SelectElement("port"); portElem != nil {
			port = portElem.Text()
		}
		if sslElem := protocolElem.SelectElement("socketType"); sslElem != nil {
			ssl = sslElem.Text()
		} else {
			ssl = "N/A"
		} //7.27
		lexicalstatus := "nonstandard"
		securitystatus := "unknown"
		//9.15_5
		switch ssl {
		case "SSL":
			lexicalstatus = "standard"
		case "PLAIN":
			lexicalstatus = "standard"
		case "STARTTLS":
			lexicalstatus = "standard"
		default:
			lexicalstatus = "nonstandard"
		}
		// 分类端口
		switch protocolType {
		case "smtp":
			if port == "465" {
				securitystatus = "secure"
				securePorts["SMTP"] = true
			} else if port == "25" || port == "587" {
				securitystatus = "insecure"
				insecurePorts["SMTP"] = true
			} else {
				nonStandardPorts["SMTP"] = true
			}
		case "imap":
			if port == "993" {
				securitystatus = "secure"
				securePorts["IMAP"] = true
			} else if port == "143" {
				securitystatus = "insecure"
				insecurePorts["IMAP"] = true
			} else {
				nonStandardPorts["IMAP"] = true
			}
		case "pop3":
			if port == "995" {
				securitystatus = "secure"
				securePorts["POP3"] = true
			} else if port == "110" {
				securitystatus = "insecure"
				insecurePorts["POP3"] = true
			} else {
				nonStandardPorts["POP3"] = true
			}
		}
		if protocolType != "" && port != "" {
			portsUsage = append(portsUsage, PortUsageDetail{
				Protocol:       strings.ToTitle(protocolType),
				Port:           port,
				LexicalStatus:  lexicalstatus,
				SecurityStatus: securitystatus,
				Host:           host,
				SSL:            ssl,
			})
		} //全部记录到新增结构中
	}

	for _, protocolElem := range emailProviderElem.SelectElements("outgoingServer") {
		//protocol := ProtocolInfo{}
		protocolType := ""
		port := ""
		host := ""
		ssl := ""
		// 检查每个子元素是否存在再获取其内容
		if typeELem := protocolElem.SelectAttr("type"); typeELem != nil {
			protocolType = typeELem.Value //? type属性 -> <Type>
		}
		if serverElem := protocolElem.SelectElement("hostname"); serverElem != nil {
			host = serverElem.Text() //<hostname> -> <Server>
		}
		if portElem := protocolElem.SelectElement("port"); portElem != nil {
			port = portElem.Text()
		}
		if sslElem := protocolElem.SelectElement("socketType"); sslElem != nil {
			ssl = sslElem.Text()
		} else {
			ssl = "N/A"
		}
		lexicalstatus := "nonstandard"
		securitystatus := "unknown"
		//9.15_5
		switch ssl {
		case "SSL":
			lexicalstatus = "standard"
		case "PLAIN":
			lexicalstatus = "standard"
		case "STARTTLS":
			lexicalstatus = "standard"
		default:
			lexicalstatus = "nonstandard"
		}
		// 分类端口
		switch protocolType {
		case "smtp":
			if port == "465" {
				securitystatus = "secure"
				securePorts["SMTP"] = true
			} else if port == "25" || port == "587" {
				securitystatus = "insecure"
				insecurePorts["SMTP"] = true
			} else {
				nonStandardPorts["SMTP"] = true
			}
		case "imap":
			if port == "993" {
				securitystatus = "secure"
				securePorts["IMAP"] = true
			} else if port == "143" {
				securitystatus = "insecure"
				insecurePorts["IMAP"] = true
			} else {
				nonStandardPorts["IMAP"] = true
			}
		case "pop3":
			if port == "995" {
				securitystatus = "secure"
				securePorts["POP3"] = true
			} else if port == "110" {
				securitystatus = "insecure"
				insecurePorts["POP3"] = true
			} else {
				nonStandardPorts["POP3"] = true
			}
		}
		if protocolType != "" && port != "" {
			portsUsage = append(portsUsage, PortUsageDetail{
				Protocol:       strings.ToTitle(protocolType),
				Port:           port,
				LexicalStatus:  lexicalstatus,
				SecurityStatus: securitystatus,
				Host:           host,
				SSL:            ssl,
			})
		} //全部记录到新增结构中
	}

	return portsUsage
}

func calculate_SRV(result models.SRVResult) []PortUsageDetail {
	var portsUsage []PortUsageDetail
	allRecords := append(result.RecvRecords, result.SendRecords...)

	for _, record := range allRecords {
		port := record.Port
		status := Identify_Port_Status(record) // 原有函数无需改动

		// 统一处理 Target
		targetHost := strings.ToLower(strings.TrimSuffix(record.Target, "."))

		portsUsage = append(portsUsage, PortUsageDetail{
			Protocol:      normalizeProtocol(record.Service),
			Port:          strconv.Itoa(int(port)),
			LexicalStatus: status, //SRV只设了这一个状态
			Host:          targetHost,
			SSL:           normalizeSSL(record.Service),
		})
	}
	return portsUsage
}

func Identify_Port_Status(record models.SRVRecord) string {
	port := record.Port
	service_prefix := strings.Split(record.Service, ".")[0]
	var status string
	switch service_prefix {
	case "_submissions":
		if port == 465 {
			status = "secure"
		} else {
			status = "nonstandard"
		}
	case "_submission":
		if port == 25 || port == 587 {
			status = "insecure"
		} else {
			status = "nonstandard"
		}
	case "_imaps":
		if port == 993 {
			status = "secure"
		} else {
			status = "nonstandard"
		}
	case "_imap":
		if port == 143 {
			status = "insecure"
		} else {
			status = "nonstandard"
		}
	case "_pop3s":
		if port == 995 {
			status = "secure"
		} else {
			status = "nonstandard"
		}
	case "_pop3":
		if port == 110 {
			status = "insecure"
		} else {
			status = "nonstandard"
		}
	}
	return status
}
func normalizeProtocol(service string) string {
	if strings.HasPrefix(service, "_submission") || strings.HasPrefix(service, "_submissions") {
		return "SMTP"
	} else if strings.HasPrefix(service, "_imap") || strings.HasPrefix(service, "_imaps") {
		return "IMAP"
	} else if strings.HasPrefix(service, "_pop3") || strings.HasPrefix(service, "_pop3s") {
		return "POP3"
	}
	return "OTHER"
}
func normalizeSSL(service string) string {
	if strings.HasPrefix(service, "_submissions") || strings.HasPrefix(service, "_imaps") || strings.HasPrefix(service, "_pop3s") {
		return "on"
	} else if strings.HasPrefix(service, "_submission") || strings.HasPrefix(service, "_imap") || strings.HasPrefix(service, "_pop3") {
		return "off"
	}
	return "UNKNOWN"
}

// 解析每个对象中的Autodiscover的config
func parseXMLConfig_Autodiscover(config string) (*models.MethodConfig, error) {
	// 创建一个新的 etree 文档
	doc := etree.NewDocument()

	// 解析 config 中的 XML 字符串
	err := doc.ReadFromString(config)
	if err != nil {
		log.Printf("Error parsing XML: %v", err)
		return nil, err
	}

	// 查找根元素
	root := doc.SelectElement("Autodiscover")
	if root == nil {
		log.Println("No root element <Autodiscover> found.")
		result1 := &models.MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, root element <Autodiscover> lost",
		}
		return result1, fmt.Errorf("missing root element <Autodiscover>")
	}

	// 查找 Response 元素
	responseElem := root.SelectElement("Response")
	if responseElem == nil {
		log.Println("No <Response> element found.")
		result2 := &models.MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, <Response> element lost",
		}
		return result2, fmt.Errorf("missing <Response> element")
	}

	// // 打印 User 和 Account 信息
	// userElem := responseElem.SelectElement("User")
	// if userElem == nil {
	// 	result3 := &MethodConfig{
	// 		Method:       "Autodiscover",
	// 		Protocols:    nil,
	// 		OverallCheck: "Invalid, <User> element lost",
	// 	}
	// 	return result3, fmt.Errorf("missing <User> element")
	// } else if userElem.SelectElement("DisplayName") == nil {
	// 	result3 := &MethodConfig{
	// 		Method:       "Autodiscover",
	// 		Protocols:    nil,
	// 		OverallCheck: "Invalid,missing <DisplayName> in <User>",
	// 	}
	// 	return result3, fmt.Errorf("missing <DisplayName> in <User>")
	// } //需要考虑将diaplayName输出到结构体中吗？TODO  3.8因为没有User的过多，先不算作错误10105 ，9

	accountElem := responseElem.SelectElement("Account")
	if accountElem == nil {
		result4 := &models.MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, missing <Account> element",
		}
		return result4, fmt.Errorf("missing <Account> element")
	}
	//4.1检查<AccountType>和<Action>
	accountTypeElem := accountElem.SelectElement("AccountType")
	if accountTypeElem == nil || accountTypeElem.Text() != "email" {
		return &models.MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, <AccountType> must be 'email'",
		}, fmt.Errorf("<AccountType> must be 'email'")
	}
	actionElem := accountElem.SelectElement("Action")
	if actionElem == nil || actionElem.Text() != "settings" {
		return &models.MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, <Action> must be 'settings'",
		}, fmt.Errorf("<Action> must be 'settings'")
	}
	//4.2查找<Protocol>元素
	var protocols []models.ProtocolInfo
	for _, protocolElem := range accountElem.SelectElements("Protocol") {
		protocol := models.ProtocolInfo{}
		protocol.SingleCheck = "Valid" //首先设置为Valid //
		// 检查每个子元素是否存在再获取其内容
		if typeElem := protocolElem.SelectElement("Type"); typeElem != nil {
			protocol.Type = typeElem.Text()
		}
		if serverElem := protocolElem.SelectElement("Server"); serverElem != nil {
			protocol.Server = serverElem.Text()
		}
		if portElem := protocolElem.SelectElement("Port"); portElem != nil {
			protocol.Port = portElem.Text()
		}
		if domainRequiredElem := protocolElem.SelectElement("DomainRequired"); domainRequiredElem != nil {
			protocol.DomainRequired = domainRequiredElem.Text()
		}
		if spaElem := protocolElem.SelectElement("SPA"); spaElem != nil {
			protocol.SPA = spaElem.Text()
		}
		if sslElem := protocolElem.SelectElement("SSL"); sslElem != nil {
			protocol.SSL = sslElem.Text()
		}
		if authRequiredElem := protocolElem.SelectElement("AuthRequired"); authRequiredElem != nil {
			protocol.AuthRequired = authRequiredElem.Text()
		}
		if encryptionElem := protocolElem.SelectElement("Encryption"); encryptionElem != nil {
			protocol.Encryption = encryptionElem.Text()
		}
		if usePOPAuthElem := protocolElem.SelectElement("UsePOPAuth"); usePOPAuthElem != nil {
			protocol.UsePOPAuth = usePOPAuthElem.Text()
		}
		if smtpLastElem := protocolElem.SelectElement("SMTPLast"); smtpLastElem != nil {
			protocol.SMTPLast = smtpLastElem.Text()
		}
		if ttlElem := protocolElem.SelectElement("TTL"); ttlElem != nil {
			protocol.TTL = ttlElem.Text()
		}

		// 检查
		if protocolElem.SelectAttr("Type") != nil && protocol.Type != "" {
			protocol.SingleCheck = fmt.Sprintf("Invalid, <Type> element mustn't show, Type attribute of <Protocol> is %s", protocolElem.SelectAttr("Type").Value)
		} else {
			if protocol.Type == "" && protocolElem.SelectAttr("Type") == nil {
				protocol.SingleCheck = "Invalid, no Type attribute in <Protocol> element nor <Type> element"
			}
		}
		if protocol.SSL == "" {
			protocol.SSL = "default(on)" //补充了SSL的缺省值
		} //SSL检查应该在Encryption之前
		if protocol.Encryption != "" {
			if !(protocol.Type == "IMAP" || protocol.Type == "SMTP" || protocol.Type == "POP3") {
				protocol.SingleCheck = "Invalid, supposed no <Encryption>"
			}
			if !(protocol.Encryption == "None" || protocol.Encryption == "SSL" || protocol.Encryption == "TLS" || protocol.Encryption == "Auto") { //按照协议规范是只有这4个值，实际上不止，还有如STARTTLS
				protocol.SingleCheck = fmt.Sprintf("Invalid, Encryption method %s, not supposed to appear", protocol.Encryption)
			}
			if protocol.SSL != "" {
				protocol.SSL = ""
			}
		}
		if protocol.Type == "EXCH" || protocol.Type == "EXPR" || protocol.Type == "EXHTTP" || protocol.Type == "POP3" || protocol.Type == "SMTP" || protocol.Type == "IMAP" {
			if protocol.Server == "" {
				protocol.SingleCheck = "Invalid, no valid Server"
			}
		}
		if protocol.SMTPLast != "" && protocol.Type != "SMTP" {
			protocol.SMTPLast = ""
			protocol.SingleCheck = "Invalid, SMTPLast not supposed"
		}
		if protocol.SPA == "" && (protocol.Type == "IMAP" || protocol.Type == "SMTP" || protocol.Type == "POP3") {
			protocol.SPA = "default(on)" //补充SPA缺省值
		}
		if protocol.SPA != "" && !(protocol.Type == "IMAP" || protocol.Type == "SMTP" || protocol.Type == "POP3") {
			protocol.SPA = ""
			protocol.SingleCheck = "Invalid, SPA not supposed"
		}
		if protocol.UsePOPAuth != "" && protocol.Type != "SMTP" {
			protocol.UsePOPAuth = ""
			protocol.SingleCheck = "Invalid, UsePOPAuth not supposed"
		}

		protocols = append(protocols, protocol)
	}
	finalStatus := "Valid"
	for _, protocol := range protocols {
		if protocol.SingleCheck != "Valid" {
			finalStatus = "Invalid"
			break
		}
	} //Autodiscover采取的是有一个协议不对就都不对（因为没有找到优先使用规则）
	result := &models.MethodConfig{
		Method:       "Autodiscover",
		Protocols:    protocols,
		OverallCheck: finalStatus,
	}
	return result, nil

}

// 解析每个对象中的Autoconfig的config
func parseXMLConfig_Autoconfig(config string) (*models.MethodConfig, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(config)
	if err != nil {
		log.Printf("Error parsing XML: %v", err)
		return nil, err
	}
	//1.确保根元素是<ClientConfig>
	root := doc.SelectElement("clientConfig")
	if root == nil {
		result1 := &models.MethodConfig{
			Method:       "Autoconfig",
			Protocols:    nil,
			OverallCheck: "Invalid, root element <clientConfig> lost",
		}
		return result1, fmt.Errorf("missing root element <clientConfig>")
	}
	//2.查找<emailProvider>元素
	emailProviderElem := root.SelectElement("emailProvider")
	if emailProviderElem == nil {
		result2 := &models.MethodConfig{
			Method:       "Autoconfig",
			Protocols:    nil,
			OverallCheck: "Invalid, <emailProvider> element lost",
		}
		return result2, fmt.Errorf("missing <emailProvider> element")
	}
	//先查找incomingServer,再OutgoingServer
	var protocols []models.ProtocolInfo
	for _, protocolElem := range emailProviderElem.SelectElements("incomingServer") {
		protocol := models.ProtocolInfo{}
		protocol.SingleCheck = "Valid"
		if typeELem := protocolElem.SelectAttr("type"); typeELem != nil {
			protocol.Type = typeELem.Value //? type属性 -> <Type>
		}
		if serverElem := protocolElem.SelectElement("hostname"); serverElem != nil {
			protocol.Server = serverElem.Text() //<hostname> -> <Server>
		}
		if portElem := protocolElem.SelectElement("port"); portElem != nil {
			protocol.Port = portElem.Text()
		}
		if sslElem := protocolElem.SelectElement("socketType"); sslElem != nil {
			protocol.SSL = sslElem.Text() //<socketType> -> <SSL>
		}

		//检查

		var authentications []string
		//对authentication
		hasOAuth2 := false
		haspassword_cleartext := false
		for _, authElem := range protocolElem.SelectElements("authentication") {
			authText := authElem.Text()
			authentications = append(authentications, authText)
			if authText == "OAuth2" {
				hasOAuth2 = true
			} else if authText == "password-cleartext" {
				haspassword_cleartext = true
			}
		}
		if hasOAuth2 && len(authentications) == 1 {
			protocol.SingleCheck = "Invalid, OAuth2 must have fallback authmethod" //

		}

		if len(authentications) != 0 {
			protocol.Encryption = strings.Join(authentications, ", ")
		}

		if protocol.Type == "imap" {
			//关于端口和socketType的检查
			if protocol.SSL == "SSL" || protocol.SSL == "TLS" {
				if protocol.Port != "993" {
					protocol.SingleCheck = "Invalid, supposed IMAP-SSL-993"
				}
			} else if protocol.SSL == "STARTTLS" {
				if protocol.Port != "143" {
					protocol.SingleCheck = "Invalid, supposed IMAP-STARTTLS-143"
				}
			} else if protocol.SSL == "plain" { //plain
				if haspassword_cleartext && len(authentications) == 1 {
					protocol.SingleCheck = "Invalid, only plain method is not supposed"
				} //如果只有plain认证算Invalid
			} else { //出现了除以上三者之外别的socketType
				protocol.SingleCheck = fmt.Sprintf("Invalid, socketType %s not supposed", protocol.SSL)
			}

		} else if protocol.Type == "pop3" {
			if protocol.SSL == "SSL" || protocol.SSL == "TLS" {
				if protocol.Port != "995" {
					protocol.SingleCheck = "Invalid, supposed POP3-SSL-995"
				}
			} else if protocol.SSL == "STARTTLS" {
				if protocol.Port != "110" {
					protocol.SingleCheck = "Invalid, supposed POP3-STARTTLS-110"
				}
			} else if protocol.SSL == "plain" { //plain
				if haspassword_cleartext && len(authentications) == 1 {
					protocol.SingleCheck = "Invalid, only plain method is not supposed"
				}
			} else {
				protocol.SingleCheck = fmt.Sprintf("Invalid, socketType %s not supposed", protocol.SSL)
			}

		} else {
			protocol.SingleCheck = "Invalid, Type supposed to be imap or pop3"
		}
		protocols = append(protocols, protocol)
	}
	finalStatus1 := "Invalid"
	for _, protocol := range protocols {
		if protocol.SingleCheck == "Valid" {
			finalStatus1 = "Valid"
			break
		}
	} //设定的是incoming中有一个Valid即可,是按照priority先后顺序得到的

	var protocols2 []models.ProtocolInfo
	for _, protocolElem := range emailProviderElem.SelectElements("outgoingServer") {
		protocol := models.ProtocolInfo{}
		protocol.SingleCheck = "Valid"
		if typeELem := protocolElem.SelectAttr("type"); typeELem != nil {
			protocol.Type = typeELem.Value //? type属性 -> <Type>
		}
		if serverElem := protocolElem.SelectElement("hostname"); serverElem != nil {
			protocol.Server = serverElem.Text() //<hostname> -> <Server>
		}
		if portElem := protocolElem.SelectElement("port"); portElem != nil {
			protocol.Port = portElem.Text()
		}
		if sslElem := protocolElem.SelectElement("socketType"); sslElem != nil {
			protocol.SSL = sslElem.Text() //<socketType> -> <SSL>
		}
		// if encryptionElem := protocolElem.SelectElement("authentication"); encryptionElem != nil {
		// 	protocol.Encryption = encryptionElem.Text() //<authentication> -> <Encryption>
		// } //<username>没写

		//检查
		var authentications []string
		//对authentication
		hasOAuth2 := false
		haspassword_cleartext := false
		for _, authElem := range protocolElem.SelectElements("authentication") {
			authText := authElem.Text()
			authentications = append(authentications, authText)
			if authText == "OAuth2" {
				hasOAuth2 = true
			} else if authText == "password-cleartext" {
				haspassword_cleartext = true
			}
		}
		if hasOAuth2 && len(authentications) == 1 {
			protocol.SingleCheck = "Invalid, OAuth2 must have fallback authmethod"

		}

		if len(authentications) != 0 {
			protocol.Encryption = strings.Join(authentications, ", ")
		}

		if protocol.Type == "smtp" {
			if protocol.SSL == "SSL" || protocol.SSL == "TLS" {
				if protocol.Port != "465" { //?不确定
					protocol.SingleCheck = "Invalid, supposed SMTP-SSL-465"
				}
			} else if protocol.SSL == "STARTTLS" {
				if !(protocol.Port == "25" || protocol.Port == "2525" || protocol.Port == "587") { //?协议中没写2525
					protocol.SingleCheck = "Invalid, supposed SMTP-STARTTLS-587" //
				}
			} else if protocol.SSL == "plain" { //plain
				if haspassword_cleartext && len(authentications) == 1 {
					protocol.SingleCheck = "Invalid, only plain method is not supposed"
				}
			} else {
				protocol.SingleCheck = fmt.Sprintf("Invalid, socketType %s not supposed", protocol.SSL)
			}

		} else {
			protocol.SingleCheck = "Invalid, Type supposed to be smtp"
		}
		protocols2 = append(protocols2, protocol)
		protocols = append(protocols, protocol)
	}
	finalStatus2 := "Invalid"
	for _, protocol := range protocols2 {
		if protocol.SingleCheck == "Valid" {
			finalStatus2 = "Valid"
			break
		}
	} //设定的是outcoming中有一个Valid即可
	var finalStatus string
	if finalStatus1 == "Valid" && finalStatus2 == "Valid" {
		finalStatus = "Valid"
	} else {
		finalStatus = "Invalid"
	}
	result := &models.MethodConfig{
		Method:       "Autoconfig",
		Protocols:    protocols,
		OverallCheck: finalStatus,
	}
	return result, nil

}

// 根据 SRV 服务名称获取协议类型
func getServiceType(service string) string {
	switch {
	case strings.HasPrefix(service, "_imaps"):
		return "IMAPS"
	case strings.HasPrefix(service, "_imap"):
		return "IMAP"
	case strings.HasPrefix(service, "_pop3s"):
		return "POP3S"
	case strings.HasPrefix(service, "_pop3"):
		return "POP3"
	case strings.HasPrefix(service, "_submissions"):
		return "SMTPS"
	case strings.HasPrefix(service, "_submission"):
		return "SMTP"
	default:
		return "Unknown"
	}
}

// 解析每个对象中的Autodiscover的config
func parseConfig_SRV(SRVResult *models.SRVResult) (*models.MethodConfig, error) {
	var protocols []models.ProtocolInfo
	finalStatus := "Invalid"
	if SRVResult.RecvRecords != nil {
		for _, RecvRecord := range SRVResult.RecvRecords {
			var protocol models.ProtocolInfo
			protocol.Type = getServiceType(RecvRecord.Service)
			protocol.Server = RecvRecord.Target
			// if protocol.Server == "." {
			// 	continue //表示该服务不可使用，直接跳过 //应该在跑配置的时候已经过滤掉了
			// }
			protocol.Port = fmt.Sprintf("%d", RecvRecord.Port)
			protocol.SingleCheck = "Valid"
			if protocol.Type == "IMAPS" && protocol.Port != "993" {
				protocol.SingleCheck = "Invalid, supposed imaps-993"
			} else if protocol.Type == "IMAP" && protocol.Port != "143" { //也有用993的？
				protocol.SingleCheck = "Invalid, supposed imap-143"
			} else if protocol.Type == "POP3S" && protocol.Port != "995" {
				protocol.SingleCheck = "Invalid, supposed pop3s-995"
			} else if protocol.Type == "POP3" && protocol.Port != "110" {
				protocol.SingleCheck = "Invalid, supposed pop3-110"
			} else {
				if protocol.Type == "Unknown" {
					protocol.SingleCheck = "Invalid, unknown protocol type"
				}
			}
			if protocol.SingleCheck == "Valid" {
				finalStatus = "Valid"
			}
			protocols = append(protocols, protocol) //SRV是只要三者中有一个valid即为valid
		}
	}
	if SRVResult.SendRecords != nil {
		for _, SendRecord := range SRVResult.SendRecords {
			var protocol models.ProtocolInfo
			protocol.Type = getServiceType(SendRecord.Service)
			protocol.Server = SendRecord.Target
			protocol.Port = fmt.Sprintf("%d", SendRecord.Port)
			protocol.SingleCheck = "Valid"
			if protocol.Type == "SMTPS" && protocol.Port != "465" {
				protocol.SingleCheck = "Invalid, supposed smtps-465"
			} else if protocol.Type == "SMTP" {
				if protocol.Port == "25" { //没有考虑其他端口
					protocol.SingleCheck = "Invalid, cleartext SMTP not supposed"
				} else {
					if protocol.Port != "587" {
						protocol.SingleCheck = "Invalid, supposed smtp-587"
					}
				}
			} else {
				if protocol.Type == "Unknown" {
					protocol.SingleCheck = "Invalid, unknown protocol type"
				}
			}
			if protocol.SingleCheck == "Valid" {
				finalStatus = "Valid"
			}
			protocols = append(protocols, protocol)
		}
	}
	result := &models.MethodConfig{
		Method:       "SRV",
		Protocols:    protocols,
		OverallCheck: finalStatus,
	}
	return result, nil
}

// ==========================================
// 1. 你原有的文件写入辅助函数 (Utility Functions)
// ==========================================

func write_map_ToFile(fileName string, data map[string]int, method string) error {
	// 检查文件是否存在，若不存在则创建
	_, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		_, err := os.Create(fileName)
		if err != nil {
			return fmt.Errorf("fail to create file: %v", err)
		}
	}

	// 以追加模式打开文件
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("fail to open file: %v", err)
	}
	defer file.Close()

	file.WriteString("\n" + "=== Count result for Method: " + method + " ===\n")
	// 遍历 map 并写入文件
	for key, value := range data {
		line := fmt.Sprintf("%s : %d\n", key, value)
		_, err := file.WriteString(line)
		if err != nil {
			return fmt.Errorf("fail to write to file: %v", err)
		}
	}

	return nil
}

var fileMutex sync.Mutex

// 并发安全的日志写入函数
func save_content_tofile(fileName string, content string, inputFile string) {
	fileMutex.Lock()
	defer fileMutex.Unlock()

	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	inputfile_Name := filepath.Base(inputFile)
	content1 := inputfile_Name + content
	if _, err = file.WriteString(content1 + "\n"); err != nil {
		log.Printf("Error writing to file: %v\n", err)
	}
}
func save_number_tofile(fileName string, number int, label string) {
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	content := fmt.Sprintf("%s: %d\n", label, number)
	_, err = file.WriteString(content)
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}
}

// ==========================================
// 2. 并发安全的统计器 (Thread-Safe Tracker)
// ==========================================

type StatsTracker struct {
	mu     sync.Mutex
	Counts map[string]int
}

func NewStatsTracker() *StatsTracker {
	return &StatsTracker{
		Counts: make(map[string]int),
	}
}

// 安全地累加某个键的值
func (s *StatsTracker) Increment(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Counts[key]++
}

// 安全地增加特定数值
func (s *StatsTracker) Add(key string, val int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Counts[key] += val
}

// ==========================================
// 3. 升级后的 CheckDifferences (融合统计逻辑)
// ==========================================

// 从 init.jsonl 中读取每行域名结果，分析机制内外差异并保存，同时统计宏观数据
// 配置信息01，得到check_dif_results.jsonl（下一步使用）和 Count_results.txt
func CheckDifferences() {
	inputFile := "/home/wzq/project/autov/data/results_test.jsonl"
	outputFile := "/home/wzq/project/autov/data/check_dif_results.jsonl"
	summaryFile := "/home/wzq/project/autov/data/Count_results.txt" // 新增的统计文件路径

	file, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("❌ Failed to open input file: %v", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	sem := make(chan struct{}, 10) // 控制并发数
	var id int64
	var wg sync.WaitGroup

	// 实例化我们的并发统计器
	tracker := NewStatsTracker()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("⚠️  Error reading line: %v", err)
			continue
		}

		var obj models.DomainResult
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			log.Printf("⚠️  Skipping invalid JSON line: %v", err)
			continue
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(obj models.DomainResult) {
			defer wg.Done()
			defer func() { <-sem }()

			// 传入 tracker
			data := processDomainResult2(obj, tracker)
			curID := atomic.AddInt64(&id, 1)
			fmt.Printf("[%d] Processed domain: %s\n", curID, obj.Domain)

			if data != nil {
				// ----- 在这里进行数据统计 (并发安全) -----
				tracker.Increment("Total_Valid_Domains")

				if data.AutodiscoverPortUsage != nil {
					tracker.Increment("Usage_Autodiscover")
				}
				if data.AutoconfigPortUsage != nil {
					tracker.Increment("Usage_Autoconfig")
				}
				if data.SRVPortUsage != nil {
					tracker.Increment("Usage_SRV")
				}
				if data.MechanismDiff {
					tracker.Increment("Issue_Mechanism_Diff")
				}
				if data.AutodiscoverInconsistent {
					tracker.Increment("Issue_Internal_Autodiscover_Diff")
				}
				if data.AutoconfigInconsistent {
					tracker.Increment("Issue_Internal_Autoconfig_Diff")
				}
				if data.Inconsistent {
					tracker.Increment("Issue_Overall_Inconsistent")
				}

				// 将详细结果保存到 JSONL
				if err := saveCheckDifResultAsJSONL(data, outputFile); err != nil {
					log.Printf("❌ Error saving result for %s: %v", obj.Domain, err)
				}
			}
		}(obj)
	}

	// 等待所有协程执行完毕
	wg.Wait()
	fmt.Println("✅ All domains processed. Detailed results saved to JSONL.")

	// ==========================================
	// 4. 执行统计文件的写入
	// ==========================================
	fmt.Println("📊 Writing summary statistics to file...")

	// 写入使用率等综合指标
	err = write_map_ToFile(summaryFile, tracker.Counts, "Ecosystem Overview")
	if err != nil {
		log.Printf("❌ Failed to write summary map: %v", err)
	}

	// 也可以单独写几行特别重要的数字
	save_number_tofile(summaryFile, tracker.Counts["Total_Valid_Domains"], "Total Valid Domains Evaluated")
	save_number_tofile(summaryFile, tracker.Counts["Issue_Overall_Inconsistent"], "Total Domains with Inconsistencies")

	fmt.Printf("✅ Summary successfully saved to: %s\n", summaryFile)
}
