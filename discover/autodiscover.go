package discover

import (
	"autov/models"
	"autov/utils"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

func hashString(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// QueryAutodiscover 入口函数
func QueryAutodiscover(domain string, email string) []models.AutodiscoverResult {
	var results []models.AutodiscoverResult

	// method1: 构造标准 URL 列表进行 POST 请求
	uris := []string{
		fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("https://autodiscover.%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", domain),
	}
	for i, uri := range uris {
		index := i + 1
		// === 修改点：接收 serverHeaders ===
		flag1, flag2, flag3, redirects, config, certinfo, serverHeaders, err := getAutodiscoverConfig(domain, uri, email, "post", index, 0, 0, 0)

		fmt.Printf("flag1: %d\n", flag1)
		fmt.Printf("flag2: %d\n", flag2)
		fmt.Printf("flag3: %d\n", flag3)

		// //309
		// // 1. 先算真理：获取真实的完整大小和 Hash
		// actualSize := len(config)
		// actualHash := hashString(config)
		// // 2. 智能判断：这是不是一个 XML 文件？
		// // 转换为小写匹配，防止大小写混用
		// lowerConfig := strings.ToLower(config)
		// isXML := strings.Contains(lowerConfig, "<?xml") || strings.Contains(lowerConfig, "<autodiscover")
		// // 3. 精准截断：只有当它【不是 XML】且【极其庞大】时，才动手切掉
		// // 这样就能完美保留所有超过 1000 字节的真实配置文件！
		// if !isXML && actualSize > 1000 {
		// 	config = config[:500] + "\n...[TRUNCATED NON-XML BODY]"
		// }

		result := models.AutodiscoverResult{
			Domain: domain,
			Method: "POST",
			// Email:     email, // 新增 TODO:CNAME字段？
			Index:     index,
			URI:       uri,
			Redirects: redirects,
			Config:    config,
			// ResponseSize:     len(config),        // 新增
			// ResponseBodyHash: hashString(config), // 新增
			// ResponseSize:     actualSize, // 记录原始真实大小
			// ResponseBodyHash: actualHash, // 记录原始完整 Hash
			CertInfo:      certinfo,
			ServerHeaders: serverHeaders, // 保存抓取到的 Headers
		}
		if err != nil {
			result.Error = err.Error()
		}
		results = append(results, result)
	}

	// method2: 通过 DNS SRV 记录找到 server, 再进行 POST 请求
	service := "_autodiscover._tcp." + domain
	uriDNS, _, err := utils.LookupSRVWithAD_autodiscover(domain)
	if err != nil {
		result_srv := models.AutodiscoverResult{
			Domain: domain,
			// Email:  email, // 新增
			Method: "srv-post",
			Index:  0,
			Error:  fmt.Sprintf("Failed to lookup SRV records for %s: %v", service, err),
		}
		results = append(results, result_srv)
	} else {
		// === 修改点：接收 serverHeaders ===
		_, _, _, redirects, config, certinfo, serverHeaders, err1 := getAutodiscoverConfig(domain, uriDNS, email, "srv-post", 0, 0, 0, 0)
		// // 1. 先算真理：获取真实的完整大小和 Hash
		// actualSize := len(config)
		// actualHash := hashString(config)
		// // 2. 智能判断：这是不是一个 XML 文件？
		// // 转换为小写匹配，防止大小写混用
		// lowerConfig := strings.ToLower(config)
		// isXML := strings.Contains(lowerConfig, "<?xml") || strings.Contains(lowerConfig, "<autodiscover")
		// // 3. 精准截断：只有当它【不是 XML】且【极其庞大】时，才动手切掉
		// // 这样就能完美保留所有超过 1000 字节的真实配置文件！
		// if !isXML && actualSize > 1000 {
		// 	config = config[:500] + "\n...[TRUNCATED NON-XML BODY]"
		// }

		result_srv := models.AutodiscoverResult{
			Domain: domain,
			//Email:     email, // 新增
			Method:    "srv-post",
			Index:     0,
			Redirects: redirects,
			Config:    config,
			// ResponseSize:     len(config),        // 新增
			// ResponseBodyHash: hashString(config), // 新增
			// ResponseSize:     actualSize, // 记录原始真实大小
			// ResponseBodyHash: actualHash, // 记录原始完整 Hash
			CertInfo:      certinfo,
			ServerHeaders: serverHeaders, // 保存抓取到的 Headers
		}
		if err1 != nil {
			result_srv.Error = err1.Error()
		}
		results = append(results, result_srv)
	}

	// method3：先 GET 找到 server，再 POST 请求 (这里暂未修改 GET_AutodiscoverConfig 的签名，故 Headers 为 nil)
	getURI := fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain)
	redirects, config, certinfo, serverheaders, err := GET_AutodiscoverConfig(domain, getURI, email)
	// // 1. 先算真理：获取真实的完整大小和 Hash
	// actualSize := len(config)
	// actualHash := hashString(config)
	// // 2. 智能判断：这是不是一个 XML 文件？
	// // 转换为小写匹配，防止大小写混用
	// lowerConfig := strings.ToLower(config)
	// isXML := strings.Contains(lowerConfig, "<?xml") || strings.Contains(lowerConfig, "<autodiscover")
	// // 3. 精准截断：只有当它【不是 XML】且【极其庞大】时，才动手切掉
	// // 这样就能完美保留所有超过 1000 字节的真实配置文件！
	// if !isXML && actualSize > 1000 {
	// 	config = config[:500] + "\n...[TRUNCATED NON-XML BODY]"
	// }

	result_GET := models.AutodiscoverResult{
		Domain: domain,
		Method: "get-post",
		//Email:     email, // 新增
		Index:     0,
		URI:       getURI,
		Redirects: redirects,
		Config:    config,
		// ResponseSize:     len(config),        // 新增
		// ResponseBodyHash: hashString(config), // 新增
		// ResponseSize:     actualSize, // 记录原始真实大小
		// ResponseBodyHash: actualHash, // 记录原始完整 Hash
		CertInfo:      certinfo,
		ServerHeaders: serverheaders,
	}
	if err != nil {
		result_GET.Error = err.Error()
	}
	results = append(results, result_GET)

	// method4: 直接 GET 请求
	direct_getURIs := []string{
		fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("https://autodiscover.%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", domain),
	}
	for i, direct_getURI := range direct_getURIs {
		index := i + 1
		// 注意：这里调用的是 direct_GET...，如果你也想抓取它的 Header，需要类似修改 direct_GET_AutodiscoverConfig
		_, _, _, redirects, config, certinfo, serverheaders, err := direct_GET_AutodiscoverConfig(domain, direct_getURI, email, "get", index, 0, 0, 0)

		// // 1. 先算真理：获取真实的完整大小和 Hash
		// actualSize := len(config)
		// actualHash := hashString(config)

		// // 2. 智能判断：这是不是一个 XML 文件？
		// // 转换为小写匹配，防止大小写混用
		// lowerConfig := strings.ToLower(config)
		// isAutodiscover := strings.Contains(lowerConfig, "<autodiscover") || strings.Contains(lowerConfig, "autodiscover xmlns") //这里怎么判定不会丢？TODO

		// // 3. 精准截断：只有当它【不是 XML】且【极其庞大】时，才动手切掉
		// // 这样就能完美保留所有超过 1000 字节的真实配置文件！
		// if !isAutodiscover && actualSize > 1000 {
		// 	config = config[:500] + "\n...[TRUNCATED NON-XML BODY]"
		// }

		result := models.AutodiscoverResult{
			Domain:    domain,
			Method:    "direct_get",
			Index:     index,
			URI:       direct_getURI,
			Redirects: redirects,
			Config:    config,
			// ResponseSize:     len(config),        // 新增
			// ResponseBodyHash: hashString(config), // 新增
			CertInfo:      certinfo,
			ServerHeaders: serverheaders,
		}
		if err != nil {
			result.Error = err.Error()
		}
		results = append(results, result)
	}

	return results
}

// getAutodiscoverConfig 执行核心的 POST 请求逻辑
// 修改了返回值签名，增加了 map[string]string 用于返回 Headers
func getAutodiscoverConfig(origin_domain string, uri string, email_add string, method string, index int, flag1 int, flag2 int, flag3 int) (int, int, int, []map[string]interface{}, string, *models.CertInfo, map[string]string, error) {
	xmlRequest := fmt.Sprintf(`
		<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
			<Request>
				<EMailAddress>%s</EMailAddress>
				<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
			</Request>
		</Autodiscover>`, email_add)

	req, err := http.NewRequest("POST", uri, bytes.NewBufferString(xmlRequest))
	if err != nil {
		fmt.Printf("Error creating request for %s: %v\n", uri, err)
		// 返回 nil Headers
		return flag1, flag2, flag3, []map[string]interface{}{}, "", nil, nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "text/xml")
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 禁止重定向
		},
		Timeout: 15 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request to %s: %v\n", uri, err)
		// 返回 nil Headers
		return flag1, flag2, flag3, []map[string]interface{}{}, "", nil, nil, fmt.Errorf("failed to send request: %v", err)
	}

	// === 新增代码：提取关键指纹 Headers ===
	serverHeaders := make(map[string]string)
	// 提取主要指纹
	serverHeaders["Server"] = resp.Header.Get("Server")
	serverHeaders["X-Powered-By"] = resp.Header.Get("X-Powered-By")
	// Exchange 特有
	serverHeaders["X-FEServer"] = resp.Header.Get("X-FEServer")
	serverHeaders["X-AspNet-Version"] = resp.Header.Get("X-AspNet-Version")
	// 其他可能的特征
	serverHeaders["Set-Cookie"] = resp.Header.Get("Set-Cookie")
	// ===================================

	redirects := utils.GetRedirects(resp) // 获取当前重定向链
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		// 处理重定向
		flag1 = flag1 + 1
		//fmt.Printf("flag1now:%d\n", flag1)
		location := resp.Header.Get("Location")
		fmt.Printf("Redirect to: %s\n", location)
		if location == "" {
			return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("missing Location header in redirect")
		} else if flag1 > 10 {
			return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("too many redirect times")
		}

		newURI, err := url.Parse(location)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("failed to parse redirect URL: %s", location)
		}

		// 递归调用并合并重定向链
		// 注意：这里接收递归调用的返回值，包括新的 Headers
		newflag1, newflag2, newflag3, nextRedirects, result, certinfo, newHeaders, err := getAutodiscoverConfig(origin_domain, newURI.String(), email_add, method, index, flag1, flag2, flag3)

		// 优先返回最终服务器的 Headers (newHeaders)，如果最终服务器没返回则使用当前的
		finalHeaders := newHeaders
		if finalHeaders == nil || len(finalHeaders) == 0 {
			finalHeaders = serverHeaders
		}

		return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, finalHeaders, err

	} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// 处理成功响应
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("failed to read response body: %v", err)
		}

		var autodiscoverResp models.AutodiscoverResponse
		err = xml.Unmarshal(body, &autodiscoverResp)
		if err != nil {
			// Unmarshal 失败也返回 headers，因为这可能也是指纹的一部分
			return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("failed to unmarshal XML: %v", err)
		}

		// 处理 redirectAddr 和 redirectUrl
		if autodiscoverResp.Response.Account.Action == "redirectAddr" {
			flag2 = flag2 + 1
			newEmail := autodiscoverResp.Response.Account.RedirectAddr
			if newEmail != "" && flag2 <= 10 {
				newflag1, newflag2, newflag3, nextRedirects, result, certinfo, newHeaders, err := getAutodiscoverConfig(origin_domain, uri, newEmail, method, index, flag1, flag2, flag3)
				return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, newHeaders, err
			} else if newEmail != "" {
				return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("too many RedirectAddr")
			} else {
				return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("nil ReAddr")
			}
		} else if autodiscoverResp.Response.Account.Action == "redirectUrl" {
			flag3 = flag3 + 1
			newUri := autodiscoverResp.Response.Account.RedirectUrl
			if newUri != "" && flag3 <= 10 {
				newflag1, newflag2, newflag3, nextRedirects, result, certinfo, newHeaders, err := getAutodiscoverConfig(origin_domain, newUri, email_add, method, index, flag1, flag2, flag3)
				return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, newHeaders, err
			} else if newUri != "" {
				return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("too many RedirectUrl")
			} else {
				return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("nil Reuri")
			}
		} else if autodiscoverResp.Response.Account.Action == "settings" {
			// 成功获取配置
			var certInfo models.CertInfo
			// 提取证书信息
			if resp.TLS != nil {
				//var encodedCerts []string //3.09暂时删除
				goChain := resp.TLS.PeerCertificates
				endCert := goChain[0]

				// 证书验证
				dnsName := resp.Request.URL.Hostname()
				var VerifyError error
				certInfo.IsTrusted, VerifyError = utils.VerifyCertificate(goChain, dnsName)
				if VerifyError != nil {
					certInfo.VerifyError = VerifyError.Error()
				} else {
					certInfo.VerifyError = ""
				}

				certInfo.IsExpired = endCert.NotAfter.Before(time.Now())
				certInfo.IsHostnameMatch = utils.VerifyHostname(endCert, dnsName)
				certInfo.IsSelfSigned = utils.IsSelfSigned(endCert)
				certInfo.IsInOrder = utils.IsChainInOrder(goChain)
				certInfo.TLSVersion = resp.TLS.Version
				certInfo.Subject = endCert.Subject.CommonName
				certInfo.Issuer = endCert.Issuer.String()
				certInfo.SignatureAlg = endCert.SignatureAlgorithm.String()
				certInfo.AlgWarning = utils.AlgWarnings(endCert)

				// for _, cert := range goChain {
				// 	encoded := base64.StdEncoding.EncodeToString(cert.Raw)
				// 	encodedCerts = append(encodedCerts, encoded)
				// }
				// certInfo.RawCerts = encodedCerts
				//3.09暂时删除
			}
			// 成功时返回 serverHeaders
			return flag1, flag2, flag3, redirects, string(body), &certInfo, serverHeaders, nil

		} else if autodiscoverResp.Response.Error != nil {
			// 处理 XML 内部的错误响应
			errorConfig := fmt.Sprintf("Errorcode:%d-%s\n", autodiscoverResp.Response.Error.ErrorCode, autodiscoverResp.Response.Error.Message)
			// 返回 headers，因为 Error XML 也是由特定软件生成的
			return flag1, flag2, flag3, redirects, errorConfig, nil, serverHeaders, nil
		} else {
			// 处理 Response 不合法
			alsoErrorConfig := fmt.Sprintf("Non-valid Response element for %s: %s\n:", email_add, string(body))
			return flag1, flag2, flag3, redirects, alsoErrorConfig, nil, serverHeaders, nil
		}
	} else {
		// 处理非 200/300 状态码 (如 401, 404, 500)
		badResponse := fmt.Sprintf("Bad response for %s: %d\n", email_add, resp.StatusCode)
		// 修改后：读取真实的 HTTP Body 并返回，这样 Hash 才能真正反映服务器的特征
		// bodyBytes, _ := io.ReadAll(resp.Body)
		// actualBody := string(bodyBytes)

		return flag1, flag2, flag3, redirects, badResponse, nil, serverHeaders, fmt.Errorf("unexpected status code: %d", resp.StatusCode)

	}
}

// GET_AutodiscoverConfig
func GET_AutodiscoverConfig(origin_domain string, uri string, email_add string) ([]map[string]interface{}, string, *models.CertInfo, map[string]string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 禁止重定向
		},
		Timeout: 15 * time.Second,
	}

	resp, err := client.Get(uri)
	if err != nil {
		return []map[string]interface{}{}, "", nil, nil, fmt.Errorf("failed to send request: %v", err)
	}

	// === 新增代码：提取关键指纹 Headers ===
	serverHeaders := make(map[string]string)
	// 提取主要指纹
	serverHeaders["Server"] = resp.Header.Get("Server")
	serverHeaders["X-Powered-By"] = resp.Header.Get("X-Powered-By")
	// Exchange 特有
	serverHeaders["X-FEServer"] = resp.Header.Get("X-FEServer")
	serverHeaders["X-AspNet-Version"] = resp.Header.Get("X-AspNet-Version")
	// 其他可能的特征
	serverHeaders["Set-Cookie"] = resp.Header.Get("Set-Cookie")
	// ===================================

	redirects := utils.GetRedirects(resp)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		fmt.Printf("Redirect to: %s\n", location)
		if location == "" {
			return nil, "", nil, serverHeaders, fmt.Errorf("missing Location header in redirect")
		}
		newURI, err := url.Parse(location)
		if err != nil {
			return nil, "", nil, serverHeaders, fmt.Errorf("failed to parse redirect URL: %s", location)
		}

		// 递归调用, 注意这里 getAutodiscoverConfig 的返回值多了 headers，我们需要用 _ 忽略它，或者修改 GET 函数签名
		// 为了保持兼容性，这里暂时忽略 headers
		_, _, _, nextRedirects, result, certinfo, serverheaders, err := getAutodiscoverConfig(origin_domain, newURI.String(), email_add, "get_post", 0, 0, 0, 0)
		return append(redirects, nextRedirects...), result, certinfo, serverheaders, err //TODO
	} else {
		// 修改后：读取真实的 HTTP Body 并返回，这样 Hash 才能真正反映服务器的特征
		bodyBytes, _ := io.ReadAll(resp.Body)
		actualBody := string(bodyBytes)
		return nil, actualBody, nil, serverHeaders, fmt.Errorf("not find Redirect Statuscode")
	}
}

// direct_GET_AutodiscoverConfig
func direct_GET_AutodiscoverConfig(origin_domain string, uri string, email_add string, method string, index int, flag1 int, flag2 int, flag3 int) (int, int, int, []map[string]interface{}, string, *models.CertInfo, map[string]string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 15 * time.Second,
	}
	resp, err := client.Get(uri)
	if err != nil {
		return flag1, flag2, flag3, []map[string]interface{}{}, "", nil, nil, fmt.Errorf("failed to send request: %v", err)
	}

	// === 新增代码：提取关键指纹 Headers ===
	serverHeaders := make(map[string]string)
	// 提取主要指纹
	serverHeaders["Server"] = resp.Header.Get("Server")
	serverHeaders["X-Powered-By"] = resp.Header.Get("X-Powered-By")
	// Exchange 特有
	serverHeaders["X-FEServer"] = resp.Header.Get("X-FEServer")
	serverHeaders["X-AspNet-Version"] = resp.Header.Get("X-AspNet-Version")
	// 其他可能的特征
	serverHeaders["Set-Cookie"] = resp.Header.Get("Set-Cookie")
	// ===================================

	redirects := utils.GetRedirects(resp)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		flag1 = flag1 + 1
		location := resp.Header.Get("Location")
		fmt.Printf("Redirect to: %s\n", location)
		if location == "" {
			return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("missing Location header in redirect")
		} else if flag1 > 10 {
			return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("too many redirect times")
		}

		newURI, err := url.Parse(location)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("failed to parse redirect URL: %s", location)
		}

		newflag1, newflag2, newflag3, nextRedirects, result, certinfo, newHeaders, err := direct_GET_AutodiscoverConfig(origin_domain, newURI.String(), email_add, method, index, flag1, flag2, flag3)
		// 优先返回最终服务器的 Headers (newHeaders)，如果最终服务器没返回则使用当前的
		finalHeaders := newHeaders
		if finalHeaders == nil || len(finalHeaders) == 0 {
			finalHeaders = serverHeaders
		}
		return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, finalHeaders, err
	} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("failed to read response body: %v", err)
		}
		var autodiscoverResp models.AutodiscoverResponse
		err = xml.Unmarshal(body, &autodiscoverResp)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("failed to unmarshal XML: %v", err)
		}
		if autodiscoverResp.Response.Account.Action == "redirectAddr" {
			flag2 = flag2 + 1
			newEmail := autodiscoverResp.Response.Account.RedirectAddr
			if newEmail != "" {
				return flag1, flag2, flag3, redirects, string(body), nil, serverHeaders, nil
			} else {
				return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("nil ReAddr")
			}
		} else if autodiscoverResp.Response.Account.Action == "redirectUrl" {
			flag3 = flag3 + 1
			newUri := autodiscoverResp.Response.Account.RedirectUrl
			if newUri != "" && flag3 <= 10 {
				newflag1, newflag2, newflag3, nextRedirects, result, certinfo, serverheaders, err := direct_GET_AutodiscoverConfig(origin_domain, newUri, email_add, method, index, flag1, flag2, flag3)
				return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, serverheaders, err
			} else if newUri != "" {
				return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("too many RedirectUrl")
			} else {
				return flag1, flag2, flag3, redirects, "", nil, serverHeaders, fmt.Errorf("nil Reurl")
			}
		} else if autodiscoverResp.Response.Account.Action == "settings" {
			var certInfo models.CertInfo
			if resp.TLS != nil {
				//var encodedCerts []string  //3.09暂时删除
				goChain := resp.TLS.PeerCertificates
				endCert := goChain[0]

				dnsName := resp.Request.URL.Hostname()
				var VerifyError error
				certInfo.IsTrusted, VerifyError = utils.VerifyCertificate(goChain, dnsName)
				if VerifyError != nil {
					certInfo.VerifyError = VerifyError.Error()
				} else {
					certInfo.VerifyError = ""
				}
				certInfo.IsExpired = endCert.NotAfter.Before(time.Now())
				certInfo.IsHostnameMatch = utils.VerifyHostname(endCert, dnsName)
				certInfo.IsSelfSigned = utils.IsSelfSigned(endCert)
				certInfo.IsInOrder = utils.IsChainInOrder(goChain)
				certInfo.TLSVersion = resp.TLS.Version
				certInfo.Subject = endCert.Subject.CommonName
				certInfo.Issuer = endCert.Issuer.String()
				certInfo.SignatureAlg = endCert.SignatureAlgorithm.String()
				certInfo.AlgWarning = utils.AlgWarnings(endCert)

				// for _, cert := range goChain {
				// 	encoded := base64.StdEncoding.EncodeToString(cert.Raw)
				// 	encodedCerts = append(encodedCerts, encoded)
				// }
				// certInfo.RawCerts = encodedCerts
				//3.09暂时删除
			}
			return flag1, flag2, flag3, redirects, string(body), &certInfo, nil, nil
		} else if autodiscoverResp.Response.Error != nil {
			errorConfig := fmt.Sprintf("Errorcode:%d-%s\n", autodiscoverResp.Response.Error.ErrorCode, autodiscoverResp.Response.Error.Message)
			return flag1, flag2, flag3, redirects, errorConfig, nil, serverHeaders, nil
		} else {
			alsoErrorConfig := fmt.Sprintf("Non-valid Response element for %s: %s\n:", email_add, string(body))
			return flag1, flag2, flag3, redirects, alsoErrorConfig, nil, serverHeaders, nil
		}
	} else {
		bad_response := fmt.Sprintf("Bad response for %s:%d\n", email_add, resp.StatusCode)
		return flag1, flag2, flag3, redirects, bad_response, nil, serverHeaders, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
