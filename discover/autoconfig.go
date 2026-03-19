package discover

import (
	"autov/models"
	"autov/utils"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// 查询Autoconfig部分
func QueryAutoconfig(domain string, email string) []models.AutoconfigResult {
	var results []models.AutoconfigResult

	// method1: 直接通过url发送get请求得到config
	urls := []string{
		fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", domain, email),             //uri1
		fmt.Sprintf("https://%s/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=%s", domain, email), //uri2
		fmt.Sprintf("http://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", domain, email),              //uri3
		fmt.Sprintf("http://%s/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=%s", domain, email),  //uri4
	}
	for i, url := range urls {
		index := i + 1
		// 直接接收返回的结构体指针
		res := Get_autoconfig_config(domain, url, "directurl", index)
		results = append(results, *res)
	}

	// method2: ISPDB
	ISPurl := fmt.Sprintf("https://autoconfig.thunderbird.net/v1.1/%s", domain)
	res_ISPDB := Get_autoconfig_config(domain, ISPurl, "ISPDB", 0)
	results = append(results, *res_ISPDB)

	// method3: MX查询
	mxHost, err := utils.ResolveMXRecord(domain)
	if err != nil {
		result_MX := models.AutoconfigResult{
			Domain:    domain,
			Method:    "MX",
			Index:     0,
			Error:     fmt.Sprintf("Resolve MX Record error for %s: %v", domain, err),
			StatusTag: "MX_RESOLVE_FAILED", // 补充状态标签
		}
		results = append(results, result_MX)
	} else {
		mxFullDomain, mxMainDomain, err := utils.ExtractDomains(mxHost)
		if err != nil {
			result_MX := models.AutoconfigResult{
				Domain:    domain,
				Method:    "MX",
				Index:     0,
				Error:     fmt.Sprintf("extract domain from mxHost error for %s: %v", domain, err),
				StatusTag: "MX_EXTRACT_FAILED", // 补充状态标签
			}
			results = append(results, result_MX)
		} else {
			if mxFullDomain == mxMainDomain {
				urls := []string{
					fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", mxFullDomain, email), //1
					fmt.Sprintf("https://autoconfig.thunderbird.net/v1.1/%s", mxFullDomain),                        //3
				}
				for i, url := range urls {
					res := Get_autoconfig_config(domain, url, "MX_samedomain", i*2+1)
					results = append(results, *res)
				}
			} else {
				urls := []string{
					fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", mxFullDomain, email), //1
					fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", mxMainDomain, email), //2
					fmt.Sprintf("https://autoconfig.thunderbird.net/v1.1/%s", mxFullDomain),                        //3
					fmt.Sprintf("https://autoconfig.thunderbird.net/v1.1/%s", mxMainDomain),                        //4
				}
				for i, url := range urls {
					res := Get_autoconfig_config(domain, url, "MX", i+1)
					results = append(results, *res)
				}
			}
		}
	}

	return results
}

// 注意：返回值改成了只返回结构体指针
func Get_autoconfig_config(domain string, url string, method string, index int) *models.AutoconfigResult {
	result := &models.AutoconfigResult{
		Domain:        domain,
		Method:        method,
		Index:         index,
		URI:           url,
		ServerHeaders: make(map[string]string),
		Redirects:     []map[string]interface{}{},
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
		},
		Timeout: 15 * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		result.StatusTag = "REQ_CREATE_ERROR"
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("failed to send request: %v", err)
		result.StatusTag = "REQ_SEND_ERROR"
		return result
	}

	// 提取关键指纹 Headers
	result.ServerHeaders["Server"] = resp.Header.Get("Server")
	result.ServerHeaders["X-Powered-By"] = resp.Header.Get("X-Powered-By")
	result.ServerHeaders["X-FEServer"] = resp.Header.Get("X-FEServer")
	result.ServerHeaders["X-AspNet-Version"] = resp.Header.Get("X-AspNet-Version")
	result.ServerHeaders["Set-Cookie"] = resp.Header.Get("Set-Cookie")

	result.Redirects = utils.GetRedirects(resp)
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read response body: %v", err)
		result.StatusTag = "READ_BODY_ERROR"
		return result
	}

	bodyStr := string(bodyBytes)
	bodyTrimmed := strings.TrimSpace(bodyStr)

	// 无论成功还是失败，先把原始Body存下来，但做一层截断防护防止打爆内存
	lowerConfig := strings.ToLower(bodyStr)
	isXML := strings.Contains(lowerConfig, "<?xml") || strings.Contains(lowerConfig, "<clientconfig")
	if !isXML && len(bodyStr) > 2000 {
		result.RawBody = bodyStr[:1000] + "\n...[TRUNCATED NON-XML BODY]"
	} else {
		result.RawBody = bodyStr
	}

	var autoconfigResp models.AutoconfigResponse
	err = xml.Unmarshal(bodyBytes, &autoconfigResp)
	if err != nil {
		result.Error = fmt.Sprintf("failed to unmarshal XML: %v", err)

		// ===== 你的词法判断逻辑在这里完美融合 =====
		if (strings.HasPrefix(bodyTrimmed, `<?xml version="1.0"`) || strings.HasPrefix(bodyTrimmed, `<clientConfig`)) &&
			!strings.Contains(bodyTrimmed, `<html`) &&
			!strings.Contains(bodyTrimmed, `<item`) &&
			!strings.Contains(bodyTrimmed, `lastmod`) &&
			!strings.Contains(bodyTrimmed, `lt`) {

			// 标记为畸形XML，交由上层统一保存
			result.StatusTag = "MALFORMED_XML"
		} else {
			result.StatusTag = "UNMARSHAL_ERROR"
		}
		return result
	}

	// 成功获取配置
	result.StatusTag = "SUCCESS"
	result.Config = bodyStr

	if resp.TLS != nil {
		var certInfo models.CertInfo
		goChain := resp.TLS.PeerCertificates
		endCert := goChain[0]
		dnsName := resp.Request.URL.Hostname()
		certInfo.IsTrusted, _ = utils.VerifyCertificate(goChain, dnsName)
		certInfo.IsExpired = endCert.NotAfter.Before(time.Now())
		certInfo.IsHostnameMatch = utils.VerifyHostname(endCert, dnsName)
		certInfo.IsSelfSigned = utils.IsSelfSigned(endCert)
		certInfo.IsInOrder = utils.IsChainInOrder(goChain)
		certInfo.TLSVersion = resp.TLS.Version
		certInfo.Subject = endCert.Subject.CommonName
		certInfo.Issuer = endCert.Issuer.String()
		certInfo.SignatureAlg = endCert.SignatureAlgorithm.String()
		certInfo.AlgWarning = utils.AlgWarnings(endCert)
		result.CertInfo = &certInfo
	}

	return result
}
