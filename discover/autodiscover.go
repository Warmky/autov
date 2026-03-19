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
	"strings"
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
		res := getAutodiscoverConfig(domain, uri, email, "post", index, 0, 0, 0)
		res.URI = uri
		results = append(results, *res)
	}

	// method2: 通过 DNS SRV 记录找到 server, 再进行 POST 请求
	service := "_autodiscover._tcp." + domain
	uriDNS, _, err := utils.LookupSRVWithAD_autodiscover(domain)
	if err != nil {
		result_srv := models.AutodiscoverResult{
			Domain:    domain,
			Method:    "srv-post",
			Index:     0,
			Error:     fmt.Sprintf("Failed to lookup SRV records for %s: %v", service, err),
			StatusTag: "SRV_LOOKUP_FAILED",
		}
		results = append(results, result_srv)
	} else {
		res := getAutodiscoverConfig(domain, uriDNS, email, "srv-post", 0, 0, 0, 0)
		res.URI = uriDNS
		results = append(results, *res)
	}

	// method3：先 GET 找到 server，再 POST 请求
	getURI := fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain)
	resGET := GET_AutodiscoverConfig(domain, getURI, email)
	resGET.URI = getURI
	results = append(results, *resGET)

	// method4: 直接 GET 请求
	direct_getURIs := []string{
		fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("https://autodiscover.%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", domain),
	}
	for i, direct_getURI := range direct_getURIs {
		index := i + 1
		res := direct_GET_AutodiscoverConfig(domain, direct_getURI, email, "direct_get", index, 0, 0, 0)
		res.URI = direct_getURI
		results = append(results, *res)
	}

	return results
}

// getAutodiscoverConfig 执行核心的 POST 请求逻辑
func getAutodiscoverConfig(origin_domain string, uri string, email_add string, method string, index int, flag1 int, flag2 int, flag3 int) *models.AutodiscoverResult {
	result := &models.AutodiscoverResult{
		Domain:        origin_domain,
		Method:        method,
		Index:         index,
		URI:           uri,
		Flag1:         flag1,
		Flag2:         flag2,
		Flag3:         flag3,
		ServerHeaders: make(map[string]string),
		Redirects:     []map[string]interface{}{},
	}

	xmlRequest := fmt.Sprintf(`
		<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
			<Request>
				<EMailAddress>%s</EMailAddress>
				<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
			</Request>
		</Autodiscover>`, email_add)

	req, err := http.NewRequest("POST", uri, bytes.NewBufferString(xmlRequest))
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		result.StatusTag = "REQ_CREATE_ERROR"
		return result
	}
	req.Header.Set("Content-Type", "text/xml")
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 15 * time.Second,
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

	currentRedirects := utils.GetRedirects(resp)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		result.Flag1++
		location := resp.Header.Get("Location")
		if location == "" {
			result.Error = "missing Location header in redirect"
			result.StatusTag = "HTTP_REDIRECT_MISSING_LOCATION"
			result.Redirects = currentRedirects
			return result
		} else if result.Flag1 > 10 {
			result.Error = "too many redirect times"
			result.StatusTag = "HTTP_REDIRECT_LIMIT"
			result.Redirects = currentRedirects
			return result
		}

		newURI, err := url.Parse(location)
		if err != nil {
			result.Error = fmt.Sprintf("failed to parse redirect URL: %s", location)
			result.StatusTag = "HTTP_REDIRECT_PARSE_ERROR"
			result.Redirects = currentRedirects
			return result
		}

		child := getAutodiscoverConfig(origin_domain, newURI.String(), email_add, method, index, result.Flag1, result.Flag2, result.Flag3)
		child.Redirects = append(currentRedirects, child.Redirects...)
		if len(child.ServerHeaders) == 0 {
			child.ServerHeaders = result.ServerHeaders
		}
		return child

	} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			result.Error = fmt.Sprintf("failed to read response body: %v", err)
			result.StatusTag = "READ_BODY_ERROR"
			result.Redirects = currentRedirects
			return result
		}

		bodyStr := string(body)
		result.Redirects = currentRedirects
		result.RawBody = bodyStr // 核心：默认保留 RawBody，不论后续解析成功还是失败

		var autodiscoverResp models.AutodiscoverResponse
		err = xml.Unmarshal(body, &autodiscoverResp)
		if err != nil {
			result.Error = fmt.Sprintf("failed to unmarshal XML: %v", err)
			lowerConfig := strings.ToLower(bodyStr)
			if !strings.Contains(lowerConfig, `<html`) && !strings.Contains(lowerConfig, `<item`) {
				result.StatusTag = "MALFORMED_XML" // 这里就是你要存入文件的残缺XML
			} else {
				result.StatusTag = "UNMARSHAL_ERROR"
			}
			return result
		}

		if autodiscoverResp.Response.Account.Action == "redirectAddr" {
			result.Flag2++
			newEmail := autodiscoverResp.Response.Account.RedirectAddr
			if newEmail != "" && result.Flag2 <= 10 {
				child := getAutodiscoverConfig(origin_domain, uri, newEmail, method, index, result.Flag1, result.Flag2, result.Flag3)
				child.Redirects = append(currentRedirects, child.Redirects...)
				if len(child.ServerHeaders) == 0 {
					child.ServerHeaders = result.ServerHeaders
				}
				return child
			} else {
				result.Error = "too many RedirectAddr or nil ReAddr"
				result.StatusTag = "REDIRECT_ADDR_FAILED"
				return result
			}
		} else if autodiscoverResp.Response.Account.Action == "redirectUrl" {
			result.Flag3++
			newUri := autodiscoverResp.Response.Account.RedirectUrl
			if newUri != "" && result.Flag3 <= 10 {
				child := getAutodiscoverConfig(origin_domain, newUri, email_add, method, index, result.Flag1, result.Flag2, result.Flag3)
				child.Redirects = append(currentRedirects, child.Redirects...)
				if len(child.ServerHeaders) == 0 {
					child.ServerHeaders = result.ServerHeaders
				}
				return child
			} else {
				result.Error = "too many RedirectUrl or nil Reuri"
				result.StatusTag = "REDIRECT_URL_FAILED"
				return result
			}
		} else if autodiscoverResp.Response.Account.Action == "settings" {
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
		} else if autodiscoverResp.Response.Error != nil {
			result.Error = fmt.Sprintf("Errorcode:%v-%s", autodiscoverResp.Response.Error.ErrorCode, autodiscoverResp.Response.Error.Message)
			result.StatusTag = "XML_API_ERROR"
			return result
		} else {
			result.Error = fmt.Sprintf("Non-valid Response element for %s", email_add)
			result.StatusTag = "INVALID_RESPONSE_ELEMENT"
			return result
		}
	} else {
		bodyBytes, _ := io.ReadAll(resp.Body)
		result.RawBody = string(bodyBytes)
		result.Error = fmt.Sprintf("unexpected status code: %d", resp.StatusCode)
		result.StatusTag = "HTTP_ERROR"
		result.Redirects = currentRedirects
		return result
	}
}

// GET_AutodiscoverConfig
func GET_AutodiscoverConfig(origin_domain string, uri string, email_add string) *models.AutodiscoverResult {
	result := &models.AutodiscoverResult{
		Domain:        origin_domain,
		Method:        "get-post",
		URI:           uri,
		ServerHeaders: make(map[string]string),
		Redirects:     []map[string]interface{}{},
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 15 * time.Second,
	}

	resp, err := client.Get(uri)
	if err != nil {
		result.Error = fmt.Sprintf("failed to send GET request: %v", err)
		result.StatusTag = "REQ_SEND_ERROR"
		return result
	}
	defer resp.Body.Close()

	result.ServerHeaders["Server"] = resp.Header.Get("Server")
	result.ServerHeaders["X-Powered-By"] = resp.Header.Get("X-Powered-By")
	result.ServerHeaders["X-FEServer"] = resp.Header.Get("X-FEServer")
	result.ServerHeaders["X-AspNet-Version"] = resp.Header.Get("X-AspNet-Version")
	result.ServerHeaders["Set-Cookie"] = resp.Header.Get("Set-Cookie")

	currentRedirects := utils.GetRedirects(resp)

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		if location == "" {
			result.Error = "missing Location header in redirect"
			result.StatusTag = "HTTP_REDIRECT_MISSING_LOCATION"
			return result
		}
		newURI, err := url.Parse(location)
		if err != nil {
			result.Error = fmt.Sprintf("failed to parse redirect URL: %s", location)
			result.StatusTag = "HTTP_REDIRECT_PARSE_ERROR"
			return result
		}
		child := getAutodiscoverConfig(origin_domain, newURI.String(), email_add, "get_post", 0, 0, 0, 0)
		child.Redirects = append(currentRedirects, child.Redirects...)
		if len(child.ServerHeaders) == 0 {
			child.ServerHeaders = result.ServerHeaders
		}
		return child
	} else {
		bodyBytes, _ := io.ReadAll(resp.Body)
		result.RawBody = string(bodyBytes)
		result.Error = "not find Redirect Statuscode"
		result.StatusTag = "NO_REDIRECT_TO_POST"
		return result
	}
}

// direct_GET_AutodiscoverConfig
func direct_GET_AutodiscoverConfig(origin_domain string, uri string, email_add string, method string, index int, flag1 int, flag2 int, flag3 int) *models.AutodiscoverResult {
	result := &models.AutodiscoverResult{
		Domain:        origin_domain,
		Method:        method,
		Index:         index,
		URI:           uri,
		Flag1:         flag1,
		Flag2:         flag2,
		Flag3:         flag3,
		ServerHeaders: make(map[string]string),
		Redirects:     []map[string]interface{}{},
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       15 * time.Second,
	}

	resp, err := client.Get(uri)
	if err != nil {
		result.Error = fmt.Sprintf("failed to send request: %v", err)
		result.StatusTag = "REQ_SEND_ERROR"
		return result
	}
	defer resp.Body.Close()

	result.ServerHeaders["Server"] = resp.Header.Get("Server")
	result.ServerHeaders["X-Powered-By"] = resp.Header.Get("X-Powered-By")
	result.ServerHeaders["X-FEServer"] = resp.Header.Get("X-FEServer")
	result.ServerHeaders["X-AspNet-Version"] = resp.Header.Get("X-AspNet-Version")
	result.ServerHeaders["Set-Cookie"] = resp.Header.Get("Set-Cookie")

	currentRedirects := utils.GetRedirects(resp)

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		result.Flag1++
		location := resp.Header.Get("Location")
		if location == "" || result.Flag1 > 10 {
			result.Error = "missing location or too many redirects"
			result.StatusTag = "HTTP_REDIRECT_FAILED"
			result.Redirects = currentRedirects
			return result
		}
		newURI, err := url.Parse(location)
		if err != nil {
			result.Error = "failed to parse redirect URL"
			result.StatusTag = "HTTP_REDIRECT_PARSE_ERROR"
			result.Redirects = currentRedirects
			return result
		}
		child := direct_GET_AutodiscoverConfig(origin_domain, newURI.String(), email_add, method, index, result.Flag1, result.Flag2, result.Flag3)
		child.Redirects = append(currentRedirects, child.Redirects...)
		if len(child.ServerHeaders) == 0 {
			child.ServerHeaders = result.ServerHeaders
		}
		return child
	} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		result.Redirects = currentRedirects
		result.RawBody = bodyStr

		var autodiscoverResp models.AutodiscoverResponse
		err = xml.Unmarshal(body, &autodiscoverResp)
		if err != nil {
			result.Error = fmt.Sprintf("failed to unmarshal XML: %v", err)
			result.StatusTag = "UNMARSHAL_ERROR"
			return result
		}

		if autodiscoverResp.Response.Account.Action == "redirectAddr" {
			result.Flag2++
			newEmail := autodiscoverResp.Response.Account.RedirectAddr
			if newEmail != "" && result.Flag2 <= 10 {
				child := direct_GET_AutodiscoverConfig(origin_domain, uri, newEmail, method, index, result.Flag1, result.Flag2, result.Flag3)
				child.Redirects = append(currentRedirects, child.Redirects...)
				if len(child.ServerHeaders) == 0 {
					child.ServerHeaders = result.ServerHeaders
				}
				return child
			}
			result.StatusTag = "REDIRECT_ADDR_FAILED"
			return result
		} else if autodiscoverResp.Response.Account.Action == "redirectUrl" {
			result.Flag3++
			newUri := autodiscoverResp.Response.Account.RedirectUrl
			if newUri != "" && result.Flag3 <= 10 {
				child := direct_GET_AutodiscoverConfig(origin_domain, newUri, email_add, method, index, result.Flag1, result.Flag2, result.Flag3)
				child.Redirects = append(currentRedirects, child.Redirects...)
				if len(child.ServerHeaders) == 0 {
					child.ServerHeaders = result.ServerHeaders
				}
				return child
			}
			result.StatusTag = "REDIRECT_URL_FAILED"
			return result
		} else if autodiscoverResp.Response.Account.Action == "settings" {
			result.StatusTag = "SUCCESS"
			result.Config = bodyStr
			// 证书验证代码省略(与上面一致)
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
		} else {
			result.Error = "XML Error or Non-valid Response element"
			result.StatusTag = "INVALID_RESPONSE_ELEMENT"
			return result
		}
	} else {
		bodyBytes, _ := io.ReadAll(resp.Body)
		result.RawBody = string(bodyBytes)
		result.Error = fmt.Sprintf("unexpected status code: %d", resp.StatusCode)
		result.StatusTag = "HTTP_ERROR"
		result.Redirects = currentRedirects
		return result
	}
}
