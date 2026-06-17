# Context Feedback Fuzzer Report

- Target: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test#/`
- Detected Platform: **wordpress**
- Platform type: `CMS`
- Scan status: `done`
- Requests sent: `1000`
- Safety: GET-only, same-host scope, rate-limited, authorization flag required.
- Server technology hint: `php` / `apache`
- Confirmed findings: `10`
- Possible findings: `105`
- Confirmation rate: `8.7%`
- Marker verified count: `0`
- Marker verification rate: `0.0%`
- Crawled links for verification: `80`

## Wordlist generation mechanism

Tool tạo wordlist theo 3 lớp: platform paths từ profile/wordlist, extension paths theo server technology, và payload values theo loại parameter.

- Path wordlist sources: `wordpress.fuzz.txt, wp-plugins.fuzz.txt, wp-themes.fuzz.txt, urls-wordpress-3.3.1.txt`
- Server extension priority: `.php, .php.bak, .php.old`
- Parameter strategy examples:
  - `p` => `numeric`
  - `page_id` => `numeric`
  - `cat` => `numeric`
  - `search` => `text`
  - `s` => `text`
  - `author` => `numeric`
  - `action` => `action`
  - `nonce` => `generic`
  - `redirect_to` => `redirect`
  - `log` => `text`
  - `pwd` => `generic`
  - `name` => `text`

- Payload strategy examples:
  - `p` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `page_id` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `cat` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `search` => `text_canary, xss_reflection_probe, xss_trigger_probe, xss_trigger_probe, sqli_probe`
  - `s` => `text_canary, xss_reflection_probe, xss_trigger_probe, xss_trigger_probe, sqli_probe`
  - `author` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `action` => `action_canary, text_canary, sqli_probe`
  - `nonce` => `generic_canary, generic_bool, generic_number, sqli_probe`
  - `redirect_to` => `redirect_probe, redirect_probe`
  - `log` => `text_canary, xss_reflection_probe, xss_trigger_probe, xss_trigger_probe, sqli_probe`
  - `pwd` => `generic_canary, generic_bool, generic_number, sqli_probe`
  - `name` => `text_canary, xss_reflection_probe, xss_trigger_probe, xss_trigger_probe, sqli_probe`

## Marker verification mechanism

Marker-based fuzzing gắn marker duy nhất vào từng payload. Sau fuzzing, verification engine crawl các link cùng host và kiểm tra marker có xuất hiện lại không. Nếu có bằng chứng marker, finding được phân loại là confirmed.

- Markers generated: `114`
- Markers verified: `0`
- Markers failed: `114`
- Marker verification rate: `0.0%`
- Crawled links: `80`

## Fingerprint scores

- wordpress: 0
- joomla: 0
- drupal: 0
- liferay: 0
- sharepoint: 0
- moodle: 0

## Findings

Các finding được chia theo trạng thái `confirmed` hoặc `possible`. Confirmed nghĩa là có bằng chứng marker-based reflection/verification; possible nghĩa là dựa trên feedback/anomaly nhưng chưa có marker xác nhận.

### 1. Confirmed XSS (JavaScript Executed)
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Confirmed XSS (JavaScript Executed)
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_name_xss_trigger_probe_3c90db4f89%27%29%3E#/`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_name_xss_trigger_probe_3c90db4f89&#x27;)&gt;`
- Response: HTTP `200` / Length `4838` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!
- Marker: `cff_marker_name_xss_trigger_probe_3c90db4f89` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_name_xss_trigger_probe_3c90db4f89%27%29%3E#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4838`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_trigger_probe_3c90db4f89; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!

### 2. Confirmed XSS (JavaScript Executed)
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Confirmed XSS (JavaScript Executed)
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%27cff_marker_name_xss_trigger_probe_cd5f3329c9%27%29%3C%2Fscript%3E#/`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_name_xss_trigger_probe_cd5f3329c9&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4835` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!
- Marker: `cff_marker_name_xss_trigger_probe_cd5f3329c9` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%27cff_marker_name_xss_trigger_probe_cd5f3329c9%27%29%3C%2Fscript%3E#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4835`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_trigger_probe_cd5f3329c9; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!

### 3. Confirmed XSS (JavaScript Executed)
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Confirmed XSS (JavaScript Executed)
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_name_xss_trigger_probe_1a40e32992%27%29%3E`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_name_xss_trigger_probe_1a40e32992&#x27;)&gt;`
- Response: HTTP `200` / Length `4838` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!
- Marker: `cff_marker_name_xss_trigger_probe_1a40e32992` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_name_xss_trigger_probe_1a40e32992%27%29%3E` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4838`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_trigger_probe_1a40e32992; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!

### 4. Confirmed XSS (JavaScript Executed)
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Confirmed XSS (JavaScript Executed)
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Cscript%3Ealert%28%27cff_marker_name_xss_trigger_probe_c8877233d1%27%29%3C%2Fscript%3E`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_name_xss_trigger_probe_c8877233d1&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4835` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!
- Marker: `cff_marker_name_xss_trigger_probe_c8877233d1` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Cscript%3Ealert%28%27cff_marker_name_xss_trigger_probe_c8877233d1%27%29%3C%2Fscript%3E` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4835`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_trigger_probe_c8877233d1; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!

### 5. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%27_cff_marker_name_sqli_probe_1c1f3a1ac7#/`
- Parameter: `name` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_name_sqli_probe_1c1f3a1ac7`
- Response: HTTP `200` / Length `4804` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response; unique marker reflected: cff_marker_name_sqli_probe_1c1f3a1ac7
- Marker: `cff_marker_name_sqli_probe_1c1f3a1ac7` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%27_cff_marker_name_sqli_probe_1c1f3a1ac7#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4804`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_sqli_probe_1c1f3a1ac7; marker hits: 1; SQL-like error keyword appeared in response; unique marker reflected: cff_marker_name_sqli_probe_1c1f3a1ac7

### 6. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%27_cff_marker_name_sqli_probe_04e075d312`
- Parameter: `name` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_name_sqli_probe_04e075d312`
- Response: HTTP `200` / Length `4804` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response; unique marker reflected: cff_marker_name_sqli_probe_04e075d312
- Marker: `cff_marker_name_sqli_probe_04e075d312` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%27_cff_marker_name_sqli_probe_04e075d312` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4804`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_sqli_probe_04e075d312; marker hits: 1; SQL-like error keyword appeared in response; unique marker reflected: cff_marker_name_sqli_probe_04e075d312

### 7. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=cff_marker_name_text_canary_c8ffbffcb3#/`
- Parameter: `name` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_name_text_canary_c8ffbffcb3`
- Response: HTTP `200` / Length `4803` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: unique marker reflected: cff_marker_name_text_canary_c8ffbffcb3
- Marker: `cff_marker_name_text_canary_c8ffbffcb3` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=cff_marker_name_text_canary_c8ffbffcb3#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4803`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_text_canary_c8ffbffcb3; marker hits: 1; unique marker reflected: cff_marker_name_text_canary_c8ffbffcb3

### 8. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=cff_marker_name_text_canary_570143b5cb`
- Parameter: `name` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_name_text_canary_570143b5cb`
- Response: HTTP `200` / Length `4803` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: unique marker reflected: cff_marker_name_text_canary_570143b5cb
- Marker: `cff_marker_name_text_canary_570143b5cb` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=cff_marker_name_text_canary_570143b5cb` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4803`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_text_canary_570143b5cb; marker hits: 1; unique marker reflected: cff_marker_name_text_canary_570143b5cb

### 9. Unescaped Payload Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Unescaped Payload Reflection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Ccff_marker_name_xss_reflection_probe_f4039e0521%3E#/`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_name_xss_reflection_probe_f4039e0521&gt;`
- Response: HTTP `200` / Length `4814` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.
- Marker: `cff_marker_name_xss_reflection_probe_f4039e0521` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Ccff_marker_name_xss_reflection_probe_f4039e0521%3E#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4814`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_reflection_probe_f4039e0521; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.

### 10. Unescaped Payload Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Unescaped Payload Reflection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Ccff_marker_name_xss_reflection_probe_fc1e685133%3E`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_name_xss_reflection_probe_fc1e685133&gt;`
- Response: HTTP `200` / Length `4814` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.
- Marker: `cff_marker_name_xss_reflection_probe_fc1e685133` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Ccff_marker_name_xss_reflection_probe_fc1e685133%3E` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4814`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_reflection_probe_fc1e685133; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.

### 11. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;action=%27_cff_marker_action_sqli_probe_0a9a0ecb46#/`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_action_sqli_probe_0a9a0ecb46`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_action_sqli_probe_0a9a0ecb46` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 12. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=1%22_cff_marker_author_sqli_probe_0d57e2a489#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_0d57e2a489`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_0d57e2a489` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 13. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=1%27_cff_marker_author_sqli_probe_25743982c4#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_25743982c4`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_25743982c4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 14. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=1%22_cff_marker_cat_sqli_probe_713e2ca76e#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_713e2ca76e`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_713e2ca76e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 15. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=1%27_cff_marker_cat_sqli_probe_de00d95019#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_de00d95019`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_de00d95019` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 16. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=%27_cff_marker_log_sqli_probe_4c09580bc4#/`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_log_sqli_probe_4c09580bc4`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_log_sqli_probe_4c09580bc4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 17. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;nonce=%27_cff_marker_nonce_sqli_probe_98c75737b1#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_nonce_sqli_probe_98c75737b1`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_nonce_sqli_probe_98c75737b1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 18. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=1%22_cff_marker_p_sqli_probe_babd49d0e0#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_babd49d0e0`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_babd49d0e0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 19. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=1%27_cff_marker_p_sqli_probe_95cd04ad8a#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_95cd04ad8a`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_95cd04ad8a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 20. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=1%22_cff_marker_page_id_sqli_probe_1857a8d171#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_1857a8d171`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_1857a8d171` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 21. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=1%27_cff_marker_page_id_sqli_probe_6406388060#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_6406388060`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_6406388060` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 22. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;pwd=%27_cff_marker_pwd_sqli_probe_85e4ecf078#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_pwd_sqli_probe_85e4ecf078`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_pwd_sqli_probe_85e4ecf078` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 23. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=%27_cff_marker_s_sqli_probe_57fe752c7a#/`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_57fe752c7a`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_s_sqli_probe_57fe752c7a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 24. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=%27_cff_marker_search_sqli_probe_149ad66a25#/`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_149ad66a25`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_search_sqli_probe_149ad66a25` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 25. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?action=%27_cff_marker_action_sqli_probe_aeb674c92c`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_action_sqli_probe_aeb674c92c`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_action_sqli_probe_aeb674c92c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 26. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=1%22_cff_marker_author_sqli_probe_492fb6ea17`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_492fb6ea17`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_492fb6ea17` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 27. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=1%27_cff_marker_author_sqli_probe_eb47de78d3`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_eb47de78d3`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_eb47de78d3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 28. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=1%22_cff_marker_cat_sqli_probe_cb0ab3ea2b`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_cb0ab3ea2b`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_cb0ab3ea2b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 29. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=1%27_cff_marker_cat_sqli_probe_7a9427c98f`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_7a9427c98f`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_7a9427c98f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 30. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=%27_cff_marker_log_sqli_probe_cffc7de528`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_log_sqli_probe_cffc7de528`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_log_sqli_probe_cffc7de528` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 31. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?nonce=%27_cff_marker_nonce_sqli_probe_949382c45d`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_nonce_sqli_probe_949382c45d`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_nonce_sqli_probe_949382c45d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 32. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=1%22_cff_marker_p_sqli_probe_748c4636c9`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_748c4636c9`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_748c4636c9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 33. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=1%27_cff_marker_p_sqli_probe_c645c9858a`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_c645c9858a`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_c645c9858a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 34. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=1%22_cff_marker_page_id_sqli_probe_09fbee5d94`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_09fbee5d94`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_09fbee5d94` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 35. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=1%27_cff_marker_page_id_sqli_probe_2d6c8eca82`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_2d6c8eca82`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_2d6c8eca82` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 36. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?pwd=%27_cff_marker_pwd_sqli_probe_ac2105f16d`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_pwd_sqli_probe_ac2105f16d`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_pwd_sqli_probe_ac2105f16d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 37. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=%27_cff_marker_s_sqli_probe_793b590f4e`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_793b590f4e`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_s_sqli_probe_793b590f4e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 38. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=%27_cff_marker_search_sqli_probe_08a496cc5b`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_08a496cc5b`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_search_sqli_probe_08a496cc5b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 39. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;action=cff_marker_action_action_canary_a717035334#/`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_a717035334`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_action_canary_a717035334` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 40. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;action=invalid_action_cff_marker_action_text_canary_e34779b1fa#/`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action_cff_marker_action_text_canary_e34779b1fa`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_text_canary_e34779b1fa` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 41. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=-1_cff_marker_author_numeric_boundary_464b8d546d#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_464b8d546d`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_464b8d546d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 42. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=0_cff_marker_author_numeric_boundary_bd579a53b0#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_bd579a53b0`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_bd579a53b0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 43. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=1_cff_marker_author_numeric_boundary_82942bfcb0#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_82942bfcb0`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_82942bfcb0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 44. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=999999_cff_marker_author_numeric_boundary_4351958452#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_4351958452`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_4351958452` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 45. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=-1_cff_marker_cat_numeric_boundary_b2db083f9c#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_b2db083f9c`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_b2db083f9c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 46. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=0_cff_marker_cat_numeric_boundary_a575079755#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_a575079755`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_a575079755` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 47. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=1_cff_marker_cat_numeric_boundary_f641309d7a#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_f641309d7a`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_f641309d7a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 48. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=999999_cff_marker_cat_numeric_boundary_db3bb21fd9#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_db3bb21fd9`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_db3bb21fd9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 49. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=%3Ccff_marker_log_xss_reflection_probe_11a7b24fdb%3E#/`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_log_xss_reflection_probe_11a7b24fdb&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_11a7b24fdb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 50. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_log_xss_trigger_probe_b866ae636b%27%29%3E#/`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_log_xss_trigger_probe_b866ae636b&#x27;)&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_b866ae636b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 51. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=%3Cscript%3Ealert%28%27cff_marker_log_xss_trigger_probe_0e34f76623%27%29%3C%2Fscript%3E#/`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_log_xss_trigger_probe_0e34f76623&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_0e34f76623` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 52. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=cff_marker_log_text_canary_8eed5b674d#/`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_log_text_canary_8eed5b674d`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_text_canary_8eed5b674d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 53. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;nonce=12345_cff_marker_nonce_generic_number_d4f2e6fde6#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_nonce_generic_number_d4f2e6fde6`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_number_d4f2e6fde6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 54. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;nonce=cff_marker_nonce_generic_canary_9328af5c8f#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_nonce_generic_canary_9328af5c8f`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_canary_9328af5c8f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 55. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;nonce=true_cff_marker_nonce_generic_bool_56a3d93cc4#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_nonce_generic_bool_56a3d93cc4`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_bool_56a3d93cc4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 56. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=-1_cff_marker_p_numeric_boundary_3d19dc8ac8#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_3d19dc8ac8`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_3d19dc8ac8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 57. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=0_cff_marker_p_numeric_boundary_7c6a55f350#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_7c6a55f350`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_7c6a55f350` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 58. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=1_cff_marker_p_numeric_boundary_e599d58320#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_e599d58320`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_e599d58320` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 59. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=999999_cff_marker_p_numeric_boundary_1e8bea301f#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_1e8bea301f`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_1e8bea301f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 60. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=-1_cff_marker_page_id_numeric_boundary_e098d3fb84#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_e098d3fb84`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_e098d3fb84` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 61. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=0_cff_marker_page_id_numeric_boundary_febd0ebe78#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_febd0ebe78`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_febd0ebe78` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 62. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=1_cff_marker_page_id_numeric_boundary_fd2e5ad45f#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_fd2e5ad45f`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_fd2e5ad45f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 63. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=999999_cff_marker_page_id_numeric_boundary_13281ebb17#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_13281ebb17`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_13281ebb17` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 64. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;pwd=12345_cff_marker_pwd_generic_number_44d00745c1#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_pwd_generic_number_44d00745c1`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_number_44d00745c1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 65. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;pwd=cff_marker_pwd_generic_canary_f96a60b8ef#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_pwd_generic_canary_f96a60b8ef`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_canary_f96a60b8ef` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 66. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;pwd=true_cff_marker_pwd_generic_bool_0f8fa3d6de#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_pwd_generic_bool_0f8fa3d6de`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_bool_0f8fa3d6de` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 67. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_fc05ee63dd#/`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_to_redirect_probe_fc05ee63dd`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_fc05ee63dd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 68. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_2d7091a0a4#/`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_to_redirect_probe_2d7091a0a4`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_2d7091a0a4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 69. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=%3Ccff_marker_s_xss_reflection_probe_c4f8860f4b%3E#/`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_c4f8860f4b&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_c4f8860f4b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 70. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_s_xss_trigger_probe_6d7dc784cb%27%29%3E#/`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_s_xss_trigger_probe_6d7dc784cb&#x27;)&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_6d7dc784cb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 71. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=%3Cscript%3Ealert%28%27cff_marker_s_xss_trigger_probe_73f63a1076%27%29%3C%2Fscript%3E#/`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_s_xss_trigger_probe_73f63a1076&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_73f63a1076` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 72. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=cff_marker_s_text_canary_e68f05c85a#/`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_e68f05c85a`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_text_canary_e68f05c85a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 73. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=%3Ccff_marker_search_xss_reflection_probe_affe9d06cc%3E#/`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_affe9d06cc&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_affe9d06cc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 74. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_e67f773858%27%29%3E#/`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_e67f773858&#x27;)&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_e67f773858` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 75. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_9e1661a5f8%27%29%3C%2Fscript%3E#/`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_9e1661a5f8&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_9e1661a5f8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 76. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=cff_marker_search_text_canary_9e424fd9a6#/`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_9e424fd9a6`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_text_canary_9e424fd9a6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4769`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 77. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?action=cff_marker_action_action_canary_632b983906`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_632b983906`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_action_canary_632b983906` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 78. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?action=invalid_action_cff_marker_action_text_canary_f256236b35`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action_cff_marker_action_text_canary_f256236b35`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_text_canary_f256236b35` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 79. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=-1_cff_marker_author_numeric_boundary_f9d41093b6`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_f9d41093b6`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_f9d41093b6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 80. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=0_cff_marker_author_numeric_boundary_fbc0777db2`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_fbc0777db2`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_fbc0777db2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 81. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=1_cff_marker_author_numeric_boundary_b02db406ed`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_b02db406ed`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_b02db406ed` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 82. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=999999_cff_marker_author_numeric_boundary_f344a6d5a0`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_f344a6d5a0`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_f344a6d5a0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 83. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=-1_cff_marker_cat_numeric_boundary_098cdf5d36`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_098cdf5d36`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_098cdf5d36` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 84. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=0_cff_marker_cat_numeric_boundary_ef5eb4b5f7`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_ef5eb4b5f7`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_ef5eb4b5f7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 85. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=1_cff_marker_cat_numeric_boundary_0b7c2ba0a5`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_0b7c2ba0a5`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_0b7c2ba0a5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 86. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=999999_cff_marker_cat_numeric_boundary_a7fb9d037e`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_a7fb9d037e`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_a7fb9d037e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 87. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=%3Ccff_marker_log_xss_reflection_probe_cab6f6fd72%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_log_xss_reflection_probe_cab6f6fd72&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_cab6f6fd72` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 88. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_log_xss_trigger_probe_23fb7dad2d%27%29%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_log_xss_trigger_probe_23fb7dad2d&#x27;)&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_23fb7dad2d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 89. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=%3Cscript%3Ealert%28%27cff_marker_log_xss_trigger_probe_88ac16df74%27%29%3C%2Fscript%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_log_xss_trigger_probe_88ac16df74&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_88ac16df74` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 90. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=cff_marker_log_text_canary_de097cafd5`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_log_text_canary_de097cafd5`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_text_canary_de097cafd5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 91. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?nonce=12345_cff_marker_nonce_generic_number_83a39c752c`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_nonce_generic_number_83a39c752c`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_number_83a39c752c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 92. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?nonce=cff_marker_nonce_generic_canary_13d3e31ffd`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_nonce_generic_canary_13d3e31ffd`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_canary_13d3e31ffd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 93. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?nonce=true_cff_marker_nonce_generic_bool_f546a22ca7`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_nonce_generic_bool_f546a22ca7`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_bool_f546a22ca7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 94. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=-1_cff_marker_p_numeric_boundary_833ad0f6f1`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_833ad0f6f1`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_833ad0f6f1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 95. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=0_cff_marker_p_numeric_boundary_ab0fb62e4d`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_ab0fb62e4d`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_ab0fb62e4d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 96. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=1_cff_marker_p_numeric_boundary_7a01f60cd0`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_7a01f60cd0`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_7a01f60cd0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 97. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=999999_cff_marker_p_numeric_boundary_a8efc408ef`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_a8efc408ef`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_a8efc408ef` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 98. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=-1_cff_marker_page_id_numeric_boundary_b6bbc1d36a`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_b6bbc1d36a`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_b6bbc1d36a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 99. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=0_cff_marker_page_id_numeric_boundary_1c5d11292e`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_1c5d11292e`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_1c5d11292e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 100. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=1_cff_marker_page_id_numeric_boundary_b00378ed76`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_b00378ed76`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_b00378ed76` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 101. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=999999_cff_marker_page_id_numeric_boundary_6ce9af09e4`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_6ce9af09e4`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_6ce9af09e4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 102. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?pwd=12345_cff_marker_pwd_generic_number_79ffd254ee`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_pwd_generic_number_79ffd254ee`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_number_79ffd254ee` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 103. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?pwd=cff_marker_pwd_generic_canary_be0ce9ee28`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_pwd_generic_canary_be0ce9ee28`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_canary_be0ce9ee28` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 104. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?pwd=true_cff_marker_pwd_generic_bool_d3d0a2bdd9`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_pwd_generic_bool_d3d0a2bdd9`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_bool_d3d0a2bdd9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 105. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_4f95ad6e0a`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_to_redirect_probe_4f95ad6e0a`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_4f95ad6e0a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 106. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_e736c8724f`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_to_redirect_probe_e736c8724f`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_e736c8724f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 107. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=%3Ccff_marker_s_xss_reflection_probe_e91ed12729%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_e91ed12729&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_e91ed12729` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 108. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_s_xss_trigger_probe_b3bdcfc3f6%27%29%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_s_xss_trigger_probe_b3bdcfc3f6&#x27;)&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_b3bdcfc3f6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 109. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=%3Cscript%3Ealert%28%27cff_marker_s_xss_trigger_probe_90e39ea2ef%27%29%3C%2Fscript%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_s_xss_trigger_probe_90e39ea2ef&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_90e39ea2ef` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 110. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=cff_marker_s_text_canary_aca49b17ee`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_aca49b17ee`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_text_canary_aca49b17ee` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 111. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=%3Ccff_marker_search_xss_reflection_probe_fe0596b276%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_fe0596b276&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_fe0596b276` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 112. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_50ed35b20b%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_50ed35b20b&#x27;)&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_50ed35b20b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 113. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_ba8bb6d716%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_ba8bb6d716&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_ba8bb6d716` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 114. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=cff_marker_search_text_canary_3c1c72c366`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_3c1c72c366`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_text_canary_3c1c72c366` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 115. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta

