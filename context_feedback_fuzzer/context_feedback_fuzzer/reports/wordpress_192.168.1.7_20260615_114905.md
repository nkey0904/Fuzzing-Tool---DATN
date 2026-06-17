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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_name_xss_trigger_probe_1f2dfb375e%27%29%3E#/`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_name_xss_trigger_probe_1f2dfb375e&#x27;)&gt;`
- Response: HTTP `200` / Length `4838` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!
- Marker: `cff_marker_name_xss_trigger_probe_1f2dfb375e` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_name_xss_trigger_probe_1f2dfb375e%27%29%3E#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4838`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_trigger_probe_1f2dfb375e; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!

### 2. Confirmed XSS (JavaScript Executed)
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Confirmed XSS (JavaScript Executed)
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%27cff_marker_name_xss_trigger_probe_d23ce28140%27%29%3C%2Fscript%3E#/`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_name_xss_trigger_probe_d23ce28140&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4835` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!
- Marker: `cff_marker_name_xss_trigger_probe_d23ce28140` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%27cff_marker_name_xss_trigger_probe_d23ce28140%27%29%3C%2Fscript%3E#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4835`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_trigger_probe_d23ce28140; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!

### 3. Confirmed XSS (JavaScript Executed)
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Confirmed XSS (JavaScript Executed)
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_name_xss_trigger_probe_55c9705108%27%29%3E`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_name_xss_trigger_probe_55c9705108&#x27;)&gt;`
- Response: HTTP `200` / Length `4838` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!
- Marker: `cff_marker_name_xss_trigger_probe_55c9705108` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_name_xss_trigger_probe_55c9705108%27%29%3E` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4838`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_trigger_probe_55c9705108; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!

### 4. Confirmed XSS (JavaScript Executed)
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Confirmed XSS (JavaScript Executed)
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Cscript%3Ealert%28%27cff_marker_name_xss_trigger_probe_9e1d841c64%27%29%3C%2Fscript%3E`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_name_xss_trigger_probe_9e1d841c64&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4835` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!
- Marker: `cff_marker_name_xss_trigger_probe_9e1d841c64` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Cscript%3Ealert%28%27cff_marker_name_xss_trigger_probe_9e1d841c64%27%29%3C%2Fscript%3E` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4835`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_trigger_probe_9e1d841c64; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!

### 5. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%27_cff_marker_name_sqli_probe_e7e8a4221b#/`
- Parameter: `name` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_name_sqli_probe_e7e8a4221b`
- Response: HTTP `200` / Length `4804` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response; unique marker reflected: cff_marker_name_sqli_probe_e7e8a4221b
- Marker: `cff_marker_name_sqli_probe_e7e8a4221b` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%27_cff_marker_name_sqli_probe_e7e8a4221b#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4804`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_sqli_probe_e7e8a4221b; marker hits: 1; SQL-like error keyword appeared in response; unique marker reflected: cff_marker_name_sqli_probe_e7e8a4221b

### 6. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%27_cff_marker_name_sqli_probe_74c0ed9b5e`
- Parameter: `name` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_name_sqli_probe_74c0ed9b5e`
- Response: HTTP `200` / Length `4804` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response; unique marker reflected: cff_marker_name_sqli_probe_74c0ed9b5e
- Marker: `cff_marker_name_sqli_probe_74c0ed9b5e` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%27_cff_marker_name_sqli_probe_74c0ed9b5e` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4804`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_sqli_probe_74c0ed9b5e; marker hits: 1; SQL-like error keyword appeared in response; unique marker reflected: cff_marker_name_sqli_probe_74c0ed9b5e

### 7. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=cff_marker_name_text_canary_372204a3ca#/`
- Parameter: `name` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_name_text_canary_372204a3ca`
- Response: HTTP `200` / Length `4803` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: unique marker reflected: cff_marker_name_text_canary_372204a3ca
- Marker: `cff_marker_name_text_canary_372204a3ca` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=cff_marker_name_text_canary_372204a3ca#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4803`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_text_canary_372204a3ca; marker hits: 1; unique marker reflected: cff_marker_name_text_canary_372204a3ca

### 8. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=cff_marker_name_text_canary_f65dacd76c`
- Parameter: `name` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_name_text_canary_f65dacd76c`
- Response: HTTP `200` / Length `4803` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: unique marker reflected: cff_marker_name_text_canary_f65dacd76c
- Marker: `cff_marker_name_text_canary_f65dacd76c` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=cff_marker_name_text_canary_f65dacd76c` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4803`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_text_canary_f65dacd76c; marker hits: 1; unique marker reflected: cff_marker_name_text_canary_f65dacd76c

### 9. Unescaped Payload Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Unescaped Payload Reflection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Ccff_marker_name_xss_reflection_probe_b49c8fd84d%3E#/`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_name_xss_reflection_probe_b49c8fd84d&gt;`
- Response: HTTP `200` / Length `4814` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.
- Marker: `cff_marker_name_xss_reflection_probe_b49c8fd84d` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Ccff_marker_name_xss_reflection_probe_b49c8fd84d%3E#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4814`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_reflection_probe_b49c8fd84d; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.

### 10. Unescaped Payload Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Unescaped Payload Reflection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Ccff_marker_name_xss_reflection_probe_b66d12eae5%3E`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_name_xss_reflection_probe_b66d12eae5&gt;`
- Response: HTTP `200` / Length `4814` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.
- Marker: `cff_marker_name_xss_reflection_probe_b66d12eae5` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Ccff_marker_name_xss_reflection_probe_b66d12eae5%3E` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4814`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_reflection_probe_b66d12eae5; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.

### 11. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;action=%27_cff_marker_action_sqli_probe_5c84b75131#/`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_action_sqli_probe_5c84b75131`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_action_sqli_probe_5c84b75131` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=1%22_cff_marker_author_sqli_probe_b99b5e1224#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_b99b5e1224`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_b99b5e1224` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=1%27_cff_marker_author_sqli_probe_6ddbf1bdae#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_6ddbf1bdae`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_6ddbf1bdae` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=1%22_cff_marker_cat_sqli_probe_9557857a45#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_9557857a45`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_9557857a45` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=1%27_cff_marker_cat_sqli_probe_0f0ea47e87#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_0f0ea47e87`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_0f0ea47e87` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=%27_cff_marker_log_sqli_probe_348ec034b9#/`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_log_sqli_probe_348ec034b9`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_log_sqli_probe_348ec034b9` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;nonce=%27_cff_marker_nonce_sqli_probe_191c6ac170#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_nonce_sqli_probe_191c6ac170`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_nonce_sqli_probe_191c6ac170` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=1%22_cff_marker_p_sqli_probe_47b6fa1ecd#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_47b6fa1ecd`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_47b6fa1ecd` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=1%27_cff_marker_p_sqli_probe_7f43deaa0a#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_7f43deaa0a`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_7f43deaa0a` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=1%22_cff_marker_page_id_sqli_probe_60f36141f2#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_60f36141f2`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_60f36141f2` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=1%27_cff_marker_page_id_sqli_probe_8da536a1e4#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_8da536a1e4`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_8da536a1e4` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;pwd=%27_cff_marker_pwd_sqli_probe_0b0c567d71#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_pwd_sqli_probe_0b0c567d71`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_pwd_sqli_probe_0b0c567d71` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=%27_cff_marker_s_sqli_probe_7464233571#/`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_7464233571`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_s_sqli_probe_7464233571` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=%27_cff_marker_search_sqli_probe_84b0f49ae0#/`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_84b0f49ae0`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_search_sqli_probe_84b0f49ae0` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?action=%27_cff_marker_action_sqli_probe_56830dfd53`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_action_sqli_probe_56830dfd53`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_action_sqli_probe_56830dfd53` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=1%22_cff_marker_author_sqli_probe_0fe59f8bec`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_0fe59f8bec`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_0fe59f8bec` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=1%27_cff_marker_author_sqli_probe_97266c83b0`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_97266c83b0`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_97266c83b0` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=1%22_cff_marker_cat_sqli_probe_0443a394a8`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_0443a394a8`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_0443a394a8` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=1%27_cff_marker_cat_sqli_probe_9fee7f523e`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_9fee7f523e`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_9fee7f523e` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=%27_cff_marker_log_sqli_probe_b5fabea5d8`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_log_sqli_probe_b5fabea5d8`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_log_sqli_probe_b5fabea5d8` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?nonce=%27_cff_marker_nonce_sqli_probe_63a968faaf`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_nonce_sqli_probe_63a968faaf`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_nonce_sqli_probe_63a968faaf` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=1%22_cff_marker_p_sqli_probe_8206815f8f`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_8206815f8f`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_8206815f8f` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=1%27_cff_marker_p_sqli_probe_b1b989dd0c`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_b1b989dd0c`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_b1b989dd0c` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=1%22_cff_marker_page_id_sqli_probe_bfdb01d10d`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_bfdb01d10d`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_bfdb01d10d` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=1%27_cff_marker_page_id_sqli_probe_1c2b01772a`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_1c2b01772a`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_1c2b01772a` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?pwd=%27_cff_marker_pwd_sqli_probe_03594d8e99`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_pwd_sqli_probe_03594d8e99`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_pwd_sqli_probe_03594d8e99` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=%27_cff_marker_s_sqli_probe_2e575f525d`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_2e575f525d`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_s_sqli_probe_2e575f525d` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=%27_cff_marker_search_sqli_probe_899314dd6d`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_899314dd6d`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_search_sqli_probe_899314dd6d` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;action=cff_marker_action_action_canary_46d54a316d#/`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_46d54a316d`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_action_canary_46d54a316d` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;action=invalid_action_cff_marker_action_text_canary_14e57ebfbf#/`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action_cff_marker_action_text_canary_14e57ebfbf`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_text_canary_14e57ebfbf` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=-1_cff_marker_author_numeric_boundary_254e43c43a#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_254e43c43a`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_254e43c43a` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=0_cff_marker_author_numeric_boundary_cf2455e93c#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_cf2455e93c`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_cf2455e93c` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=1_cff_marker_author_numeric_boundary_1a17cf6f64#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_1a17cf6f64`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_1a17cf6f64` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=999999_cff_marker_author_numeric_boundary_f43d20f2cc#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_f43d20f2cc`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_f43d20f2cc` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=-1_cff_marker_cat_numeric_boundary_8e68da9f66#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_8e68da9f66`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_8e68da9f66` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=0_cff_marker_cat_numeric_boundary_79f48b9d55#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_79f48b9d55`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_79f48b9d55` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=1_cff_marker_cat_numeric_boundary_6dc05b2566#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_6dc05b2566`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_6dc05b2566` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=999999_cff_marker_cat_numeric_boundary_e83753442f#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_e83753442f`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_e83753442f` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=%3Ccff_marker_log_xss_reflection_probe_5bf1486bc0%3E#/`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_log_xss_reflection_probe_5bf1486bc0&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_5bf1486bc0` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_log_xss_trigger_probe_a4fa8c684c%27%29%3E#/`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_log_xss_trigger_probe_a4fa8c684c&#x27;)&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_a4fa8c684c` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=%3Cscript%3Ealert%28%27cff_marker_log_xss_trigger_probe_7939eca6ab%27%29%3C%2Fscript%3E#/`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_log_xss_trigger_probe_7939eca6ab&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_7939eca6ab` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=cff_marker_log_text_canary_598d06b7c2#/`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_log_text_canary_598d06b7c2`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_text_canary_598d06b7c2` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;nonce=12345_cff_marker_nonce_generic_number_288ed25b0c#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_nonce_generic_number_288ed25b0c`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_number_288ed25b0c` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;nonce=cff_marker_nonce_generic_canary_18efde517a#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_nonce_generic_canary_18efde517a`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_canary_18efde517a` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;nonce=true_cff_marker_nonce_generic_bool_66211c11f6#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_nonce_generic_bool_66211c11f6`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_bool_66211c11f6` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=-1_cff_marker_p_numeric_boundary_dbedc85a3c#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_dbedc85a3c`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_dbedc85a3c` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=0_cff_marker_p_numeric_boundary_66989c1235#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_66989c1235`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_66989c1235` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=1_cff_marker_p_numeric_boundary_5cb98c8236#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_5cb98c8236`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_5cb98c8236` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=999999_cff_marker_p_numeric_boundary_9d79a2a25c#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_9d79a2a25c`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_9d79a2a25c` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=-1_cff_marker_page_id_numeric_boundary_d9d2026ee8#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_d9d2026ee8`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_d9d2026ee8` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=0_cff_marker_page_id_numeric_boundary_8fa9e311f8#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_8fa9e311f8`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_8fa9e311f8` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=1_cff_marker_page_id_numeric_boundary_b9130dee10#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_b9130dee10`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_b9130dee10` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=999999_cff_marker_page_id_numeric_boundary_1cf50ec5e5#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_1cf50ec5e5`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_1cf50ec5e5` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;pwd=12345_cff_marker_pwd_generic_number_d301bc6174#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_pwd_generic_number_d301bc6174`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_number_d301bc6174` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;pwd=cff_marker_pwd_generic_canary_22a5043e78#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_pwd_generic_canary_22a5043e78`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_canary_22a5043e78` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;pwd=true_cff_marker_pwd_generic_bool_2d2804e67e#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_pwd_generic_bool_2d2804e67e`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_bool_2d2804e67e` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_c37c71185f#/`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_to_redirect_probe_c37c71185f`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_c37c71185f` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_cfba820b88#/`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_to_redirect_probe_cfba820b88`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_cfba820b88` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=%3Ccff_marker_s_xss_reflection_probe_c104876cbf%3E#/`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_c104876cbf&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_c104876cbf` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_s_xss_trigger_probe_ddbcc87cca%27%29%3E#/`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_s_xss_trigger_probe_ddbcc87cca&#x27;)&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_ddbcc87cca` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=%3Cscript%3Ealert%28%27cff_marker_s_xss_trigger_probe_5fec2dc9c2%27%29%3C%2Fscript%3E#/`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_s_xss_trigger_probe_5fec2dc9c2&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_5fec2dc9c2` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=cff_marker_s_text_canary_5d920e3f67#/`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_5d920e3f67`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_text_canary_5d920e3f67` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=%3Ccff_marker_search_xss_reflection_probe_caef061400%3E#/`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_caef061400&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_caef061400` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_2688dc3b09%27%29%3E#/`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_2688dc3b09&#x27;)&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_2688dc3b09` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_fcc9a98dd2%27%29%3C%2Fscript%3E#/`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_fcc9a98dd2&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_fcc9a98dd2` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=cff_marker_search_text_canary_822e56df16#/`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_822e56df16`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_text_canary_822e56df16` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?action=cff_marker_action_action_canary_66be11637e`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_66be11637e`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_action_canary_66be11637e` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?action=invalid_action_cff_marker_action_text_canary_880df751ef`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action_cff_marker_action_text_canary_880df751ef`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_text_canary_880df751ef` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=-1_cff_marker_author_numeric_boundary_7fed7172f1`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_7fed7172f1`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_7fed7172f1` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=0_cff_marker_author_numeric_boundary_33dec70359`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_33dec70359`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_33dec70359` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=1_cff_marker_author_numeric_boundary_19592e570c`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_19592e570c`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_19592e570c` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=999999_cff_marker_author_numeric_boundary_258e5acec5`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_258e5acec5`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_258e5acec5` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=-1_cff_marker_cat_numeric_boundary_cbe0cd82f4`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_cbe0cd82f4`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_cbe0cd82f4` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=0_cff_marker_cat_numeric_boundary_89f3c21c5f`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_89f3c21c5f`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_89f3c21c5f` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=1_cff_marker_cat_numeric_boundary_f56bf2b033`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_f56bf2b033`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_f56bf2b033` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=999999_cff_marker_cat_numeric_boundary_af77266f8b`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_af77266f8b`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_af77266f8b` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=%3Ccff_marker_log_xss_reflection_probe_a84c78e7d4%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_log_xss_reflection_probe_a84c78e7d4&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_a84c78e7d4` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_log_xss_trigger_probe_4463280040%27%29%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_log_xss_trigger_probe_4463280040&#x27;)&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_4463280040` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=%3Cscript%3Ealert%28%27cff_marker_log_xss_trigger_probe_17e7d46451%27%29%3C%2Fscript%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_log_xss_trigger_probe_17e7d46451&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_17e7d46451` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=cff_marker_log_text_canary_7fdb820b46`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_log_text_canary_7fdb820b46`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_text_canary_7fdb820b46` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?nonce=12345_cff_marker_nonce_generic_number_b614b485e8`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_nonce_generic_number_b614b485e8`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_number_b614b485e8` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?nonce=cff_marker_nonce_generic_canary_6114473bfa`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_nonce_generic_canary_6114473bfa`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_canary_6114473bfa` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?nonce=true_cff_marker_nonce_generic_bool_10e5d3591c`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_nonce_generic_bool_10e5d3591c`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_bool_10e5d3591c` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=-1_cff_marker_p_numeric_boundary_fad185b954`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_fad185b954`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_fad185b954` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=0_cff_marker_p_numeric_boundary_9f13c3edc4`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_9f13c3edc4`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_9f13c3edc4` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=1_cff_marker_p_numeric_boundary_3236fa3858`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_3236fa3858`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_3236fa3858` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=999999_cff_marker_p_numeric_boundary_3987f71e0f`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_3987f71e0f`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_3987f71e0f` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=-1_cff_marker_page_id_numeric_boundary_77958eb587`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_77958eb587`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_77958eb587` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=0_cff_marker_page_id_numeric_boundary_ae062b3482`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_ae062b3482`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_ae062b3482` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=1_cff_marker_page_id_numeric_boundary_223c5056a7`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_223c5056a7`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_223c5056a7` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=999999_cff_marker_page_id_numeric_boundary_71dc159abe`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_71dc159abe`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_71dc159abe` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?pwd=12345_cff_marker_pwd_generic_number_39a2863c35`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_pwd_generic_number_39a2863c35`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_number_39a2863c35` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?pwd=cff_marker_pwd_generic_canary_3c12d0cbd9`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_pwd_generic_canary_3c12d0cbd9`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_canary_3c12d0cbd9` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?pwd=true_cff_marker_pwd_generic_bool_cba10bc5f6`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_pwd_generic_bool_cba10bc5f6`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_bool_cba10bc5f6` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_436d09ac49`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_to_redirect_probe_436d09ac49`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_436d09ac49` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_e8b2519b22`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_to_redirect_probe_e8b2519b22`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_e8b2519b22` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=%3Ccff_marker_s_xss_reflection_probe_4641a2871e%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_4641a2871e&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_4641a2871e` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_s_xss_trigger_probe_18f7eff97b%27%29%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_s_xss_trigger_probe_18f7eff97b&#x27;)&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_18f7eff97b` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=%3Cscript%3Ealert%28%27cff_marker_s_xss_trigger_probe_429531419b%27%29%3C%2Fscript%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_s_xss_trigger_probe_429531419b&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_429531419b` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=cff_marker_s_text_canary_0cfe6b24de`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_0cfe6b24de`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_text_canary_0cfe6b24de` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=%3Ccff_marker_search_xss_reflection_probe_db12bf96af%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_db12bf96af&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_db12bf96af` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_dbc0c1ffad%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_dbc0c1ffad&#x27;)&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_dbc0c1ffad` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_723ba11bc5%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_723ba11bc5&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_723ba11bc5` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=cff_marker_search_text_canary_d23815ed97`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_d23815ed97`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_text_canary_d23815ed97` | Reflected: `False` | Hits: `0`
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

