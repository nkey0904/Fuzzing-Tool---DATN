# Context Feedback Fuzzer Report

- Target: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test#/`
- Detected Platform: **wordpress**
- Platform type: `CMS`
- Scan status: `done`
- Requests sent: `2000`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_name_xss_trigger_probe_0922fbb1ca%27%29%3E#/`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_name_xss_trigger_probe_0922fbb1ca&#x27;)&gt;`
- Response: HTTP `200` / Length `4838` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!
- Marker: `cff_marker_name_xss_trigger_probe_0922fbb1ca` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_name_xss_trigger_probe_0922fbb1ca%27%29%3E#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4838`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_trigger_probe_0922fbb1ca; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!

### 2. Confirmed XSS (JavaScript Executed)
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Confirmed XSS (JavaScript Executed)
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%27cff_marker_name_xss_trigger_probe_a1f44b63e8%27%29%3C%2Fscript%3E#/`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_name_xss_trigger_probe_a1f44b63e8&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4835` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!
- Marker: `cff_marker_name_xss_trigger_probe_a1f44b63e8` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%27cff_marker_name_xss_trigger_probe_a1f44b63e8%27%29%3C%2Fscript%3E#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4835`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_trigger_probe_a1f44b63e8; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!

### 3. Confirmed XSS (JavaScript Executed)
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Confirmed XSS (JavaScript Executed)
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_name_xss_trigger_probe_e2e079056a%27%29%3E`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_name_xss_trigger_probe_e2e079056a&#x27;)&gt;`
- Response: HTTP `200` / Length `4838` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!
- Marker: `cff_marker_name_xss_trigger_probe_e2e079056a` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_name_xss_trigger_probe_e2e079056a%27%29%3E` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4838`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_trigger_probe_e2e079056a; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!

### 4. Confirmed XSS (JavaScript Executed)
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Confirmed XSS (JavaScript Executed)
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Cscript%3Ealert%28%27cff_marker_name_xss_trigger_probe_8381e0a4e0%27%29%3C%2Fscript%3E`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_name_xss_trigger_probe_8381e0a4e0&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4835` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!
- Marker: `cff_marker_name_xss_trigger_probe_8381e0a4e0` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Cscript%3Ealert%28%27cff_marker_name_xss_trigger_probe_8381e0a4e0%27%29%3C%2Fscript%3E` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4835`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_trigger_probe_8381e0a4e0; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.; SELENIUM VERIFIED: JavaScript alert() was successfully executed in the browser!

### 5. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%27_cff_marker_name_sqli_probe_97dd8ed219#/`
- Parameter: `name` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_name_sqli_probe_97dd8ed219`
- Response: HTTP `200` / Length `4804` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response; unique marker reflected: cff_marker_name_sqli_probe_97dd8ed219
- Marker: `cff_marker_name_sqli_probe_97dd8ed219` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%27_cff_marker_name_sqli_probe_97dd8ed219#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4804`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_sqli_probe_97dd8ed219; marker hits: 1; SQL-like error keyword appeared in response; unique marker reflected: cff_marker_name_sqli_probe_97dd8ed219

### 6. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%27_cff_marker_name_sqli_probe_0f568a3f38`
- Parameter: `name` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_name_sqli_probe_0f568a3f38`
- Response: HTTP `200` / Length `4804` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response; unique marker reflected: cff_marker_name_sqli_probe_0f568a3f38
- Marker: `cff_marker_name_sqli_probe_0f568a3f38` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%27_cff_marker_name_sqli_probe_0f568a3f38` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4804`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_sqli_probe_0f568a3f38; marker hits: 1; SQL-like error keyword appeared in response; unique marker reflected: cff_marker_name_sqli_probe_0f568a3f38

### 7. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=cff_marker_name_text_canary_9a709e6ecb#/`
- Parameter: `name` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_name_text_canary_9a709e6ecb`
- Response: HTTP `200` / Length `4803` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: unique marker reflected: cff_marker_name_text_canary_9a709e6ecb
- Marker: `cff_marker_name_text_canary_9a709e6ecb` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=cff_marker_name_text_canary_9a709e6ecb#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4803`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_text_canary_9a709e6ecb; marker hits: 1; unique marker reflected: cff_marker_name_text_canary_9a709e6ecb

### 8. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=cff_marker_name_text_canary_73d5b8cad0`
- Parameter: `name` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_name_text_canary_73d5b8cad0`
- Response: HTTP `200` / Length `4803` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: unique marker reflected: cff_marker_name_text_canary_73d5b8cad0
- Marker: `cff_marker_name_text_canary_73d5b8cad0` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=cff_marker_name_text_canary_73d5b8cad0` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4803`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_text_canary_73d5b8cad0; marker hits: 1; unique marker reflected: cff_marker_name_text_canary_73d5b8cad0

### 9. Unescaped Payload Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Unescaped Payload Reflection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Ccff_marker_name_xss_reflection_probe_a2fb4965c7%3E#/`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_name_xss_reflection_probe_a2fb4965c7&gt;`
- Response: HTTP `200` / Length `4814` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.
- Marker: `cff_marker_name_xss_reflection_probe_a2fb4965c7` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=%3Ccff_marker_name_xss_reflection_probe_a2fb4965c7%3E#/` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4814`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_reflection_probe_a2fb4965c7; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.

### 10. Unescaped Payload Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Unescaped Payload Reflection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Ccff_marker_name_xss_reflection_probe_2d0adb347d%3E`
- Parameter: `name` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_name_xss_reflection_probe_2d0adb347d&gt;`
- Response: HTTP `200` / Length `4814` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: Dangerous characters (&lt;, &quot;) survived encoding.
- Marker: `cff_marker_name_xss_reflection_probe_2d0adb347d` | Reflected: `True` | Hits: `1`
  - Hit: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?name=%3Ccff_marker_name_xss_reflection_probe_2d0adb347d%3E` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4814`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_name_xss_reflection_probe_2d0adb347d; marker hits: 1; Dangerous characters (&lt;, &quot;) survived encoding.

### 11. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;action=%27_cff_marker_action_sqli_probe_897d19f249#/`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_action_sqli_probe_897d19f249`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_action_sqli_probe_897d19f249` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=1%22_cff_marker_author_sqli_probe_445312d62a#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_445312d62a`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_445312d62a` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=1%27_cff_marker_author_sqli_probe_c3e44e7848#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_c3e44e7848`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_c3e44e7848` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=1%22_cff_marker_cat_sqli_probe_334850e5b4#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_334850e5b4`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_334850e5b4` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=1%27_cff_marker_cat_sqli_probe_45c51207b2#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_45c51207b2`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_45c51207b2` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=%27_cff_marker_log_sqli_probe_6d8ce782a8#/`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_log_sqli_probe_6d8ce782a8`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_log_sqli_probe_6d8ce782a8` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;nonce=%27_cff_marker_nonce_sqli_probe_a19f7ee89e#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_nonce_sqli_probe_a19f7ee89e`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_nonce_sqli_probe_a19f7ee89e` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=1%22_cff_marker_p_sqli_probe_be0a9c4eb7#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_be0a9c4eb7`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_be0a9c4eb7` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=1%27_cff_marker_p_sqli_probe_9fe4a56e0d#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_9fe4a56e0d`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_9fe4a56e0d` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=1%22_cff_marker_page_id_sqli_probe_c8ee647e56#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_c8ee647e56`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_c8ee647e56` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=1%27_cff_marker_page_id_sqli_probe_e013e7ad88#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_e013e7ad88`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_e013e7ad88` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;pwd=%27_cff_marker_pwd_sqli_probe_f1e6442656#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_pwd_sqli_probe_f1e6442656`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_pwd_sqli_probe_f1e6442656` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=%27_cff_marker_s_sqli_probe_cb718005e7#/`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_cb718005e7`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_s_sqli_probe_cb718005e7` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=%27_cff_marker_search_sqli_probe_269f0ed53b#/`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_269f0ed53b`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_search_sqli_probe_269f0ed53b` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?action=%27_cff_marker_action_sqli_probe_5124a0b997`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_action_sqli_probe_5124a0b997`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_action_sqli_probe_5124a0b997` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=1%22_cff_marker_author_sqli_probe_2c149ecfb3`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_2c149ecfb3`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_2c149ecfb3` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=1%27_cff_marker_author_sqli_probe_f8d15e66ee`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_f8d15e66ee`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_f8d15e66ee` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=1%22_cff_marker_cat_sqli_probe_15906d981e`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_15906d981e`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_15906d981e` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=1%27_cff_marker_cat_sqli_probe_8c9a1c0f6e`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_8c9a1c0f6e`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_8c9a1c0f6e` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=%27_cff_marker_log_sqli_probe_22301f761b`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_log_sqli_probe_22301f761b`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_log_sqli_probe_22301f761b` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?nonce=%27_cff_marker_nonce_sqli_probe_c7346d68a5`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_nonce_sqli_probe_c7346d68a5`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_nonce_sqli_probe_c7346d68a5` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=1%22_cff_marker_p_sqli_probe_e12948354a`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_e12948354a`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_e12948354a` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=1%27_cff_marker_p_sqli_probe_9d0ab3d2dc`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_9d0ab3d2dc`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_9d0ab3d2dc` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=1%22_cff_marker_page_id_sqli_probe_b975837bb2`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_b975837bb2`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_b975837bb2` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=1%27_cff_marker_page_id_sqli_probe_7a8ca622b4`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_7a8ca622b4`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_7a8ca622b4` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?pwd=%27_cff_marker_pwd_sqli_probe_eba6dec8f9`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_pwd_sqli_probe_eba6dec8f9`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_pwd_sqli_probe_eba6dec8f9` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=%27_cff_marker_s_sqli_probe_0a3713b0e7`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_0a3713b0e7`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_s_sqli_probe_0a3713b0e7` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=%27_cff_marker_search_sqli_probe_fce2adac96`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_fce2adac96`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_search_sqli_probe_fce2adac96` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;action=cff_marker_action_action_canary_29035bdca5#/`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_29035bdca5`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_action_canary_29035bdca5` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;action=invalid_action_cff_marker_action_text_canary_8b48b04565#/`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action_cff_marker_action_text_canary_8b48b04565`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_text_canary_8b48b04565` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=-1_cff_marker_author_numeric_boundary_d9348cf9d8#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_d9348cf9d8`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_d9348cf9d8` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=0_cff_marker_author_numeric_boundary_564bfda6a1#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_564bfda6a1`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_564bfda6a1` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=1_cff_marker_author_numeric_boundary_f5d400b741#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_f5d400b741`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_f5d400b741` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;author=999999_cff_marker_author_numeric_boundary_3024bd1271#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_3024bd1271`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_3024bd1271` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=-1_cff_marker_cat_numeric_boundary_f86458b156#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_f86458b156`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_f86458b156` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=0_cff_marker_cat_numeric_boundary_0813e6d415#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_0813e6d415`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_0813e6d415` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=1_cff_marker_cat_numeric_boundary_65a9ebb151#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_65a9ebb151`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_65a9ebb151` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;cat=999999_cff_marker_cat_numeric_boundary_8bb6e92e63#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_8bb6e92e63`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_8bb6e92e63` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=%3Ccff_marker_log_xss_reflection_probe_f79e4c3742%3E#/`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_log_xss_reflection_probe_f79e4c3742&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_f79e4c3742` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_log_xss_trigger_probe_373f7ae1a9%27%29%3E#/`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_log_xss_trigger_probe_373f7ae1a9&#x27;)&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_373f7ae1a9` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=%3Cscript%3Ealert%28%27cff_marker_log_xss_trigger_probe_2fe0ec7610%27%29%3C%2Fscript%3E#/`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_log_xss_trigger_probe_2fe0ec7610&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_2fe0ec7610` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;log=cff_marker_log_text_canary_1b7a844e21#/`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_log_text_canary_1b7a844e21`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_text_canary_1b7a844e21` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;nonce=12345_cff_marker_nonce_generic_number_781116d868#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_nonce_generic_number_781116d868`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_number_781116d868` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;nonce=cff_marker_nonce_generic_canary_f30fb4b08c#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_nonce_generic_canary_f30fb4b08c`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_canary_f30fb4b08c` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;nonce=true_cff_marker_nonce_generic_bool_7991708cc7#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_nonce_generic_bool_7991708cc7`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_bool_7991708cc7` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=-1_cff_marker_p_numeric_boundary_fc3947958c#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_fc3947958c`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_fc3947958c` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=0_cff_marker_p_numeric_boundary_1b7dfa6e37#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_1b7dfa6e37`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_1b7dfa6e37` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=1_cff_marker_p_numeric_boundary_f7ef2d1620#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_f7ef2d1620`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_f7ef2d1620` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;p=999999_cff_marker_p_numeric_boundary_e70fdd81e0#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_e70fdd81e0`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_e70fdd81e0` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=-1_cff_marker_page_id_numeric_boundary_6b93438b94#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_6b93438b94`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_6b93438b94` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=0_cff_marker_page_id_numeric_boundary_5494070434#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_5494070434`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_5494070434` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=1_cff_marker_page_id_numeric_boundary_77dd08b7a0#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_77dd08b7a0`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_77dd08b7a0` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;page_id=999999_cff_marker_page_id_numeric_boundary_e4cc52b76f#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_e4cc52b76f`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_e4cc52b76f` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;pwd=12345_cff_marker_pwd_generic_number_bf45941da3#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_pwd_generic_number_bf45941da3`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_number_bf45941da3` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;pwd=cff_marker_pwd_generic_canary_b340f2afe8#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_pwd_generic_canary_b340f2afe8`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_canary_b340f2afe8` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;pwd=true_cff_marker_pwd_generic_bool_ace9710ff3#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_pwd_generic_bool_ace9710ff3`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_bool_ace9710ff3` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_357252af59#/`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_to_redirect_probe_357252af59`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_357252af59` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_3cd2c0bb63#/`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_to_redirect_probe_3cd2c0bb63`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_3cd2c0bb63` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=%3Ccff_marker_s_xss_reflection_probe_a3f9ed9545%3E#/`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_a3f9ed9545&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_a3f9ed9545` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_s_xss_trigger_probe_6118437f4a%27%29%3E#/`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_s_xss_trigger_probe_6118437f4a&#x27;)&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_6118437f4a` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=%3Cscript%3Ealert%28%27cff_marker_s_xss_trigger_probe_8d18cc4282%27%29%3C%2Fscript%3E#/`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_s_xss_trigger_probe_8d18cc4282&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_8d18cc4282` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;s=cff_marker_s_text_canary_043dfecff2#/`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_043dfecff2`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_text_canary_043dfecff2` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=%3Ccff_marker_search_xss_reflection_probe_e32b42625f%3E#/`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_e32b42625f&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_e32b42625f` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_aec4eb53e3%27%29%3E#/`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_aec4eb53e3&#x27;)&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_aec4eb53e3` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_7de559054c%27%29%3C%2Fscript%3E#/`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_7de559054c&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_7de559054c` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/?name=test&amp;search=cff_marker_search_text_canary_68e5e051a2#/`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_68e5e051a2`
- Response: HTTP `200` / Length `4769` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_text_canary_68e5e051a2` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?action=cff_marker_action_action_canary_4574cf31a8`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_4574cf31a8`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_action_canary_4574cf31a8` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?action=invalid_action_cff_marker_action_text_canary_4190dde2b7`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action_cff_marker_action_text_canary_4190dde2b7`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_text_canary_4190dde2b7` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=-1_cff_marker_author_numeric_boundary_bac5981b59`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_bac5981b59`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_bac5981b59` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=0_cff_marker_author_numeric_boundary_f58f4f4ea0`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_f58f4f4ea0`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_f58f4f4ea0` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=1_cff_marker_author_numeric_boundary_26d828b6ec`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_26d828b6ec`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_26d828b6ec` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?author=999999_cff_marker_author_numeric_boundary_fbf7ed57cb`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_fbf7ed57cb`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_fbf7ed57cb` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=-1_cff_marker_cat_numeric_boundary_658aa56dcb`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_658aa56dcb`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_658aa56dcb` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=0_cff_marker_cat_numeric_boundary_06babd6ff4`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_06babd6ff4`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_06babd6ff4` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=1_cff_marker_cat_numeric_boundary_38461e4bb0`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_38461e4bb0`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_38461e4bb0` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?cat=999999_cff_marker_cat_numeric_boundary_8a0614eaad`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_8a0614eaad`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_8a0614eaad` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=%3Ccff_marker_log_xss_reflection_probe_8b8dd509af%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_log_xss_reflection_probe_8b8dd509af&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_8b8dd509af` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_log_xss_trigger_probe_934fda83b1%27%29%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_log_xss_trigger_probe_934fda83b1&#x27;)&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_934fda83b1` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=%3Cscript%3Ealert%28%27cff_marker_log_xss_trigger_probe_84bb547ee8%27%29%3C%2Fscript%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_log_xss_trigger_probe_84bb547ee8&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_84bb547ee8` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?log=cff_marker_log_text_canary_404c38423b`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_log_text_canary_404c38423b`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_text_canary_404c38423b` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?nonce=12345_cff_marker_nonce_generic_number_b0fecbbfb2`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_nonce_generic_number_b0fecbbfb2`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_number_b0fecbbfb2` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?nonce=cff_marker_nonce_generic_canary_31b211adae`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_nonce_generic_canary_31b211adae`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_canary_31b211adae` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?nonce=true_cff_marker_nonce_generic_bool_6ebabdb1fa`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_nonce_generic_bool_6ebabdb1fa`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_bool_6ebabdb1fa` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=-1_cff_marker_p_numeric_boundary_d308fc45bb`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_d308fc45bb`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_d308fc45bb` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=0_cff_marker_p_numeric_boundary_8fa867b338`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_8fa867b338`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_8fa867b338` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=1_cff_marker_p_numeric_boundary_5692b7de55`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_5692b7de55`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_5692b7de55` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?p=999999_cff_marker_p_numeric_boundary_e74a6de386`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_e74a6de386`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_e74a6de386` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=-1_cff_marker_page_id_numeric_boundary_ea1f93f761`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_ea1f93f761`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_ea1f93f761` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=0_cff_marker_page_id_numeric_boundary_849f094ad3`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_849f094ad3`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_849f094ad3` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=1_cff_marker_page_id_numeric_boundary_782717f661`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_782717f661`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_782717f661` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?page_id=999999_cff_marker_page_id_numeric_boundary_502ef8e134`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_502ef8e134`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_502ef8e134` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?pwd=12345_cff_marker_pwd_generic_number_96e5e33ed8`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_pwd_generic_number_96e5e33ed8`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_number_96e5e33ed8` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?pwd=cff_marker_pwd_generic_canary_4d49a08f57`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_pwd_generic_canary_4d49a08f57`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_canary_4d49a08f57` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?pwd=true_cff_marker_pwd_generic_bool_624e6ba358`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_pwd_generic_bool_624e6ba358`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_bool_624e6ba358` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_cdbe5a086c`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_to_redirect_probe_cdbe5a086c`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_cdbe5a086c` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_6d4e2c3dcd`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_to_redirect_probe_6d4e2c3dcd`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_6d4e2c3dcd` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=%3Ccff_marker_s_xss_reflection_probe_014ad2cdad%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_014ad2cdad&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_014ad2cdad` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_s_xss_trigger_probe_9df2aec1b6%27%29%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_s_xss_trigger_probe_9df2aec1b6&#x27;)&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_9df2aec1b6` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=%3Cscript%3Ealert%28%27cff_marker_s_xss_trigger_probe_4839cc4c6c%27%29%3C%2Fscript%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_s_xss_trigger_probe_4839cc4c6c&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_4839cc4c6c` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?s=cff_marker_s_text_canary_2ccfd9172e`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_2ccfd9172e`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_text_canary_2ccfd9172e` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=%3Ccff_marker_search_xss_reflection_probe_e0b4f4cfb0%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_e0b4f4cfb0&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_e0b4f4cfb0` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_b420d0eb25%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_b420d0eb25&#x27;)&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_b420d0eb25` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_44c575c5a2%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_44c575c5a2&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_44c575c5a2` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.7/DVWA/vulnerabilities/xss_r/index.php?search=cff_marker_search_text_canary_9c865c5778`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_9c865c5778`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_text_canary_9c865c5778` | Reflected: `False` | Hits: `0`
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

