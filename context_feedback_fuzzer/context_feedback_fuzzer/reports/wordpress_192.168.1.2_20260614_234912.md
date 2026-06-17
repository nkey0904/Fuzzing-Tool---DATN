# Context Feedback Fuzzer Report

- Target: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/`
- Detected Platform: **wordpress**
- Platform type: `CMS`
- Scan status: `done`
- Requests sent: `400`
- Safety: GET-only, same-host scope, rate-limited, authorization flag required.
- Server technology hint: `php` / `apache`
- Confirmed findings: `0`
- Possible findings: `88`
- Confirmation rate: `0.0%`
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

- Payload strategy examples:
  - `p` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `page_id` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `cat` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `search` => `text_canary, xss_reflection_probe, xss_reflection_probe, xss_reflection_probe, sqli_probe`
  - `s` => `text_canary, xss_reflection_probe, xss_reflection_probe, xss_reflection_probe, sqli_probe`
  - `author` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `action` => `action_canary, text_canary, sqli_probe`
  - `nonce` => `generic_canary, generic_bool, generic_number, sqli_probe`
  - `redirect_to` => `redirect_probe, redirect_probe`
  - `log` => `text_canary, xss_reflection_probe, xss_reflection_probe, xss_reflection_probe, sqli_probe`
  - `pwd` => `generic_canary, generic_bool, generic_number, sqli_probe`

## Marker verification mechanism

Marker-based fuzzing gắn marker duy nhất vào từng payload. Sau fuzzing, verification engine crawl các link cùng host và kiểm tra marker có xuất hiện lại không. Nếu có bằng chứng marker, finding được phân loại là confirmed.

- Markers generated: `104`
- Markers verified: `0`
- Markers failed: `104`
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

### 1. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?action=%27_cff_marker_action_sqli_probe_212012ba23`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_action_sqli_probe_212012ba23`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_action_sqli_probe_212012ba23` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 2. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?author=1%22_cff_marker_author_sqli_probe_cbff406005`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_cbff406005`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_cbff406005` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 3. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?author=1%27_cff_marker_author_sqli_probe_a25c7ab6a5`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_a25c7ab6a5`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_a25c7ab6a5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 4. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?cat=1%22_cff_marker_cat_sqli_probe_c75976451f`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_c75976451f`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_c75976451f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 5. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?cat=1%27_cff_marker_cat_sqli_probe_c007c7a4d7`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_c007c7a4d7`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_c007c7a4d7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 6. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?log=%27_cff_marker_log_sqli_probe_9454498626`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_log_sqli_probe_9454498626`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_log_sqli_probe_9454498626` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 7. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?nonce=%27_cff_marker_nonce_sqli_probe_6e870e2e81`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_nonce_sqli_probe_6e870e2e81`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_nonce_sqli_probe_6e870e2e81` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 8. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?p=1%22_cff_marker_p_sqli_probe_5d7c6cf725`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_5d7c6cf725`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_5d7c6cf725` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 9. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?p=1%27_cff_marker_p_sqli_probe_1cb3007756`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_1cb3007756`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_1cb3007756` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 10. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?page_id=1%22_cff_marker_page_id_sqli_probe_0665da0709`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_0665da0709`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_0665da0709` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 11. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?page_id=1%27_cff_marker_page_id_sqli_probe_31459638d8`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_31459638d8`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_31459638d8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 12. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?pwd=%27_cff_marker_pwd_sqli_probe_7ea8d2208b`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_pwd_sqli_probe_7ea8d2208b`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_pwd_sqli_probe_7ea8d2208b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 13. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?s=%27_cff_marker_s_sqli_probe_d84978405b`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_d84978405b`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_s_sqli_probe_d84978405b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 14. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?search=%27_cff_marker_search_sqli_probe_4162da2e9b`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_4162da2e9b`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_search_sqli_probe_4162da2e9b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 15. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?author=1%22_cff_marker_author_sqli_probe_04437ec676`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_04437ec676`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_04437ec676` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 16. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?author=1%27_cff_marker_author_sqli_probe_d9a692859b`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_d9a692859b`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_d9a692859b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 17. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?cat=1%22_cff_marker_cat_sqli_probe_990de281db`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_990de281db`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_990de281db` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 18. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?cat=1%27_cff_marker_cat_sqli_probe_353b6d4487`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_353b6d4487`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_353b6d4487` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 19. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?p=1%22_cff_marker_p_sqli_probe_38aacbc31c`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_38aacbc31c`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_38aacbc31c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 20. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?p=1%27_cff_marker_p_sqli_probe_4aaa186df3`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_4aaa186df3`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_4aaa186df3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 21. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?page_id=1%22_cff_marker_page_id_sqli_probe_075736778a`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_075736778a`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_075736778a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 22. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?page_id=1%27_cff_marker_page_id_sqli_probe_6e147db6ad`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_6e147db6ad`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_6e147db6ad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 23. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?s=%27_cff_marker_s_sqli_probe_02d0b6c7e9`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_02d0b6c7e9`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_s_sqli_probe_02d0b6c7e9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 24. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?search=%27_cff_marker_search_sqli_probe_45efa196e5`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_45efa196e5`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_search_sqli_probe_45efa196e5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 25. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?action=cff_marker_action_action_canary_08e6d5c9a5`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_08e6d5c9a5`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_action_canary_08e6d5c9a5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 26. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?action=invalid_action_cff_marker_action_text_canary_7bc08f5b8f`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action_cff_marker_action_text_canary_7bc08f5b8f`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_text_canary_7bc08f5b8f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 27. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?author=-1_cff_marker_author_numeric_boundary_7fd383ef0a`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_7fd383ef0a`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_7fd383ef0a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 28. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?author=0_cff_marker_author_numeric_boundary_c294b24197`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_c294b24197`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_c294b24197` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 29. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?author=1_cff_marker_author_numeric_boundary_4908e40d33`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_4908e40d33`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_4908e40d33` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 30. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?author=999999_cff_marker_author_numeric_boundary_0f75e19ff1`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_0f75e19ff1`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_0f75e19ff1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 31. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?cat=-1_cff_marker_cat_numeric_boundary_7f89bca35f`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_7f89bca35f`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_7f89bca35f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 32. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?cat=0_cff_marker_cat_numeric_boundary_dfb568fa8b`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_dfb568fa8b`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_dfb568fa8b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 33. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?cat=1_cff_marker_cat_numeric_boundary_d47520edce`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_d47520edce`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_d47520edce` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 34. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?cat=999999_cff_marker_cat_numeric_boundary_6d308d3072`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_6d308d3072`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_6d308d3072` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 35. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?log=%22cff_marker_log_xss_reflection_probe_bfcff41a6a`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_log_xss_reflection_probe_bfcff41a6a`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_bfcff41a6a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 36. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?log=%27cff_marker_log_xss_reflection_probe_1780c9773b`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_log_xss_reflection_probe_1780c9773b`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_1780c9773b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 37. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?log=%3Ccff_marker_log_xss_reflection_probe_b724f2f118%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_log_xss_reflection_probe_b724f2f118&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_b724f2f118` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 38. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?log=cff_marker_log_text_canary_88f14c6519`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_log_text_canary_88f14c6519`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_text_canary_88f14c6519` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 39. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?nonce=12345_cff_marker_nonce_generic_number_cc95682fcc`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_nonce_generic_number_cc95682fcc`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_number_cc95682fcc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 40. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?nonce=cff_marker_nonce_generic_canary_c15a78ed20`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_nonce_generic_canary_c15a78ed20`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_canary_c15a78ed20` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 41. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?nonce=true_cff_marker_nonce_generic_bool_245352f116`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_nonce_generic_bool_245352f116`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_bool_245352f116` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 42. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?p=-1_cff_marker_p_numeric_boundary_606315bc36`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_606315bc36`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_606315bc36` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 43. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?p=0_cff_marker_p_numeric_boundary_3eee965de7`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_3eee965de7`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_3eee965de7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 44. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?p=1_cff_marker_p_numeric_boundary_4ce5d83812`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_4ce5d83812`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_4ce5d83812` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 45. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?p=999999_cff_marker_p_numeric_boundary_f20387c948`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_f20387c948`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_f20387c948` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 46. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?page_id=-1_cff_marker_page_id_numeric_boundary_eff597b45a`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_eff597b45a`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_eff597b45a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 47. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?page_id=0_cff_marker_page_id_numeric_boundary_2bebddca7b`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_2bebddca7b`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_2bebddca7b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 48. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?page_id=1_cff_marker_page_id_numeric_boundary_d0161f2bb5`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_d0161f2bb5`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_d0161f2bb5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 49. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?page_id=999999_cff_marker_page_id_numeric_boundary_e879c099b2`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_e879c099b2`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_e879c099b2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 50. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?pwd=12345_cff_marker_pwd_generic_number_fe35614c92`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_pwd_generic_number_fe35614c92`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_number_fe35614c92` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 51. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?pwd=cff_marker_pwd_generic_canary_7db57ef5a6`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_pwd_generic_canary_7db57ef5a6`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_canary_7db57ef5a6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 52. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?pwd=true_cff_marker_pwd_generic_bool_7c5cfbb784`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_pwd_generic_bool_7c5cfbb784`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_bool_7c5cfbb784` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 53. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_76d96bde0d`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_to_redirect_probe_76d96bde0d`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_76d96bde0d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 54. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_e926788701`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_to_redirect_probe_e926788701`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_e926788701` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 55. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?s=%22cff_marker_s_xss_reflection_probe_e2ffb92475`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_s_xss_reflection_probe_e2ffb92475`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_e2ffb92475` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 56. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?s=%27cff_marker_s_xss_reflection_probe_a4cfb7084a`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_s_xss_reflection_probe_a4cfb7084a`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_a4cfb7084a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 57. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?s=%3Ccff_marker_s_xss_reflection_probe_0138cfffa8%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_0138cfffa8&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_0138cfffa8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 58. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?s=cff_marker_s_text_canary_a566a87b3e`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_a566a87b3e`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_text_canary_a566a87b3e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 59. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?search=%22cff_marker_search_xss_reflection_probe_053a3e913e`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_search_xss_reflection_probe_053a3e913e`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_053a3e913e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 60. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?search=%27cff_marker_search_xss_reflection_probe_bd3f23700f`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_search_xss_reflection_probe_bd3f23700f`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_bd3f23700f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 61. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?search=%3Ccff_marker_search_xss_reflection_probe_3d04497699%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_3d04497699&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_3d04497699` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 62. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/?search=cff_marker_search_text_canary_d6cd79bb45`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_d6cd79bb45`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_text_canary_d6cd79bb45` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 63. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?action=cff_marker_action_action_canary_11b9b4618b`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_11b9b4618b`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_action_canary_11b9b4618b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 64. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?author=-1_cff_marker_author_numeric_boundary_5fc3ece542`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_5fc3ece542`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_5fc3ece542` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 65. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?author=0_cff_marker_author_numeric_boundary_49cc373a0a`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_49cc373a0a`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_49cc373a0a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 66. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?author=1_cff_marker_author_numeric_boundary_13daf4bf00`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_13daf4bf00`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_13daf4bf00` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 67. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?author=999999_cff_marker_author_numeric_boundary_c8f2a18bbc`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_c8f2a18bbc`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_c8f2a18bbc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 68. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?cat=-1_cff_marker_cat_numeric_boundary_5b88442e7a`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_5b88442e7a`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_5b88442e7a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 69. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?cat=0_cff_marker_cat_numeric_boundary_d92fc0c476`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_d92fc0c476`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_d92fc0c476` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 70. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?cat=1_cff_marker_cat_numeric_boundary_d6fb882633`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_d6fb882633`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_d6fb882633` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 71. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?cat=999999_cff_marker_cat_numeric_boundary_0fd766d553`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_0fd766d553`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_0fd766d553` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 72. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?p=-1_cff_marker_p_numeric_boundary_bf30c8f776`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_bf30c8f776`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_bf30c8f776` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 73. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?p=0_cff_marker_p_numeric_boundary_033a753c5b`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_033a753c5b`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_033a753c5b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 74. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?p=1_cff_marker_p_numeric_boundary_e6c0ae04e5`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_e6c0ae04e5`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_e6c0ae04e5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 75. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?p=999999_cff_marker_p_numeric_boundary_0806ea03de`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_0806ea03de`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_0806ea03de` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 76. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?page_id=-1_cff_marker_page_id_numeric_boundary_c77fe9fedc`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_c77fe9fedc`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_c77fe9fedc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 77. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?page_id=0_cff_marker_page_id_numeric_boundary_b365fb6266`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_b365fb6266`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_b365fb6266` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?page_id=1_cff_marker_page_id_numeric_boundary_32abbd80a6`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_32abbd80a6`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_32abbd80a6` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?page_id=999999_cff_marker_page_id_numeric_boundary_1aaa44d076`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_1aaa44d076`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_1aaa44d076` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?s=%22cff_marker_s_xss_reflection_probe_2d1a923868`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_s_xss_reflection_probe_2d1a923868`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_2d1a923868` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?s=%27cff_marker_s_xss_reflection_probe_898b84b8df`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_s_xss_reflection_probe_898b84b8df`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_898b84b8df` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?s=%3Ccff_marker_s_xss_reflection_probe_460bedebca%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_460bedebca&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_460bedebca` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?s=cff_marker_s_text_canary_56e91c260c`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_56e91c260c`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_text_canary_56e91c260c` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?search=%22cff_marker_search_xss_reflection_probe_247c1ec06e`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_search_xss_reflection_probe_247c1ec06e`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_247c1ec06e` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?search=%27cff_marker_search_xss_reflection_probe_132f091bb2`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_search_xss_reflection_probe_132f091bb2`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_132f091bb2` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?search=%3Ccff_marker_search_xss_reflection_probe_2673773621%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_2673773621&gt;`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_2673773621` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php?search=cff_marker_search_text_canary_be663d03d1`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_be663d03d1`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_text_canary_be663d03d1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 88. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://192.168.1.2/DVWA/vulnerabilities/xss_r/index.php`
- Response: HTTP `200` / Length `4748` / Type `text/html;charset=utf-8`
- Title: Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4748`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta

