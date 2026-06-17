# Context Feedback Fuzzer Report

- Target: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit#/`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;action=%27_cff_marker_action_sqli_probe_539a96afa7#/`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_action_sqli_probe_539a96afa7`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_action_sqli_probe_539a96afa7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 2. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;author=1%22_cff_marker_author_sqli_probe_b28ddca0e4#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_b28ddca0e4`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_b28ddca0e4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 3. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;author=1%27_cff_marker_author_sqli_probe_9a326bfee1#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_9a326bfee1`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_9a326bfee1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 4. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;cat=1%22_cff_marker_cat_sqli_probe_cc0cebbedd#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_cc0cebbedd`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_cc0cebbedd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 5. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;cat=1%27_cff_marker_cat_sqli_probe_a894b8ddc3#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_a894b8ddc3`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_a894b8ddc3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 6. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;log=%27_cff_marker_log_sqli_probe_035aa84f56#/`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_log_sqli_probe_035aa84f56`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_log_sqli_probe_035aa84f56` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 7. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;nonce=%27_cff_marker_nonce_sqli_probe_8fcd395728#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_nonce_sqli_probe_8fcd395728`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_nonce_sqli_probe_8fcd395728` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 8. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;p=1%22_cff_marker_p_sqli_probe_ec893a5886#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_ec893a5886`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_ec893a5886` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 9. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;p=1%27_cff_marker_p_sqli_probe_fb33b72bd3#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_fb33b72bd3`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_fb33b72bd3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 10. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;page_id=1%22_cff_marker_page_id_sqli_probe_3a8030e3b6#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_3a8030e3b6`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_3a8030e3b6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 11. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;page_id=1%27_cff_marker_page_id_sqli_probe_dd6a40d746#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_dd6a40d746`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_dd6a40d746` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 12. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;pwd=%27_cff_marker_pwd_sqli_probe_0e1db258ab#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_pwd_sqli_probe_0e1db258ab`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_pwd_sqli_probe_0e1db258ab` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 13. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;s=%27_cff_marker_s_sqli_probe_b92c8f12e1#/`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_b92c8f12e1`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_s_sqli_probe_b92c8f12e1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 14. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;search=%27_cff_marker_search_sqli_probe_7ffa13128f#/`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_7ffa13128f`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_search_sqli_probe_7ffa13128f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 15. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?author=1%22_cff_marker_author_sqli_probe_fdf8b3a5d6`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_fdf8b3a5d6`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_fdf8b3a5d6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 16. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?author=1%27_cff_marker_author_sqli_probe_ce8e4d4ad3`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_ce8e4d4ad3`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_ce8e4d4ad3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 17. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?cat=1%22_cff_marker_cat_sqli_probe_263b818b33`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_263b818b33`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_263b818b33` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 18. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?cat=1%27_cff_marker_cat_sqli_probe_ebe49fec23`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_ebe49fec23`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_ebe49fec23` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 19. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?p=1%22_cff_marker_p_sqli_probe_8a0f89024f`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_8a0f89024f`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_8a0f89024f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 20. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?p=1%27_cff_marker_p_sqli_probe_0c4b6888f7`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_0c4b6888f7`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_0c4b6888f7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 21. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?page_id=1%22_cff_marker_page_id_sqli_probe_afd4df3ec1`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_afd4df3ec1`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_afd4df3ec1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 22. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?page_id=1%27_cff_marker_page_id_sqli_probe_a77bae2cae`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_a77bae2cae`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_a77bae2cae` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 23. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?s=%27_cff_marker_s_sqli_probe_af3b45e816`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_af3b45e816`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_s_sqli_probe_af3b45e816` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 24. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?search=%27_cff_marker_search_sqli_probe_5097e2099c`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_5097e2099c`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_search_sqli_probe_5097e2099c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 25. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;action=cff_marker_action_action_canary_9a8f280315#/`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_9a8f280315`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_action_canary_9a8f280315` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 26. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;action=invalid_action_cff_marker_action_text_canary_060935601a#/`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action_cff_marker_action_text_canary_060935601a`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_text_canary_060935601a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 27. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;author=-1_cff_marker_author_numeric_boundary_4fa32f7edd#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_4fa32f7edd`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_4fa32f7edd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 28. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;author=0_cff_marker_author_numeric_boundary_62462e9a6b#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_62462e9a6b`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_62462e9a6b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 29. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;author=1_cff_marker_author_numeric_boundary_e25fcf572f#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_e25fcf572f`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_e25fcf572f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 30. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;author=999999_cff_marker_author_numeric_boundary_506a528695#/`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_506a528695`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_506a528695` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 31. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;cat=-1_cff_marker_cat_numeric_boundary_1c7eca1d3b#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_1c7eca1d3b`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_1c7eca1d3b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 32. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;cat=0_cff_marker_cat_numeric_boundary_9f9e3c1eab#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_9f9e3c1eab`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_9f9e3c1eab` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 33. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;cat=1_cff_marker_cat_numeric_boundary_e516db973f#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_e516db973f`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_e516db973f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 34. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;cat=999999_cff_marker_cat_numeric_boundary_793d662d47#/`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_793d662d47`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_793d662d47` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 35. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;log=%22cff_marker_log_xss_reflection_probe_6126ec20bd#/`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_log_xss_reflection_probe_6126ec20bd`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_6126ec20bd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 36. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;log=%27cff_marker_log_xss_reflection_probe_efe2eeadac#/`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_log_xss_reflection_probe_efe2eeadac`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_efe2eeadac` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 37. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;log=%3Ccff_marker_log_xss_reflection_probe_8d0a5011c7%3E#/`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_log_xss_reflection_probe_8d0a5011c7&gt;`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_8d0a5011c7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 38. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;log=cff_marker_log_text_canary_a1e257c460#/`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_log_text_canary_a1e257c460`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_text_canary_a1e257c460` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 39. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;nonce=12345_cff_marker_nonce_generic_number_9a88c04bd4#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_nonce_generic_number_9a88c04bd4`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_number_9a88c04bd4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 40. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;nonce=cff_marker_nonce_generic_canary_aa8857648e#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_nonce_generic_canary_aa8857648e`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_canary_aa8857648e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 41. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;nonce=true_cff_marker_nonce_generic_bool_da331e526f#/`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_nonce_generic_bool_da331e526f`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_bool_da331e526f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 42. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;p=-1_cff_marker_p_numeric_boundary_68b7c184b8#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_68b7c184b8`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_68b7c184b8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 43. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;p=0_cff_marker_p_numeric_boundary_044a7f92a6#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_044a7f92a6`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_044a7f92a6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 44. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;p=1_cff_marker_p_numeric_boundary_0946ed9cb4#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_0946ed9cb4`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_0946ed9cb4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 45. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;p=999999_cff_marker_p_numeric_boundary_f868f49aec#/`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_f868f49aec`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_f868f49aec` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 46. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;page_id=-1_cff_marker_page_id_numeric_boundary_b9468bd7c3#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_b9468bd7c3`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_b9468bd7c3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 47. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;page_id=0_cff_marker_page_id_numeric_boundary_8ce9229f48#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_8ce9229f48`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_8ce9229f48` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 48. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;page_id=1_cff_marker_page_id_numeric_boundary_a8119c43c4#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_a8119c43c4`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_a8119c43c4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 49. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;page_id=999999_cff_marker_page_id_numeric_boundary_15cd38792b#/`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_15cd38792b`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_15cd38792b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 50. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;pwd=12345_cff_marker_pwd_generic_number_24a1a06f8c#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_pwd_generic_number_24a1a06f8c`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_number_24a1a06f8c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 51. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;pwd=cff_marker_pwd_generic_canary_f06cada3e7#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_pwd_generic_canary_f06cada3e7`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_canary_f06cada3e7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 52. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;pwd=true_cff_marker_pwd_generic_bool_31846716be#/`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_pwd_generic_bool_31846716be`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_bool_31846716be` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 53. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_e1eb0300a6#/`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_to_redirect_probe_e1eb0300a6`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_e1eb0300a6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 54. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_84744daa35#/`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_to_redirect_probe_84744daa35`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_84744daa35` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 55. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;s=%22cff_marker_s_xss_reflection_probe_ab2a37d542#/`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_s_xss_reflection_probe_ab2a37d542`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_ab2a37d542` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 56. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;s=%27cff_marker_s_xss_reflection_probe_5bd2331b6c#/`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_s_xss_reflection_probe_5bd2331b6c`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_5bd2331b6c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 57. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;s=%3Ccff_marker_s_xss_reflection_probe_1b2788a024%3E#/`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_1b2788a024&gt;`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_1b2788a024` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 58. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;s=cff_marker_s_text_canary_00cecde06f#/`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_00cecde06f`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_text_canary_00cecde06f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 59. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;search=%22cff_marker_search_xss_reflection_probe_70cfbd434e#/`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_search_xss_reflection_probe_70cfbd434e`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_70cfbd434e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 60. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;search=%27cff_marker_search_xss_reflection_probe_95b64efca7#/`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_search_xss_reflection_probe_95b64efca7`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_95b64efca7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 61. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;search=%3Ccff_marker_search_xss_reflection_probe_8979b93287%3E#/`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_8979b93287&gt;`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_8979b93287` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 62. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?id=1&amp;Submit=Submit&amp;search=cff_marker_search_text_canary_4e7bc9bb21#/`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_4e7bc9bb21`
- Response: HTTP `200` / Length `4651` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_text_canary_4e7bc9bb21` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4651`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 63. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?action=cff_marker_action_action_canary_c4c028d605`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_c4c028d605`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_action_canary_c4c028d605` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 64. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?author=-1_cff_marker_author_numeric_boundary_c7571568b3`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_c7571568b3`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_c7571568b3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 65. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?author=0_cff_marker_author_numeric_boundary_4da6c29e01`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_4da6c29e01`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_4da6c29e01` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 66. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?author=1_cff_marker_author_numeric_boundary_7047ab0037`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_7047ab0037`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_7047ab0037` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 67. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?author=999999_cff_marker_author_numeric_boundary_bdd88f244f`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_bdd88f244f`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_bdd88f244f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 68. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?cat=-1_cff_marker_cat_numeric_boundary_33ef24922e`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_33ef24922e`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_33ef24922e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 69. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?cat=0_cff_marker_cat_numeric_boundary_b4c9f32daf`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_b4c9f32daf`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_b4c9f32daf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 70. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?cat=1_cff_marker_cat_numeric_boundary_3cbab1586c`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_3cbab1586c`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_3cbab1586c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 71. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?cat=999999_cff_marker_cat_numeric_boundary_67fbb01159`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_67fbb01159`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_67fbb01159` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 72. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?p=-1_cff_marker_p_numeric_boundary_e385d6a778`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_e385d6a778`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_e385d6a778` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 73. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?p=0_cff_marker_p_numeric_boundary_881370e85f`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_881370e85f`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_881370e85f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 74. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?p=1_cff_marker_p_numeric_boundary_c6ed129b0c`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_c6ed129b0c`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_c6ed129b0c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 75. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?p=999999_cff_marker_p_numeric_boundary_3705246805`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_3705246805`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_3705246805` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 76. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?page_id=-1_cff_marker_page_id_numeric_boundary_c00ccc889b`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_c00ccc889b`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_c00ccc889b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 77. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?page_id=0_cff_marker_page_id_numeric_boundary_de3e3dd493`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_de3e3dd493`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_de3e3dd493` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 78. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?page_id=1_cff_marker_page_id_numeric_boundary_584635ce2b`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_584635ce2b`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_584635ce2b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 79. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?page_id=999999_cff_marker_page_id_numeric_boundary_2b124ebc28`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_2b124ebc28`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_2b124ebc28` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 80. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?s=%22cff_marker_s_xss_reflection_probe_f8792ada7a`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_s_xss_reflection_probe_f8792ada7a`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_f8792ada7a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 81. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?s=%27cff_marker_s_xss_reflection_probe_b1e724b05e`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_s_xss_reflection_probe_b1e724b05e`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_b1e724b05e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 82. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?s=%3Ccff_marker_s_xss_reflection_probe_c6b3da8d8b%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_c6b3da8d8b&gt;`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_c6b3da8d8b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 83. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?s=cff_marker_s_text_canary_47f132d663`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_47f132d663`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_text_canary_47f132d663` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 84. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?search=%22cff_marker_search_xss_reflection_probe_bf13b34fd1`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_search_xss_reflection_probe_bf13b34fd1`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_bf13b34fd1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 85. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?search=%27cff_marker_search_xss_reflection_probe_a0aee5046a`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_search_xss_reflection_probe_a0aee5046a`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_a0aee5046a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 86. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?search=%3Ccff_marker_search_xss_reflection_probe_6931d40b25%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_6931d40b25&gt;`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_6931d40b25` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 87. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?search=cff_marker_search_text_canary_b60383c532`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_b60383c532`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_text_canary_b60383c532` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 88. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta

