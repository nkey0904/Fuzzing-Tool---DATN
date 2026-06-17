# Context Feedback Fuzzer Report

- Target: `http://192.168.1.2/DVWA/vulnerabilities/sqli/`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?action=%27_cff_marker_action_sqli_probe_0c73a4a37a`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_action_sqli_probe_0c73a4a37a`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_action_sqli_probe_0c73a4a37a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 2. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?author=1%22_cff_marker_author_sqli_probe_69e3eb5b6e`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_69e3eb5b6e`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_69e3eb5b6e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 3. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?author=1%27_cff_marker_author_sqli_probe_3ee0f1af84`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_3ee0f1af84`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_3ee0f1af84` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 4. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?cat=1%22_cff_marker_cat_sqli_probe_8adf2f8008`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_8adf2f8008`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_8adf2f8008` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 5. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?cat=1%27_cff_marker_cat_sqli_probe_404793c3d1`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_404793c3d1`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_404793c3d1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 6. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?log=%27_cff_marker_log_sqli_probe_972caa02dd`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_log_sqli_probe_972caa02dd`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_log_sqli_probe_972caa02dd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 7. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?nonce=%27_cff_marker_nonce_sqli_probe_74937117c5`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_nonce_sqli_probe_74937117c5`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_nonce_sqli_probe_74937117c5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 8. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?p=1%22_cff_marker_p_sqli_probe_59359604f6`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_59359604f6`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_59359604f6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 9. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?p=1%27_cff_marker_p_sqli_probe_67b8e2abb6`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_67b8e2abb6`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_67b8e2abb6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 10. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?page_id=1%22_cff_marker_page_id_sqli_probe_fec3647890`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_fec3647890`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_fec3647890` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 11. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?page_id=1%27_cff_marker_page_id_sqli_probe_7e2aa9557b`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_7e2aa9557b`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_7e2aa9557b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 12. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?pwd=%27_cff_marker_pwd_sqli_probe_52bc279605`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_pwd_sqli_probe_52bc279605`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_pwd_sqli_probe_52bc279605` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 13. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?s=%27_cff_marker_s_sqli_probe_be8ce9b96f`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_be8ce9b96f`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_s_sqli_probe_be8ce9b96f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 14. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?search=%27_cff_marker_search_sqli_probe_246deaf7da`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_246deaf7da`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_search_sqli_probe_246deaf7da` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; SQL-like error keyword appeared in response

### 15. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?author=1%22_cff_marker_author_sqli_probe_d6d97ce061`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_d6d97ce061`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_d6d97ce061` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?author=1%27_cff_marker_author_sqli_probe_1beba879f0`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_1beba879f0`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_1beba879f0` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?cat=1%22_cff_marker_cat_sqli_probe_08e12a664f`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_08e12a664f`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_08e12a664f` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?cat=1%27_cff_marker_cat_sqli_probe_c9d75aa185`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_c9d75aa185`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_c9d75aa185` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?p=1%22_cff_marker_p_sqli_probe_cb373daff6`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_cb373daff6`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_cb373daff6` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?p=1%27_cff_marker_p_sqli_probe_186c0f3510`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_186c0f3510`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_186c0f3510` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?page_id=1%22_cff_marker_page_id_sqli_probe_a82d9a50ec`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_a82d9a50ec`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_a82d9a50ec` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?page_id=1%27_cff_marker_page_id_sqli_probe_74f70ec3ba`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_74f70ec3ba`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_74f70ec3ba` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?s=%27_cff_marker_s_sqli_probe_0dd70a1ebe`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_0dd70a1ebe`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_s_sqli_probe_0dd70a1ebe` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?search=%27_cff_marker_search_sqli_probe_3ae7d7deb7`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_3ae7d7deb7`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_search_sqli_probe_3ae7d7deb7` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?action=cff_marker_action_action_canary_047c2c1c62`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_047c2c1c62`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_action_canary_047c2c1c62` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 26. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?action=invalid_action_cff_marker_action_text_canary_fc3331165c`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action_cff_marker_action_text_canary_fc3331165c`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_text_canary_fc3331165c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 27. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?author=-1_cff_marker_author_numeric_boundary_0fe0b5d9f7`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_0fe0b5d9f7`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_0fe0b5d9f7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 28. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?author=0_cff_marker_author_numeric_boundary_feb7107275`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_feb7107275`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_feb7107275` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 29. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?author=1_cff_marker_author_numeric_boundary_f20b6e7475`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_f20b6e7475`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_f20b6e7475` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 30. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?author=999999_cff_marker_author_numeric_boundary_d26dd6de64`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_d26dd6de64`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_d26dd6de64` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 31. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?cat=-1_cff_marker_cat_numeric_boundary_a53a2c17ca`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_a53a2c17ca`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_a53a2c17ca` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 32. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?cat=0_cff_marker_cat_numeric_boundary_69c96a922f`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_69c96a922f`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_69c96a922f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 33. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?cat=1_cff_marker_cat_numeric_boundary_4aec3f6664`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_4aec3f6664`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_4aec3f6664` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 34. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?cat=999999_cff_marker_cat_numeric_boundary_7616d7f1c6`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_7616d7f1c6`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_7616d7f1c6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 35. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?log=%22cff_marker_log_xss_reflection_probe_59b7fab386`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_log_xss_reflection_probe_59b7fab386`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_59b7fab386` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 36. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?log=%27cff_marker_log_xss_reflection_probe_dd7a968d34`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_log_xss_reflection_probe_dd7a968d34`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_dd7a968d34` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 37. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?log=%3Ccff_marker_log_xss_reflection_probe_e48cd6e06e%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_log_xss_reflection_probe_e48cd6e06e&gt;`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_e48cd6e06e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 38. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?log=cff_marker_log_text_canary_07ce5cf642`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_log_text_canary_07ce5cf642`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_text_canary_07ce5cf642` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 39. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?nonce=12345_cff_marker_nonce_generic_number_90b78f07dd`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_nonce_generic_number_90b78f07dd`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_number_90b78f07dd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 40. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?nonce=cff_marker_nonce_generic_canary_6cfae0232a`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_nonce_generic_canary_6cfae0232a`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_canary_6cfae0232a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 41. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?nonce=true_cff_marker_nonce_generic_bool_3be714b77b`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_nonce_generic_bool_3be714b77b`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_nonce_generic_bool_3be714b77b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 42. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?p=-1_cff_marker_p_numeric_boundary_16d90b1f1f`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_16d90b1f1f`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_16d90b1f1f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 43. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?p=0_cff_marker_p_numeric_boundary_41b54b18b5`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_41b54b18b5`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_41b54b18b5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 44. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?p=1_cff_marker_p_numeric_boundary_4dccbb5e2e`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_4dccbb5e2e`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_4dccbb5e2e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 45. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?p=999999_cff_marker_p_numeric_boundary_173097b91d`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_173097b91d`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_173097b91d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 46. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?page_id=-1_cff_marker_page_id_numeric_boundary_62e93d7563`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_62e93d7563`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_62e93d7563` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 47. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?page_id=0_cff_marker_page_id_numeric_boundary_18673426d9`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_18673426d9`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_18673426d9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 48. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?page_id=1_cff_marker_page_id_numeric_boundary_1a1271f02b`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_1a1271f02b`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_1a1271f02b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 49. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?page_id=999999_cff_marker_page_id_numeric_boundary_9d817a00f1`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_9d817a00f1`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_9d817a00f1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 50. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?pwd=12345_cff_marker_pwd_generic_number_8ba64ac288`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_pwd_generic_number_8ba64ac288`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_number_8ba64ac288` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 51. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?pwd=cff_marker_pwd_generic_canary_f36c14de49`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_pwd_generic_canary_f36c14de49`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_canary_f36c14de49` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 52. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?pwd=true_cff_marker_pwd_generic_bool_3c4891bb7b`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_pwd_generic_bool_3c4891bb7b`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_pwd_generic_bool_3c4891bb7b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 53. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_733eb6e187`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_to_redirect_probe_733eb6e187`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_733eb6e187` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 54. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_6b54ce9623`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_to_redirect_probe_6b54ce9623`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_6b54ce9623` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 55. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?s=%22cff_marker_s_xss_reflection_probe_f451f4d218`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_s_xss_reflection_probe_f451f4d218`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_f451f4d218` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 56. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?s=%27cff_marker_s_xss_reflection_probe_c55c4e108f`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_s_xss_reflection_probe_c55c4e108f`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_c55c4e108f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 57. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?s=%3Ccff_marker_s_xss_reflection_probe_4d552c0784%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_4d552c0784&gt;`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_4d552c0784` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 58. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?s=cff_marker_s_text_canary_ef54e58121`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_ef54e58121`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_text_canary_ef54e58121` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 59. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?search=%22cff_marker_search_xss_reflection_probe_fd3b99b434`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_search_xss_reflection_probe_fd3b99b434`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_fd3b99b434` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 60. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?search=%27cff_marker_search_xss_reflection_probe_69726635e7`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_search_xss_reflection_probe_69726635e7`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_69726635e7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 61. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?search=%3Ccff_marker_search_xss_reflection_probe_30cbbf40fd%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_30cbbf40fd&gt;`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_30cbbf40fd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 62. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/?search=cff_marker_search_text_canary_b934c8e91f`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_b934c8e91f`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_text_canary_b934c8e91f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4592`
  - Content-Type: `text/html;charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 63. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?action=cff_marker_action_action_canary_6e33c3dd2e`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_6e33c3dd2e`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_action_action_canary_6e33c3dd2e` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?author=-1_cff_marker_author_numeric_boundary_a7e67e441e`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_a7e67e441e`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_a7e67e441e` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?author=0_cff_marker_author_numeric_boundary_70d28484d9`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_70d28484d9`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_70d28484d9` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?author=1_cff_marker_author_numeric_boundary_7fbe886d28`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_7fbe886d28`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_7fbe886d28` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?author=999999_cff_marker_author_numeric_boundary_7e1645866b`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_7e1645866b`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_7e1645866b` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?cat=-1_cff_marker_cat_numeric_boundary_4f4e19b5b4`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_4f4e19b5b4`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_4f4e19b5b4` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?cat=0_cff_marker_cat_numeric_boundary_37de5472ec`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_37de5472ec`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_37de5472ec` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?cat=1_cff_marker_cat_numeric_boundary_be7b12ed4d`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_be7b12ed4d`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_be7b12ed4d` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?cat=999999_cff_marker_cat_numeric_boundary_5cf76c15e6`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_5cf76c15e6`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_5cf76c15e6` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?p=-1_cff_marker_p_numeric_boundary_2cfbf29432`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_2cfbf29432`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_2cfbf29432` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?p=0_cff_marker_p_numeric_boundary_0276654500`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_0276654500`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_0276654500` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?p=1_cff_marker_p_numeric_boundary_fe9ae64694`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_fe9ae64694`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_fe9ae64694` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?p=999999_cff_marker_p_numeric_boundary_d6a5f2b107`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_d6a5f2b107`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_d6a5f2b107` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?page_id=-1_cff_marker_page_id_numeric_boundary_22570ada55`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_22570ada55`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_22570ada55` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?page_id=0_cff_marker_page_id_numeric_boundary_37b456cb84`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_37b456cb84`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_37b456cb84` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?page_id=1_cff_marker_page_id_numeric_boundary_b3143d96c2`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_b3143d96c2`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_b3143d96c2` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?page_id=999999_cff_marker_page_id_numeric_boundary_c920321b49`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_c920321b49`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_c920321b49` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?s=%22cff_marker_s_xss_reflection_probe_f78b0bdff6`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_s_xss_reflection_probe_f78b0bdff6`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_f78b0bdff6` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?s=%27cff_marker_s_xss_reflection_probe_c719a5d785`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_s_xss_reflection_probe_c719a5d785`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_c719a5d785` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?s=%3Ccff_marker_s_xss_reflection_probe_f9471b2b80%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_f9471b2b80&gt;`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_f9471b2b80` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?s=cff_marker_s_text_canary_f6c17fdf14`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_f6c17fdf14`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_s_text_canary_f6c17fdf14` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?search=%22cff_marker_search_xss_reflection_probe_352a0084b6`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_search_xss_reflection_probe_352a0084b6`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_352a0084b6` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?search=%27cff_marker_search_xss_reflection_probe_7af9d10481`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_search_xss_reflection_probe_7af9d10481`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_7af9d10481` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?search=%3Ccff_marker_search_xss_reflection_probe_03db9e4d60%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_03db9e4d60&gt;`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_03db9e4d60` | Reflected: `False` | Hits: `0`
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
- URL: `http://192.168.1.2/DVWA/vulnerabilities/sqli/index.php?search=cff_marker_search_text_canary_febe598891`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_febe598891`
- Response: HTTP `200` / Length `4592` / Type `text/html;charset=utf-8`
- Title: Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA)
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_text_canary_febe598891` | Reflected: `False` | Hits: `0`
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

