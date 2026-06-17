# Context Feedback Fuzzer Report

- Target: `https://pallife.co/`
- Detected Platform: **wordpress**
- Platform type: `CMS`
- Scan status: `done`
- Requests sent: `1000`
- Safety: GET-only, same-host scope, rate-limited, authorization flag required.
- Server technology hint: `php` / `unknown`
- Confirmed findings: `17`
- Possible findings: `488`
- Confirmation rate: `3.37%`
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
  - `search` => `text_canary, xss_reflection_probe, xss_trigger_probe, xss_trigger_probe, sqli_probe`
  - `s` => `text_canary, xss_reflection_probe, xss_trigger_probe, xss_trigger_probe, sqli_probe`
  - `author` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `action` => `action_canary, text_canary, sqli_probe`
  - `nonce` => `generic_canary, generic_bool, generic_number, sqli_probe`
  - `redirect_to` => `redirect_probe, redirect_probe`
  - `log` => `text_canary, xss_reflection_probe, xss_trigger_probe, xss_trigger_probe, sqli_probe`
  - `pwd` => `generic_canary, generic_bool, generic_number, sqli_probe`

## Marker verification mechanism

Marker-based fuzzing gắn marker duy nhất vào từng payload. Sau fuzzing, verification engine crawl các link cùng host và kiểm tra marker có xuất hiện lại không. Nếu có bằng chứng marker, finding được phân loại là confirmed.

- Markers generated: `468`
- Markers verified: `0`
- Markers failed: `468`
- Marker verification rate: `0.0%`
- Crawled links: `80`

## Fingerprint scores

- wordpress: 30
- joomla: 5
- drupal: 0
- liferay: 0
- sharepoint: 0
- moodle: 0

## Findings

Các finding được chia theo trạng thái `confirmed` hoặc `possible`. Confirmed nghĩa là có bằng chứng marker-based reflection/verification; possible nghĩa là dựa trên feedback/anomaly nhưng chưa có marker xác nhận.

### 1. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?action=%27_cff_marker_action_sqli_probe_1a2037552c`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_action_sqli_probe_1a2037552c`
- Response: HTTP `200` / Length `91828` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_action_sqli_probe_1a2037552c
- Marker: `cff_marker_action_sqli_probe_1a2037552c` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?action=%27_cff_marker_action_sqli_probe_1a2037552c` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91828`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_action_sqli_probe_1a2037552c; marker hits: 1; unique marker reflected: cff_marker_action_sqli_probe_1a2037552c

### 2. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?action=cff_marker_action_action_canary_62f1befb96`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_62f1befb96`
- Response: HTTP `200` / Length `91827` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_action_action_canary_62f1befb96
- Marker: `cff_marker_action_action_canary_62f1befb96` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?action=cff_marker_action_action_canary_62f1befb96` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91827`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_action_action_canary_62f1befb96; marker hits: 1; unique marker reflected: cff_marker_action_action_canary_62f1befb96

### 3. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?action=invalid_action_cff_marker_action_text_canary_cf3bf65411`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action_cff_marker_action_text_canary_cf3bf65411`
- Response: HTTP `200` / Length `91840` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_action_text_canary_cf3bf65411
- Marker: `cff_marker_action_text_canary_cf3bf65411` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?action=invalid_action_cff_marker_action_text_canary_cf3bf65411` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91840`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_action_text_canary_cf3bf65411; marker hits: 1; unique marker reflected: cff_marker_action_text_canary_cf3bf65411

### 4. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?log=%27_cff_marker_log_sqli_probe_74e9381770`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_log_sqli_probe_74e9381770`
- Response: HTTP `200` / Length `91822` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_log_sqli_probe_74e9381770
- Marker: `cff_marker_log_sqli_probe_74e9381770` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?log=%27_cff_marker_log_sqli_probe_74e9381770` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91822`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_log_sqli_probe_74e9381770; marker hits: 1; unique marker reflected: cff_marker_log_sqli_probe_74e9381770

### 5. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?log=cff_marker_log_text_canary_ff85cb70ce`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_log_text_canary_ff85cb70ce`
- Response: HTTP `200` / Length `91819` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_log_text_canary_ff85cb70ce
- Marker: `cff_marker_log_text_canary_ff85cb70ce` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?log=cff_marker_log_text_canary_ff85cb70ce` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91819`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_log_text_canary_ff85cb70ce; marker hits: 1; unique marker reflected: cff_marker_log_text_canary_ff85cb70ce

### 6. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?nonce=%27_cff_marker_nonce_sqli_probe_a9af94f489`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_nonce_sqli_probe_a9af94f489`
- Response: HTTP `200` / Length `91826` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_nonce_sqli_probe_a9af94f489
- Marker: `cff_marker_nonce_sqli_probe_a9af94f489` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?nonce=%27_cff_marker_nonce_sqli_probe_a9af94f489` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91826`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_nonce_sqli_probe_a9af94f489; marker hits: 1; unique marker reflected: cff_marker_nonce_sqli_probe_a9af94f489

### 7. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?nonce=12345_cff_marker_nonce_generic_number_9169d11e36`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_nonce_generic_number_9169d11e36`
- Response: HTTP `200` / Length `91832` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_nonce_generic_number_9169d11e36
- Marker: `cff_marker_nonce_generic_number_9169d11e36` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?nonce=12345_cff_marker_nonce_generic_number_9169d11e36` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91832`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_nonce_generic_number_9169d11e36; marker hits: 1; unique marker reflected: cff_marker_nonce_generic_number_9169d11e36

### 8. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?nonce=cff_marker_nonce_generic_canary_9f178be0a4`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_nonce_generic_canary_9f178be0a4`
- Response: HTTP `200` / Length `91826` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_nonce_generic_canary_9f178be0a4
- Marker: `cff_marker_nonce_generic_canary_9f178be0a4` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?nonce=cff_marker_nonce_generic_canary_9f178be0a4` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91826`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_nonce_generic_canary_9f178be0a4; marker hits: 1; unique marker reflected: cff_marker_nonce_generic_canary_9f178be0a4

### 9. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?nonce=true_cff_marker_nonce_generic_bool_b2efd3b54c`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_nonce_generic_bool_b2efd3b54c`
- Response: HTTP `200` / Length `91829` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_nonce_generic_bool_b2efd3b54c
- Marker: `cff_marker_nonce_generic_bool_b2efd3b54c` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?nonce=true_cff_marker_nonce_generic_bool_b2efd3b54c` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91829`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_nonce_generic_bool_b2efd3b54c; marker hits: 1; unique marker reflected: cff_marker_nonce_generic_bool_b2efd3b54c

### 10. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?pwd=%27_cff_marker_pwd_sqli_probe_3d95647f4a`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_pwd_sqli_probe_3d95647f4a`
- Response: HTTP `200` / Length `91822` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_pwd_sqli_probe_3d95647f4a
- Marker: `cff_marker_pwd_sqli_probe_3d95647f4a` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?pwd=%27_cff_marker_pwd_sqli_probe_3d95647f4a` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91822`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_pwd_sqli_probe_3d95647f4a; marker hits: 1; unique marker reflected: cff_marker_pwd_sqli_probe_3d95647f4a

### 11. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?pwd=12345_cff_marker_pwd_generic_number_a4349bb93b`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_pwd_generic_number_a4349bb93b`
- Response: HTTP `200` / Length `91828` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_pwd_generic_number_a4349bb93b
- Marker: `cff_marker_pwd_generic_number_a4349bb93b` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?pwd=12345_cff_marker_pwd_generic_number_a4349bb93b` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91828`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_pwd_generic_number_a4349bb93b; marker hits: 1; unique marker reflected: cff_marker_pwd_generic_number_a4349bb93b

### 12. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?pwd=cff_marker_pwd_generic_canary_e99aceb72c`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_pwd_generic_canary_e99aceb72c`
- Response: HTTP `200` / Length `91822` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_pwd_generic_canary_e99aceb72c
- Marker: `cff_marker_pwd_generic_canary_e99aceb72c` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?pwd=cff_marker_pwd_generic_canary_e99aceb72c` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91822`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_pwd_generic_canary_e99aceb72c; marker hits: 1; unique marker reflected: cff_marker_pwd_generic_canary_e99aceb72c

### 13. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?pwd=true_cff_marker_pwd_generic_bool_9f23d8c393`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_pwd_generic_bool_9f23d8c393`
- Response: HTTP `200` / Length `91825` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_pwd_generic_bool_9f23d8c393
- Marker: `cff_marker_pwd_generic_bool_9f23d8c393` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?pwd=true_cff_marker_pwd_generic_bool_9f23d8c393` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91825`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_pwd_generic_bool_9f23d8c393; marker hits: 1; unique marker reflected: cff_marker_pwd_generic_bool_9f23d8c393

### 14. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_9c34c90d2d`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_to_redirect_probe_9c34c90d2d`
- Response: HTTP `200` / Length `91858` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_redirect_to_redirect_probe_9c34c90d2d
- Marker: `cff_marker_redirect_to_redirect_probe_9c34c90d2d` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_9c34c90d2d` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91858`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_redirect_to_redirect_probe_9c34c90d2d; marker hits: 1; unique marker reflected: cff_marker_redirect_to_redirect_probe_9c34c90d2d

### 15. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_2bdc4dabef`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_to_redirect_probe_2bdc4dabef`
- Response: HTTP `200` / Length `91866` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: unique marker reflected: cff_marker_redirect_to_redirect_probe_2bdc4dabef
- Marker: `cff_marker_redirect_to_redirect_probe_2bdc4dabef` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_2bdc4dabef` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91866`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; marker reflected: cff_marker_redirect_to_redirect_probe_2bdc4dabef; marker hits: 1; unique marker reflected: cff_marker_redirect_to_redirect_probe_2bdc4dabef

### 16. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?s=%27_cff_marker_s_sqli_probe_a225634b96`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_a225634b96`
- Response: HTTP `200` / Length `42877` / Type `text/html; charset=UTF-8`
- Title: Search Results for “&#x27;_cff_marker_s_sqli_probe_a225634b96” – pallife
- Evidence: unique marker reflected: cff_marker_s_sqli_probe_a225634b96
- Marker: `cff_marker_s_sqli_probe_a225634b96` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?s=%27_cff_marker_s_sqli_probe_a225634b96` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42877`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; marker reflected: cff_marker_s_sqli_probe_a225634b96; marker hits: 1; unique marker reflected: cff_marker_s_sqli_probe_a225634b96

### 17. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hoặc JS được kích hoạt.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?s=cff_marker_s_text_canary_d8fba451bb`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_d8fba451bb`
- Response: HTTP `200` / Length `42826` / Type `text/html; charset=UTF-8`
- Title: Search Results for “cff_marker_s_text_canary_d8fba451bb” – pallife
- Evidence: unique marker reflected: cff_marker_s_text_canary_d8fba451bb
- Marker: `cff_marker_s_text_canary_d8fba451bb` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?s=cff_marker_s_text_canary_d8fba451bb` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42826`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; marker reflected: cff_marker_s_text_canary_d8fba451bb; marker hits: 1; unique marker reflected: cff_marker_s_text_canary_d8fba451bb

### 18. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://pallife.co/readme.html?action=%27_cff_marker_action_sqli_probe_b5a45a8689`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_action_sqli_probe_b5a45a8689`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_action_sqli_probe_b5a45a8689` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 19. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://pallife.co/readme.html?author=1%22_cff_marker_author_sqli_probe_3841ce7d7e`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_3841ce7d7e`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_3841ce7d7e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 20. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://pallife.co/readme.html?author=1%27_cff_marker_author_sqli_probe_f53fc50571`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_f53fc50571`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_author_sqli_probe_f53fc50571` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 21. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://pallife.co/readme.html?cat=1%22_cff_marker_cat_sqli_probe_78eee18761`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_78eee18761`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_78eee18761` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 22. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://pallife.co/readme.html?cat=1%27_cff_marker_cat_sqli_probe_8045a3b8d1`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_8045a3b8d1`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_cat_sqli_probe_8045a3b8d1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 23. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://pallife.co/readme.html?log=%27_cff_marker_log_sqli_probe_a1b7d34baa`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_log_sqli_probe_a1b7d34baa`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_log_sqli_probe_a1b7d34baa` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 24. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://pallife.co/readme.html?nonce=%27_cff_marker_nonce_sqli_probe_54dcd896b7`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_nonce_sqli_probe_54dcd896b7`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_nonce_sqli_probe_54dcd896b7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 25. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://pallife.co/readme.html?p=1%22_cff_marker_p_sqli_probe_26547e6a9e`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_26547e6a9e`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_26547e6a9e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 26. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://pallife.co/readme.html?p=1%27_cff_marker_p_sqli_probe_938984265a`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_938984265a`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_p_sqli_probe_938984265a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 27. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://pallife.co/readme.html?page_id=1%22_cff_marker_page_id_sqli_probe_1e272aafe7`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_1e272aafe7`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_1e272aafe7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 28. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://pallife.co/readme.html?page_id=1%27_cff_marker_page_id_sqli_probe_07caed4c7a`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_07caed4c7a`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_id_sqli_probe_07caed4c7a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 29. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://pallife.co/readme.html?pwd=%27_cff_marker_pwd_sqli_probe_56642813a8`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_pwd_sqli_probe_56642813a8`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_pwd_sqli_probe_56642813a8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 30. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://pallife.co/readme.html?s=%27_cff_marker_s_sqli_probe_43bd06c46e`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_43bd06c46e`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_s_sqli_probe_43bd06c46e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 31. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://pallife.co/readme.html?search=%27_cff_marker_search_sqli_probe_0179d2fd28`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_0179d2fd28`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_search_sqli_probe_0179d2fd28` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 32. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://pallife.co/wp-admin/?redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_616b467503`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_to_redirect_probe_616b467503`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_redirect_to_redirect_probe_616b467503` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 33. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://pallife.co/wp-admin/?redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_7c151216a8`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_to_redirect_probe_7c151216a8`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_redirect_to_redirect_probe_7c151216a8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 34. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?action=cff_marker_action_action_canary_c8fcd52b04`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_c8fcd52b04`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_action_action_canary_c8fcd52b04` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 35. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?action=invalid_action_cff_marker_action_text_canary_809a902814`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action_cff_marker_action_text_canary_809a902814`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_action_text_canary_809a902814` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 36. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?author=-1_cff_marker_author_numeric_boundary_16b867f456`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_16b867f456`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_author_numeric_boundary_16b867f456` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 37. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?author=0_cff_marker_author_numeric_boundary_7e5d77f8a0`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_7e5d77f8a0`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_author_numeric_boundary_7e5d77f8a0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 38. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?author=1_cff_marker_author_numeric_boundary_cbdad57bb5`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_cbdad57bb5`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_author_numeric_boundary_cbdad57bb5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 39. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?author=999999_cff_marker_author_numeric_boundary_d4b4cba72d`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_d4b4cba72d`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_author_numeric_boundary_d4b4cba72d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 40. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?cat=-1_cff_marker_cat_numeric_boundary_fab1c92625`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_fab1c92625`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_cat_numeric_boundary_fab1c92625` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 41. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?cat=0_cff_marker_cat_numeric_boundary_003f6d1e79`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_003f6d1e79`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_cat_numeric_boundary_003f6d1e79` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 42. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?cat=1_cff_marker_cat_numeric_boundary_83d932030a`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_83d932030a`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_cat_numeric_boundary_83d932030a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 43. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?cat=999999_cff_marker_cat_numeric_boundary_04c9000eb7`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_04c9000eb7`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_cat_numeric_boundary_04c9000eb7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 44. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?log=%3Ccff_marker_log_xss_reflection_probe_56eddb7d24%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_log_xss_reflection_probe_56eddb7d24&gt;`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_log_xss_reflection_probe_56eddb7d24` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 45. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?log=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_log_xss_trigger_probe_99a204e094%27%29%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_log_xss_trigger_probe_99a204e094&#x27;)&gt;`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_log_xss_trigger_probe_99a204e094` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 46. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?log=%3Cscript%3Ealert%28%27cff_marker_log_xss_trigger_probe_d5d0032257%27%29%3C%2Fscript%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_log_xss_trigger_probe_d5d0032257&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_log_xss_trigger_probe_d5d0032257` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 47. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?log=cff_marker_log_text_canary_d55f73995b`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_log_text_canary_d55f73995b`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_log_text_canary_d55f73995b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 48. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?nonce=12345_cff_marker_nonce_generic_number_df67d7895d`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_nonce_generic_number_df67d7895d`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_nonce_generic_number_df67d7895d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 49. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?nonce=cff_marker_nonce_generic_canary_6f5d8b8681`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_nonce_generic_canary_6f5d8b8681`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_nonce_generic_canary_6f5d8b8681` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 50. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?nonce=true_cff_marker_nonce_generic_bool_6e72c4969d`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_nonce_generic_bool_6e72c4969d`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_nonce_generic_bool_6e72c4969d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 51. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?p=-1_cff_marker_p_numeric_boundary_e53a0c2058`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_e53a0c2058`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_p_numeric_boundary_e53a0c2058` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 52. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?p=0_cff_marker_p_numeric_boundary_fa30fbfe90`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_fa30fbfe90`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_p_numeric_boundary_fa30fbfe90` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 53. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?p=1_cff_marker_p_numeric_boundary_4a01fa1ade`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_4a01fa1ade`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_p_numeric_boundary_4a01fa1ade` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 54. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?p=999999_cff_marker_p_numeric_boundary_2de9b7bd08`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_2de9b7bd08`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_p_numeric_boundary_2de9b7bd08` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 55. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?page_id=-1_cff_marker_page_id_numeric_boundary_ed1cf1f13f`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_ed1cf1f13f`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_id_numeric_boundary_ed1cf1f13f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 56. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?page_id=0_cff_marker_page_id_numeric_boundary_61cc6daf79`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_61cc6daf79`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_id_numeric_boundary_61cc6daf79` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 57. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?page_id=1_cff_marker_page_id_numeric_boundary_12ed60e6a0`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_12ed60e6a0`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_id_numeric_boundary_12ed60e6a0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 58. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?page_id=999999_cff_marker_page_id_numeric_boundary_f5c417720a`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_f5c417720a`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_id_numeric_boundary_f5c417720a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 59. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?pwd=12345_cff_marker_pwd_generic_number_0db52fb708`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_pwd_generic_number_0db52fb708`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_pwd_generic_number_0db52fb708` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 60. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?pwd=cff_marker_pwd_generic_canary_0b312b1b9a`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_pwd_generic_canary_0b312b1b9a`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_pwd_generic_canary_0b312b1b9a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 61. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?pwd=true_cff_marker_pwd_generic_bool_bdda9bb3ad`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_pwd_generic_bool_bdda9bb3ad`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_pwd_generic_bool_bdda9bb3ad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 62. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_6476398804`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_to_redirect_probe_6476398804`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_to_redirect_probe_6476398804` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 63. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_b39fe6bee8`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_to_redirect_probe_b39fe6bee8`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_to_redirect_probe_b39fe6bee8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 64. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?s=%3Ccff_marker_s_xss_reflection_probe_27c5130e41%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_27c5130e41&gt;`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_s_xss_reflection_probe_27c5130e41` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 65. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?s=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_s_xss_trigger_probe_d388299922%27%29%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_s_xss_trigger_probe_d388299922&#x27;)&gt;`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_s_xss_trigger_probe_d388299922` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 66. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?s=%3Cscript%3Ealert%28%27cff_marker_s_xss_trigger_probe_47d2429880%27%29%3C%2Fscript%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_s_xss_trigger_probe_47d2429880&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_s_xss_trigger_probe_47d2429880` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 67. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?s=cff_marker_s_text_canary_5f41c2140f`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_5f41c2140f`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_s_text_canary_5f41c2140f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 68. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?search=%3Ccff_marker_search_xss_reflection_probe_2838fb87ee%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_2838fb87ee&gt;`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_reflection_probe_2838fb87ee` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 69. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_175067a47c%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_175067a47c&#x27;)&gt;`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_175067a47c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 70. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_96e50d565c%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_96e50d565c&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_96e50d565c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 71. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://pallife.co/license.txt?search=cff_marker_search_text_canary_8969e4012a`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_8969e4012a`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_text_canary_8969e4012a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 72. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?action=%27_cff_marker_action_sqli_probe_9e6b642f27`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_action_sqli_probe_9e6b642f27`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_action_sqli_probe_9e6b642f27` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 73. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?action=cff_marker_action_action_canary_8673c4ca22`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_8673c4ca22`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_action_action_canary_8673c4ca22` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 74. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?action=invalid_action_cff_marker_action_text_canary_792e34f3b7`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action_cff_marker_action_text_canary_792e34f3b7`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_action_text_canary_792e34f3b7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 75. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?author=-1_cff_marker_author_numeric_boundary_28d5b4cf44`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_28d5b4cf44`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_28d5b4cf44` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 76. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?author=0_cff_marker_author_numeric_boundary_d67f5bacd7`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_d67f5bacd7`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_d67f5bacd7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 77. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?author=1%22_cff_marker_author_sqli_probe_294e61ffaf`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_294e61ffaf`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_sqli_probe_294e61ffaf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 78. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?author=1%27_cff_marker_author_sqli_probe_12528ff304`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_12528ff304`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_sqli_probe_12528ff304` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 79. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?author=1_cff_marker_author_numeric_boundary_557b0dc8ec`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_557b0dc8ec`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_557b0dc8ec` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 80. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?author=999999_cff_marker_author_numeric_boundary_ba5b3fffbc`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_ba5b3fffbc`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_ba5b3fffbc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 81. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?cat=-1_cff_marker_cat_numeric_boundary_4d9429f4a2`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_4d9429f4a2`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_4d9429f4a2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 82. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?cat=0_cff_marker_cat_numeric_boundary_54d2ce0f33`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_54d2ce0f33`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_54d2ce0f33` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 83. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?cat=1%22_cff_marker_cat_sqli_probe_77d708f386`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_77d708f386`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_sqli_probe_77d708f386` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 84. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?cat=1%27_cff_marker_cat_sqli_probe_e9bce30f8b`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_e9bce30f8b`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_sqli_probe_e9bce30f8b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 85. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?cat=1_cff_marker_cat_numeric_boundary_71039bc3b8`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_71039bc3b8`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_71039bc3b8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 86. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?cat=999999_cff_marker_cat_numeric_boundary_cb3843fb28`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_cb3843fb28`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_cb3843fb28` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 87. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?log=%27_cff_marker_log_sqli_probe_85aec1b4cb`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_log_sqli_probe_85aec1b4cb`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_log_sqli_probe_85aec1b4cb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 88. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?log=%3Ccff_marker_log_xss_reflection_probe_b0f42c9e51%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_log_xss_reflection_probe_b0f42c9e51&gt;`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_b0f42c9e51` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 89. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?log=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_log_xss_trigger_probe_e0494fc975%27%29%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_log_xss_trigger_probe_e0494fc975&#x27;)&gt;`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_e0494fc975` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 90. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?log=%3Cscript%3Ealert%28%27cff_marker_log_xss_trigger_probe_fb5bfffde1%27%29%3C%2Fscript%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_log_xss_trigger_probe_fb5bfffde1&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_fb5bfffde1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 91. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?log=cff_marker_log_text_canary_7bad2d0007`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_log_text_canary_7bad2d0007`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_log_text_canary_7bad2d0007` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 92. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?nonce=%27_cff_marker_nonce_sqli_probe_6b66a61a68`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_nonce_sqli_probe_6b66a61a68`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_nonce_sqli_probe_6b66a61a68` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 93. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?nonce=12345_cff_marker_nonce_generic_number_a4b7790171`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_nonce_generic_number_a4b7790171`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_nonce_generic_number_a4b7790171` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 94. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?nonce=cff_marker_nonce_generic_canary_150918ec1b`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_nonce_generic_canary_150918ec1b`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_nonce_generic_canary_150918ec1b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 95. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?nonce=true_cff_marker_nonce_generic_bool_f623f5fd78`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_nonce_generic_bool_f623f5fd78`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_nonce_generic_bool_f623f5fd78` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 96. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?p=-1_cff_marker_p_numeric_boundary_3e1890f387`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_3e1890f387`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_3e1890f387` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 97. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?p=0_cff_marker_p_numeric_boundary_8ff806c76a`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_8ff806c76a`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_8ff806c76a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 98. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?p=1%22_cff_marker_p_sqli_probe_21a9dab8e0`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_21a9dab8e0`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_sqli_probe_21a9dab8e0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 99. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?p=1%27_cff_marker_p_sqli_probe_1ce667b984`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_1ce667b984`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_sqli_probe_1ce667b984` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 100. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?p=1_cff_marker_p_numeric_boundary_b7da160a52`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_b7da160a52`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_b7da160a52` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 101. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?p=999999_cff_marker_p_numeric_boundary_bb9ab7cb9b`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_bb9ab7cb9b`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_bb9ab7cb9b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 102. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?page_id=-1_cff_marker_page_id_numeric_boundary_1090e68e7a`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_1090e68e7a`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_1090e68e7a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 103. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?page_id=0_cff_marker_page_id_numeric_boundary_68e3af8c18`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_68e3af8c18`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_68e3af8c18` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 104. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?page_id=1%22_cff_marker_page_id_sqli_probe_e3a0c58b25`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_e3a0c58b25`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_sqli_probe_e3a0c58b25` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 105. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?page_id=1%27_cff_marker_page_id_sqli_probe_e3820dcdad`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_e3820dcdad`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_sqli_probe_e3820dcdad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 106. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?page_id=1_cff_marker_page_id_numeric_boundary_155ac6b044`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_155ac6b044`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_155ac6b044` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 107. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?page_id=999999_cff_marker_page_id_numeric_boundary_dc1428e8f1`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_dc1428e8f1`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_dc1428e8f1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 108. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?pwd=%27_cff_marker_pwd_sqli_probe_7e8508084f`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_pwd_sqli_probe_7e8508084f`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_pwd_sqli_probe_7e8508084f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 109. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?pwd=12345_cff_marker_pwd_generic_number_bd9672693f`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_pwd_generic_number_bd9672693f`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_pwd_generic_number_bd9672693f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 110. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?pwd=cff_marker_pwd_generic_canary_3081402ce0`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_pwd_generic_canary_3081402ce0`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_pwd_generic_canary_3081402ce0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 111. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?pwd=true_cff_marker_pwd_generic_bool_ef82f0a4bc`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_pwd_generic_bool_ef82f0a4bc`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_pwd_generic_bool_ef82f0a4bc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 112. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_57290aed1e`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_to_redirect_probe_57290aed1e`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_57290aed1e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 113. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_3b34d2377c`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_to_redirect_probe_3b34d2377c`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_3b34d2377c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 114. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?s=%27_cff_marker_s_sqli_probe_8fbd818310`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_8fbd818310`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_sqli_probe_8fbd818310` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 115. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?s=%3Ccff_marker_s_xss_reflection_probe_6678f9df81%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_6678f9df81&gt;`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_6678f9df81` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 116. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?s=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_s_xss_trigger_probe_1ef8ee4217%27%29%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_s_xss_trigger_probe_1ef8ee4217&#x27;)&gt;`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_1ef8ee4217` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 117. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?s=%3Cscript%3Ealert%28%27cff_marker_s_xss_trigger_probe_dee4f3feb7%27%29%3C%2Fscript%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_s_xss_trigger_probe_dee4f3feb7&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_dee4f3feb7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 118. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?s=cff_marker_s_text_canary_92db46ad74`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_92db46ad74`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_text_canary_92db46ad74` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 119. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?search=%27_cff_marker_search_sqli_probe_ba03adfe3f`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_ba03adfe3f`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_ba03adfe3f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 120. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?search=%3Ccff_marker_search_xss_reflection_probe_041b74e674%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_041b74e674&gt;`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_041b74e674` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 121. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_5490791cbd%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_5490791cbd&#x27;)&gt;`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_5490791cbd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 122. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_ad956293db%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_ad956293db&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_ad956293db` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 123. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/admin.php?search=cff_marker_search_text_canary_96659dc892`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_96659dc892`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_text_canary_96659dc892` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 124. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/license.txt?action=%27_cff_marker_action_sqli_probe_5ebcbca955`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_action_sqli_probe_5ebcbca955`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_action_sqli_probe_5ebcbca955` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 125. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/license.txt?author=1%22_cff_marker_author_sqli_probe_2b7531dc4b`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_2b7531dc4b`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_sqli_probe_2b7531dc4b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 126. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/license.txt?author=1%27_cff_marker_author_sqli_probe_707d8eaf79`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_707d8eaf79`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_sqli_probe_707d8eaf79` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 127. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/license.txt?cat=1%22_cff_marker_cat_sqli_probe_18b28666df`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_18b28666df`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_sqli_probe_18b28666df` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 128. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/license.txt?cat=1%27_cff_marker_cat_sqli_probe_32f1486bee`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_32f1486bee`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_sqli_probe_32f1486bee` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 129. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/license.txt?log=%27_cff_marker_log_sqli_probe_eb55e45a58`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_log_sqli_probe_eb55e45a58`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_log_sqli_probe_eb55e45a58` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 130. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/license.txt?nonce=%27_cff_marker_nonce_sqli_probe_e01dc602ec`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_nonce_sqli_probe_e01dc602ec`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_nonce_sqli_probe_e01dc602ec` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 131. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/license.txt?p=1%22_cff_marker_p_sqli_probe_ee06111bd2`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_ee06111bd2`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_sqli_probe_ee06111bd2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 132. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/license.txt?p=1%27_cff_marker_p_sqli_probe_8682f4a75e`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_8682f4a75e`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_sqli_probe_8682f4a75e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 133. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/license.txt?page_id=1%22_cff_marker_page_id_sqli_probe_f5a517a452`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_f5a517a452`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_sqli_probe_f5a517a452` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 134. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/license.txt?page_id=1%27_cff_marker_page_id_sqli_probe_f8e354f343`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_f8e354f343`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_sqli_probe_f8e354f343` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 135. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/license.txt?pwd=%27_cff_marker_pwd_sqli_probe_7403fa9149`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_pwd_sqli_probe_7403fa9149`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_pwd_sqli_probe_7403fa9149` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 136. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/license.txt?s=%27_cff_marker_s_sqli_probe_542b4ab25f`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_542b4ab25f`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_sqli_probe_542b4ab25f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 137. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/license.txt?search=%27_cff_marker_search_sqli_probe_1566c42624`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_1566c42624`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_1566c42624` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 138. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?action=cff_marker_action_action_canary_fb5d249ba5`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_fb5d249ba5`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_action_action_canary_fb5d249ba5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 139. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?action=invalid_action_cff_marker_action_text_canary_4386e86e1e`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action_cff_marker_action_text_canary_4386e86e1e`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_action_text_canary_4386e86e1e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 140. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?author=-1_cff_marker_author_numeric_boundary_5a169a4a77`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_5a169a4a77`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_5a169a4a77` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 141. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?author=0_cff_marker_author_numeric_boundary_cb59920560`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_cb59920560`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_cb59920560` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 142. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?author=1_cff_marker_author_numeric_boundary_7293ea8614`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_7293ea8614`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_7293ea8614` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 143. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?author=999999_cff_marker_author_numeric_boundary_ffbd772420`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_ffbd772420`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_ffbd772420` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 144. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?cat=-1_cff_marker_cat_numeric_boundary_da6872161f`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_da6872161f`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_da6872161f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 145. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?cat=0_cff_marker_cat_numeric_boundary_b26ebf2416`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_b26ebf2416`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_b26ebf2416` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 146. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?cat=1_cff_marker_cat_numeric_boundary_0e89415432`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_0e89415432`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_0e89415432` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 147. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?cat=999999_cff_marker_cat_numeric_boundary_9c43651587`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_9c43651587`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_9c43651587` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 148. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?log=%3Ccff_marker_log_xss_reflection_probe_cbc340e7e6%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_log_xss_reflection_probe_cbc340e7e6&gt;`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_cbc340e7e6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 149. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?log=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_log_xss_trigger_probe_d9669feaf1%27%29%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_log_xss_trigger_probe_d9669feaf1&#x27;)&gt;`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_d9669feaf1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 150. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?log=%3Cscript%3Ealert%28%27cff_marker_log_xss_trigger_probe_6bdb121f2b%27%29%3C%2Fscript%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_log_xss_trigger_probe_6bdb121f2b&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_log_xss_trigger_probe_6bdb121f2b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 151. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?log=cff_marker_log_text_canary_00d8f2bb31`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_log_text_canary_00d8f2bb31`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_log_text_canary_00d8f2bb31` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 152. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?nonce=12345_cff_marker_nonce_generic_number_534ca99bc9`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_nonce_generic_number_534ca99bc9`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_nonce_generic_number_534ca99bc9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 153. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?nonce=cff_marker_nonce_generic_canary_694b187937`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_nonce_generic_canary_694b187937`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_nonce_generic_canary_694b187937` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 154. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?nonce=true_cff_marker_nonce_generic_bool_1b50661831`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_nonce_generic_bool_1b50661831`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_nonce_generic_bool_1b50661831` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 155. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?p=-1_cff_marker_p_numeric_boundary_3ca31d04f8`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_3ca31d04f8`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_3ca31d04f8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 156. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?p=0_cff_marker_p_numeric_boundary_2819a17315`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_2819a17315`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_2819a17315` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 157. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?p=1_cff_marker_p_numeric_boundary_f540c05f3c`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_f540c05f3c`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_f540c05f3c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 158. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?p=999999_cff_marker_p_numeric_boundary_5751d92ba6`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_5751d92ba6`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_5751d92ba6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 159. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?page_id=-1_cff_marker_page_id_numeric_boundary_0c6c7aeac5`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_0c6c7aeac5`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_0c6c7aeac5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 160. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?page_id=0_cff_marker_page_id_numeric_boundary_a8da2495ba`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_a8da2495ba`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_a8da2495ba` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 161. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?page_id=1_cff_marker_page_id_numeric_boundary_e3d4dcb5aa`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_e3d4dcb5aa`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_e3d4dcb5aa` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 162. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?page_id=999999_cff_marker_page_id_numeric_boundary_c610ea7005`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_c610ea7005`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_c610ea7005` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 163. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?pwd=12345_cff_marker_pwd_generic_number_922a7d3137`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_pwd_generic_number_922a7d3137`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_pwd_generic_number_922a7d3137` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 164. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?pwd=cff_marker_pwd_generic_canary_ec5d5f4201`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_pwd_generic_canary_ec5d5f4201`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_pwd_generic_canary_ec5d5f4201` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 165. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?pwd=true_cff_marker_pwd_generic_bool_1a8636b0f3`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_pwd_generic_bool_1a8636b0f3`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_pwd_generic_bool_1a8636b0f3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 166. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?redirect_to=%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_31f4834c7e`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_to_redirect_probe_31f4834c7e`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_31f4834c7e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 167. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?redirect_to=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_to_redirect_probe_beae197c66`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_to_redirect_probe_beae197c66`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_redirect_to_redirect_probe_beae197c66` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 168. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?s=%3Ccff_marker_s_xss_reflection_probe_c3e7a15da0%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_c3e7a15da0&gt;`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_c3e7a15da0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 169. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?s=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_s_xss_trigger_probe_31dd0c413f%27%29%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_s_xss_trigger_probe_31dd0c413f&#x27;)&gt;`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_31dd0c413f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 170. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?s=%3Cscript%3Ealert%28%27cff_marker_s_xss_trigger_probe_652d38b777%27%29%3C%2Fscript%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_s_xss_trigger_probe_652d38b777&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_xss_trigger_probe_652d38b777` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 171. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?s=cff_marker_s_text_canary_6873a459e5`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_6873a459e5`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_text_canary_6873a459e5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 172. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?search=%3Ccff_marker_search_xss_reflection_probe_f390aaf2fc%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_f390aaf2fc&gt;`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_f390aaf2fc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 173. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_949f6330f2%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_949f6330f2&#x27;)&gt;`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_949f6330f2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 174. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_ab96cf6e14%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_ab96cf6e14&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_ab96cf6e14` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 175. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/readme.html?search=cff_marker_search_text_canary_020749c01c`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_020749c01c`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_text_canary_020749c01c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 176. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?author=1_cff_marker_author_numeric_boundary_c439eacad0`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_c439eacad0`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_c439eacad0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 177. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?cat=-1_cff_marker_cat_numeric_boundary_4942df4ded`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_4942df4ded`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_4942df4ded` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 178. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?cat=0_cff_marker_cat_numeric_boundary_620eaf6363`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_620eaf6363`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_620eaf6363` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 179. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?cat=1%22_cff_marker_cat_sqli_probe_84c3860513`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_84c3860513`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_sqli_probe_84c3860513` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 180. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?cat=1%27_cff_marker_cat_sqli_probe_e810185bc7`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_e810185bc7`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_sqli_probe_e810185bc7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 181. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?cat=1_cff_marker_cat_numeric_boundary_2bac610c84`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_2bac610c84`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_2bac610c84` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 182. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?cat=999999_cff_marker_cat_numeric_boundary_d84403c716`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_d84403c716`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_d84403c716` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 183. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?p=-1_cff_marker_p_numeric_boundary_e55ecf4372`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_e55ecf4372`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_e55ecf4372` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 184. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?p=0_cff_marker_p_numeric_boundary_50a48dca4f`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_50a48dca4f`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_50a48dca4f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 185. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?p=1%22_cff_marker_p_sqli_probe_4a08402850`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_4a08402850`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_sqli_probe_4a08402850` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 186. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?p=1%27_cff_marker_p_sqli_probe_c088b6515e`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_c088b6515e`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_sqli_probe_c088b6515e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 187. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?p=1_cff_marker_p_numeric_boundary_e37bca005a`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_e37bca005a`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_e37bca005a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 188. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?p=999999_cff_marker_p_numeric_boundary_dc8c650742`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_dc8c650742`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_dc8c650742` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 189. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?page_id=-1_cff_marker_page_id_numeric_boundary_96d918c5ea`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_96d918c5ea`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_96d918c5ea` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 190. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?page_id=0_cff_marker_page_id_numeric_boundary_d517c41677`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_d517c41677`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_d517c41677` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 191. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?page_id=1%22_cff_marker_page_id_sqli_probe_5f2fe1a895`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_5f2fe1a895`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_sqli_probe_5f2fe1a895` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 192. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?page_id=1%27_cff_marker_page_id_sqli_probe_8fd091143b`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_8fd091143b`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_sqli_probe_8fd091143b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 193. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?page_id=1_cff_marker_page_id_numeric_boundary_7efb7e7f4a`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_7efb7e7f4a`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_7efb7e7f4a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 194. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?page_id=999999_cff_marker_page_id_numeric_boundary_c2591b107f`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_c2591b107f`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_c2591b107f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 195. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?s=%27_cff_marker_s_sqli_probe_3829f02845`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_3829f02845`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_sqli_probe_3829f02845` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 196. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?s=%3Ccff_marker_s_xss_reflection_probe_288d038a9b%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_288d038a9b&gt;`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_288d038a9b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 197. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?s=cff_marker_s_text_canary_b2a6075d67`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_b2a6075d67`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_text_canary_b2a6075d67` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 198. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?search=%27_cff_marker_search_sqli_probe_46396cfdcd`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_46396cfdcd`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_46396cfdcd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 199. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?search=%3Ccff_marker_search_xss_reflection_probe_5ae920da97%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_5ae920da97&gt;`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_5ae920da97` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 200. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-login.php?search=cff_marker_search_text_canary_36e8427b8f`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_36e8427b8f`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_text_canary_36e8427b8f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 201. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?action=%27_cff_marker_action_sqli_probe_7d77a6883c`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_action_sqli_probe_7d77a6883c`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_action_sqli_probe_7d77a6883c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 202. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?action=cff_marker_action_action_canary_0635cf29c5`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_marker_action_action_canary_0635cf29c5`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_action_action_canary_0635cf29c5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 203. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?action=invalid_action_cff_marker_action_text_canary_e4483337d8`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action_cff_marker_action_text_canary_e4483337d8`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_action_text_canary_e4483337d8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 204. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?author=-1_cff_marker_author_numeric_boundary_1282466987`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_author_numeric_boundary_1282466987`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_1282466987` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 205. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?author=0_cff_marker_author_numeric_boundary_6b7d5e0c4e`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_author_numeric_boundary_6b7d5e0c4e`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_6b7d5e0c4e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 206. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?author=1%22_cff_marker_author_sqli_probe_c7c5657b1d`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_author_sqli_probe_c7c5657b1d`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_sqli_probe_c7c5657b1d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 207. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?author=1%27_cff_marker_author_sqli_probe_f6d57d23fe`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_author_sqli_probe_f6d57d23fe`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_sqli_probe_f6d57d23fe` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 208. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?author=1_cff_marker_author_numeric_boundary_37c6013652`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_author_numeric_boundary_37c6013652`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_37c6013652` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 209. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?author=999999_cff_marker_author_numeric_boundary_ff4fe2ba15`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_author_numeric_boundary_ff4fe2ba15`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_author_numeric_boundary_ff4fe2ba15` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 210. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?cat=-1_cff_marker_cat_numeric_boundary_bcfb17f5a8`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_bcfb17f5a8`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_bcfb17f5a8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 211. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?cat=0_cff_marker_cat_numeric_boundary_6cd5d0d87d`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_cat_numeric_boundary_6cd5d0d87d`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_6cd5d0d87d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 212. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?cat=1%22_cff_marker_cat_sqli_probe_55b37d2a0e`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_cat_sqli_probe_55b37d2a0e`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_sqli_probe_55b37d2a0e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 213. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?cat=1%27_cff_marker_cat_sqli_probe_ce9c5c9dad`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_cat_sqli_probe_ce9c5c9dad`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_sqli_probe_ce9c5c9dad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 214. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?cat=1_cff_marker_cat_numeric_boundary_5fddb10b7e`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_cat_numeric_boundary_5fddb10b7e`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_5fddb10b7e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 215. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?cat=999999_cff_marker_cat_numeric_boundary_65f7b8c5b5`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_cat_numeric_boundary_65f7b8c5b5`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_65f7b8c5b5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 216. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?log=%27_cff_marker_log_sqli_probe_ede779c08b`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_log_sqli_probe_ede779c08b`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_log_sqli_probe_ede779c08b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 217. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?log=%3Ccff_marker_log_xss_reflection_probe_df0f5198a2%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_log_xss_reflection_probe_df0f5198a2&gt;`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_df0f5198a2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 218. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?log=cff_marker_log_text_canary_02acaa9edf`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_log_text_canary_02acaa9edf`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_log_text_canary_02acaa9edf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 219. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?nonce=%27_cff_marker_nonce_sqli_probe_3fd6a19895`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_nonce_sqli_probe_3fd6a19895`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_nonce_sqli_probe_3fd6a19895` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 220. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?nonce=12345_cff_marker_nonce_generic_number_ab044ae680`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_nonce_generic_number_ab044ae680`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_nonce_generic_number_ab044ae680` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 221. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?nonce=cff_marker_nonce_generic_canary_2279da7700`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_nonce_generic_canary_2279da7700`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_nonce_generic_canary_2279da7700` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 222. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?nonce=true_cff_marker_nonce_generic_bool_f68f01673b`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_nonce_generic_bool_f68f01673b`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_nonce_generic_bool_f68f01673b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 223. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?p=-1_cff_marker_p_numeric_boundary_3bb8e8b7a2`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_3bb8e8b7a2`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_3bb8e8b7a2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 224. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?p=0_cff_marker_p_numeric_boundary_649b137b61`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_649b137b61`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_649b137b61` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 225. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?p=1%22_cff_marker_p_sqli_probe_a29ec79c09`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_p_sqli_probe_a29ec79c09`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_sqli_probe_a29ec79c09` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 226. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?p=1%27_cff_marker_p_sqli_probe_94d59cdd3f`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_p_sqli_probe_94d59cdd3f`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_sqli_probe_94d59cdd3f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 227. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?p=1_cff_marker_p_numeric_boundary_11eba6c51d`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_p_numeric_boundary_11eba6c51d`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_11eba6c51d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 228. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?p=999999_cff_marker_p_numeric_boundary_86a113b6ea`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_p_numeric_boundary_86a113b6ea`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_86a113b6ea` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 229. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?page_id=-1_cff_marker_page_id_numeric_boundary_db1fea3af1`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_id_numeric_boundary_db1fea3af1`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_db1fea3af1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 230. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?page_id=0_cff_marker_page_id_numeric_boundary_bf68a336d6`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_bf68a336d6`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_bf68a336d6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 231. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?page_id=1%22_cff_marker_page_id_sqli_probe_7b54e7fa73`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_id_sqli_probe_7b54e7fa73`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_sqli_probe_7b54e7fa73` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 232. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?page_id=1%27_cff_marker_page_id_sqli_probe_bca0068e8f`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_id_sqli_probe_bca0068e8f`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_sqli_probe_bca0068e8f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 233. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?page_id=1_cff_marker_page_id_numeric_boundary_d88fe5a821`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_id_numeric_boundary_d88fe5a821`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_d88fe5a821` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 234. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?page_id=999999_cff_marker_page_id_numeric_boundary_85de555bb7`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_id_numeric_boundary_85de555bb7`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_85de555bb7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 235. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?pwd=%27_cff_marker_pwd_sqli_probe_3e90bf54d4`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_pwd_sqli_probe_3e90bf54d4`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_pwd_sqli_probe_3e90bf54d4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 236. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?pwd=12345_cff_marker_pwd_generic_number_43b27cc25e`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345_cff_marker_pwd_generic_number_43b27cc25e`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_pwd_generic_number_43b27cc25e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 237. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?pwd=cff_marker_pwd_generic_canary_36ec4f1cd4`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_marker_pwd_generic_canary_36ec4f1cd4`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_pwd_generic_canary_36ec4f1cd4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 238. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?pwd=true_cff_marker_pwd_generic_bool_b80788f180`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true_cff_marker_pwd_generic_bool_b80788f180`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_pwd_generic_bool_b80788f180` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 239. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?s=%27_cff_marker_s_sqli_probe_765251535e`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_s_sqli_probe_765251535e`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_sqli_probe_765251535e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 240. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?s=%3Ccff_marker_s_xss_reflection_probe_95b94aaff8%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_95b94aaff8&gt;`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_xss_reflection_probe_95b94aaff8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 241. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?s=cff_marker_s_text_canary_aad720b230`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_aad720b230`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_s_text_canary_aad720b230` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 242. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?search=%27_cff_marker_search_sqli_probe_4077a01069`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_4077a01069`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_4077a01069` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 243. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?search=%3Ccff_marker_search_xss_reflection_probe_06c5e2d53c%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_06c5e2d53c&gt;`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_06c5e2d53c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 244. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/wp-admin/?search=cff_marker_search_text_canary_362cc2506b`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_362cc2506b`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_text_canary_362cc2506b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 245. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?cat=-1_cff_marker_cat_numeric_boundary_f7b4f3822e`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_f7b4f3822e`
- Response: HTTP `200` / Length `46917` / Type `text/html; charset=UTF-8`
- Title: pallife
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_f7b4f3822e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46917`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 246. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?log=%3Ccff_marker_log_xss_reflection_probe_f2325a3e63%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_log_xss_reflection_probe_f2325a3e63&gt;`
- Response: HTTP `200` / Length `91834` / Type `text/html; charset=UTF-8`
- Title: pallife – Just another WordPress site
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_log_xss_reflection_probe_f2325a3e63` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `91834`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 247. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?p=-1_cff_marker_p_numeric_boundary_350a305feb`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_350a305feb`
- Response: HTTP `200` / Length `46733` / Type `text/html; charset=UTF-8`
- Title: Page not found – pallife
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_350a305feb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46733`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 248. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?p=0_cff_marker_p_numeric_boundary_05a1b07943`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_05a1b07943`
- Response: HTTP `200` / Length `46917` / Type `text/html; charset=UTF-8`
- Title: pallife
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_05a1b07943` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46917`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 249. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?search=%27_cff_marker_search_sqli_probe_063cbc88df`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_063cbc88df`
- Response: HTTP `200` / Length `46917` / Type `text/html; charset=UTF-8`
- Title: pallife
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_063cbc88df` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46917`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 250. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?search=%3Ccff_marker_search_xss_reflection_probe_608a38e3e0%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_608a38e3e0&gt;`
- Response: HTTP `200` / Length `46917` / Type `text/html; charset=UTF-8`
- Title: pallife
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_608a38e3e0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46917`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 251. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?search=cff_marker_search_text_canary_25326ada55`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_25326ada55`
- Response: HTTP `200` / Length `46917` / Type `text/html; charset=UTF-8`
- Title: pallife
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_text_canary_25326ada55` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46917`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 252. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/admin.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 253. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/license.txt`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `19903`
  - Content-Type: `text/plain`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 254. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/readme.html`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7406`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 255. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/admin-footer.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 256. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/admin-functions.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 257. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/admin-header.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 258. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/admin-post.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 259. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/color-picker-rtl.css`
- Response: HTTP `200` / Length `3957` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3957`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 260. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/color-picker-rtl.min.css`
- Response: HTTP `200` / Length `3201` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3201`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 261. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/color-picker.css`
- Response: HTTP `200` / Length `3919` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3919`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 262. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/color-picker.min.css`
- Response: HTTP `200` / Length `3198` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3198`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 263. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/customize-controls-rtl.css`
- Response: HTTP `200` / Length `72569` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `72569`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 264. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/customize-controls-rtl.min.css`
- Response: HTTP `200` / Length `60473` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `60473`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 265. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/customize-controls.css`
- Response: HTTP `200` / Length `72491` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `72491`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 266. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/customize-controls.min.css`
- Response: HTTP `200` / Length `60430` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `60430`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 267. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/dashboard-rtl.css`
- Response: HTTP `200` / Length `30439` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `30439`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 268. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/dashboard.css`
- Response: HTTP `200` / Length `30409` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `30409`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 269. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/farbtastic-rtl.css`
- Response: HTTP `200` / Length `647` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `647`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 270. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/farbtastic.css`
- Response: HTTP `200` / Length `611` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `611`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 271. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/install-rtl.css`
- Response: HTTP `200` / Length `6497` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6497`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 272. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/install.css`
- Response: HTTP `200` / Length `6464` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6464`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 273. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/install.min.css`
- Response: HTTP `200` / Length `5266` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `5266`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 274. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/login-rtl.css`
- Response: HTTP `200` / Length `8291` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `8291`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 275. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/login.css`
- Response: HTTP `200` / Length `8253` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `8253`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 276. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/media-rtl.css`
- Response: HTTP `200` / Length `28190` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `28190`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 277. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/media-rtl.min.css`
- Response: HTTP `200` / Length `22694` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `22694`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 278. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/media.css`
- Response: HTTP `200` / Length `28139` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `28139`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 279. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/media.min.css`
- Response: HTTP `200` / Length `22678` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `22678`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 280. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/widgets-rtl.css`
- Response: HTTP `200` / Length `17887` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `17887`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 281. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/widgets.css`
- Response: HTTP `200` / Length `17850` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `17850`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 282. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/wp-admin-rtl.css`
- Response: HTTP `200` / Length `490` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `490`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 283. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/wp-admin-rtl.min.css`
- Response: HTTP `200` / Length `550` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `550`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 284. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/wp-admin.css`
- Response: HTTP `200` / Length `395` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `395`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 285. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/wp-admin.min.css`
- Response: HTTP `200` / Length `490` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `490`
  - Content-Type: `text/css`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 286. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/custom-background.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 287. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/custom-header.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 288. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-form-advanced.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 289. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-form-comment.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 290. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-link-form.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 291. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-tag-form.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 292. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/align-center-2x.png`
- Response: HTTP `200` / Length `147` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `147`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 293. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/align-center.png`
- Response: HTTP `200` / Length `546` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `546`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 294. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/align-left-2x.png`
- Response: HTTP `200` / Length `143` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `143`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 295. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/align-left.png`
- Response: HTTP `200` / Length `554` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `554`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 296. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/align-none-2x.png`
- Response: HTTP `200` / Length `121` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `121`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 297. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/align-none.png`
- Response: HTTP `200` / Length `417` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `417`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 298. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/align-right-2x.png`
- Response: HTTP `200` / Length `142` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 299. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/align-right.png`
- Response: HTTP `200` / Length `509` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `509`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 300. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/arrows-2x.png`
- Response: HTTP `200` / Length `863` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `863`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 301. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/arrows.png`
- Response: HTTP `200` / Length `243` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `243`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 302. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/bubble_bg-2x.gif`
- Response: HTTP `200` / Length `424` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `424`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 303. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/bubble_bg.gif`
- Response: HTTP `200` / Length `398` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `398`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 304. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/comment-grey-bubble-2x.png`
- Response: HTTP `200` / Length `258` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `258`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 305. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/comment-grey-bubble.png`
- Response: HTTP `200` / Length `114` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `114`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 306. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/date-button-2x.gif`
- Response: HTTP `200` / Length `996` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `996`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 307. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/date-button.gif`
- Response: HTTP `200` / Length `400` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `400`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 308. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/generic.png`
- Response: HTTP `200` / Length `719` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `719`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 309. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/icons32-2x.png`
- Response: HTTP `200` / Length `21770` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `21770`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 310. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/icons32-vs-2x.png`
- Response: HTTP `200` / Length `21396` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `21396`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 311. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/icons32-vs.png`
- Response: HTTP `200` / Length `8007` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `8007`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 312. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/icons32.png`
- Response: HTTP `200` / Length `8023` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `8023`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 313. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/imgedit-icons-2x.png`
- Response: HTTP `200` / Length `7664` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `7664`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 314. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/imgedit-icons.png`
- Response: HTTP `200` / Length `4055` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4055`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 315. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/list-2x.png`
- Response: HTTP `200` / Length `1523` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1523`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 316. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/list.png`
- Response: HTTP `200` / Length `1003` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1003`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 317. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/loading.gif`
- Response: HTTP `200` / Length `1368` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1368`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 318. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/marker.png`
- Response: HTTP `200` / Length `360` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `360`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 319. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/mask.png`
- Response: HTTP `200` / Length `2001` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2001`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 320. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/media-button-2x.png`
- Response: HTTP `200` / Length `850` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `850`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 321. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/media-button-image.gif`
- Response: HTTP `200` / Length `200` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `200`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 322. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/media-button-music.gif`
- Response: HTTP `200` / Length `206` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `206`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 323. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/media-button-other.gif`
- Response: HTTP `200` / Length `248` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `248`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 324. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/media-button-video.gif`
- Response: HTTP `200` / Length `133` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `133`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 325. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/media-button.png`
- Response: HTTP `200` / Length `323` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `323`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 326. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/menu-2x.png`
- Response: HTTP `200` / Length `12672` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `12672`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 327. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/menu-vs-2x.png`
- Response: HTTP `200` / Length `12453` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `12453`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 328. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/menu-vs.png`
- Response: HTTP `200` / Length `5086` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `5086`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 329. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/menu.png`
- Response: HTTP `200` / Length `5039` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `5039`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 330. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/no.png`
- Response: HTTP `200` / Length `755` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `755`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 331. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/post-formats-vs.png`
- Response: HTTP `200` / Length `2450` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2450`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 332. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/post-formats.png`
- Response: HTTP `200` / Length `2157` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2157`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 333. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/post-formats32-vs.png`
- Response: HTTP `200` / Length `5111` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `5111`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 334. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/post-formats32.png`
- Response: HTTP `200` / Length `5142` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `5142`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 335. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/resize-2x.gif`
- Response: HTTP `200` / Length `151` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `151`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 336. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/resize-rtl-2x.gif`
- Response: HTTP `200` / Length `150` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `150`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 337. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/resize-rtl.gif`
- Response: HTTP `200` / Length `70` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `70`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 338. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/resize.gif`
- Response: HTTP `200` / Length `64` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `64`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 339. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/se.png`
- Response: HTTP `200` / Length `120` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `120`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 340. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/sort-2x.gif`
- Response: HTTP `200` / Length `97` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `97`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 341. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/sort.gif`
- Response: HTTP `200` / Length `55` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `55`
  - Content-Type: `image/gif`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 342. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/stars-2x.png`
- Response: HTTP `200` / Length `1257` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1257`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 343. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/stars.png`
- Response: HTTP `200` / Length `924` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `924`
  - Content-Type: `image/png`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 344. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-json/`
- Response: HTTP `200` / Length `229394` / Type `application/json; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; API-like endpoint
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `229394`
  - Content-Type: `application/json; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; API-like endpoint

### 345. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-json/wp/v2/posts`
- Response: HTTP `200` / Length `13202` / Type `application/json; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; API-like endpoint
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `13202`
  - Content-Type: `application/json; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; API-like endpoint

### 346. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-login.php`
- Response: HTTP `200` / Length `6372` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ pallife — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6372`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 347. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?page_id=0_cff_marker_page_id_numeric_boundary_7bcaeaeada`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_7bcaeaeada`
- Response: HTTP `301` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=301; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_7bcaeaeada` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=301; different from 404 baseline; length delta; parameter changed response shape

### 348. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/login.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 349. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 350. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/about.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 351. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/admin-db.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 352. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/admin.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 353. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/async-upload.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 354. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/bookmarklet.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 355. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/cat.js`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 356. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/categories.js`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 357. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/categories.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 358. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/comment.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 359. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/credits.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 360. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/colors-classic-rtl.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 361. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/colors-classic-rtl.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 362. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/colors-classic.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 363. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/colors-classic.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 364. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/colors-classic.min.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 365. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/colors-fresh-rtl.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 366. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/colors-fresh-rtl.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 367. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/colors-fresh.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 368. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/colors-fresh.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 369. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/colors-fresh.min.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 370. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/dashboard-rtl.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 371. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/dashboard.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 372. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/global-rtl.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 373. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/global-rtl.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 374. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/global.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 375. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/global.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 376. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/ie-rtl.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 377. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/ie-rtl.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 378. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/ie-rtl.min.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 379. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/ie.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 380. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/ie.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 381. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/ie.min.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 382. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/install-rtl.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 383. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/install.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 384. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/login-rtl.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 385. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/login.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 386. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/media-rtl.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 387. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/media.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 388. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/ms.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 389. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/ms.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 390. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/nav-menu-rtl.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 391. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/nav-menu-rtl.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 392. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/nav-menu.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 393. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/nav-menu.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 394. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/plugin-install-rtl.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 395. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/plugin-install-rtl.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 396. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/plugin-install.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 397. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/plugin-install.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 398. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/press-this-rtl.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 399. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/press-this-rtl.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 400. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/press-this.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 401. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/press-this.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 402. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/theme-editor-rtl.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 403. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/theme-editor-rtl.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 404. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/theme-editor.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 405. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/theme-editor.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 406. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/theme-install.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 407. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/theme-install.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 408. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/widgets-rtl.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 409. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/widgets.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 410. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/wp-admin-rtl.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 411. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/css/wp-admin.dev.css`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 412. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/custom-fields.js`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 413. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/customize.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 414. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/dbx-admin-key.js`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 415. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-attachment-rows.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 416. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-category-form.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 417. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-comments.js`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 418. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-comments.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 419. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-form.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 420. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-link-categories.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 421. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-link-category-form.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 422. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-page-form.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 423. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-pages.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 424. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-post-rows.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 425. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit-tags.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 426. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/edit.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 427. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/export.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 428. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/freedoms.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 429. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/gears-manifest.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 430. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/archive-link.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 431. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/arrows-dark-2x.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 432. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/arrows-dark-vs-2x.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 433. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/arrows-dark-vs.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 434. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/arrows-dark.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 435. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/arrows-pr-2x.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 436. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/arrows-pr.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 437. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/arrows-vs-2x.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 438. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/arrows-vs.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 439. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/blue-grad.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 440. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/box-bg-left.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 441. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/box-bg-right.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 442. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/box-bg.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 443. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/box-butt-left.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 444. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/box-butt-right.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 445. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/box-butt.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 446. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/box-head-left.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 447. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/box-head-right.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 448. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/box-head.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 449. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/browse-happy.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 450. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/bubble_bg-rtl-2x.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 451. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/bubble_bg-rtl.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 452. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/button-grad-active-vs.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 453. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/button-grad-active.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 454. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/button-grad-vs.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 455. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/button-grad.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 456. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/ed-bg-vs.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 457. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/ed-bg.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 458. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/fade-butt.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 459. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/fav-arrow-rtl.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 460. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/fav-arrow-vs-rtl.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 461. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/fav-arrow-vs.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 462. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/fav-arrow.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 463. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/fav-top-vs.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 464. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/fav-vs.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 465. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/fav.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 466. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/gray-grad.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 467. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/list-vs.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 468. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/loading-publish.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 469. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/lock-2x.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 470. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/lock.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 471. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/login-bkg-bottom.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 472. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/login-bkg-tile.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 473. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/login-header.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 474. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/logo-ghost.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 475. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/logo-login.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 476. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/logo.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 477. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/menu-arrows.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 478. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/menu-bits-rtl-vs.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 479. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/menu-bits-rtl.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 480. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/menu-bits-vs.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 481. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/menu-bits.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 482. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/menu-dark-rtl.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 483. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/menu-dark.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 484. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/menu-shadow-rtl.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 485. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/menu-shadow.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 486. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/notice.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 487. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/press-this-2x.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 488. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/press-this.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 489. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/required.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 490. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/screen-options-right-up.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 491. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/screen-options-right.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 492. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/star.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 493. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/stars-rtl-2x.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 494. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/stars-rtl.png`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 495. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/toggle-arrow-rtl.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 496. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/toggle-arrow.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 497. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/toggle.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 498. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-admin/images/visit-site-button-grad-vs.gif`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta; sensitive-looking path

### 499. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/login.php?p=-1_cff_marker_p_numeric_boundary_67d49c04ab`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_67d49c04ab`
- Response: HTTP `200` / Length `41993` / Type `text/html; charset=UTF-8`
- Title: Page not found – pallife
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_p_numeric_boundary_67d49c04ab` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `41993`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 500. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?s=%3Ccff_marker_s_xss_reflection_probe_fed5ab83ff%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_fed5ab83ff&gt;`
- Response: HTTP `200` / Length `42969` / Type `text/html; charset=UTF-8`
- Title: Search Results for “&lt;cff_marker_s_xss_reflection_probe_fed5ab83ff&gt;” – pallife
- Evidence: status=200; different from 404 baseline; length delta
- Marker: `cff_marker_s_xss_reflection_probe_fed5ab83ff` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42969`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta

### 501. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-content/`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta

### 502. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-content/index.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta

### 503. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-cron.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta

### 504. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/index.php`
- Response: HTTP `301` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=301; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=301; different from 404 baseline; length delta

### 505. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://pallife.co/wp-activate.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `302`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=302; different from 404 baseline; length delta

