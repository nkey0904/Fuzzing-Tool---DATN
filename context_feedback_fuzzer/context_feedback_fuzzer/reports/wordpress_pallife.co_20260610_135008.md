# Context Feedback Fuzzer Report

- Target: `https://pallife.co/`
- Detected Platform: **wordpress**
- Platform type: `CMS`
- Scan status: `done`
- Requests sent: `400`
- Safety: GET-only, same-host scope, rate-limited, authorization flag required.
- Server technology hint: `php` / `unknown`
- Confirmed findings: `3`
- Possible findings: `242`
- Confirmation rate: `1.22%`
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
- Confirmation reason: Marker duy nhất được phản chiếu trong response hiện tại.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?s=%22cff_marker_s_xss_reflection_probe_ac019a681b`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_s_xss_reflection_probe_ac019a681b`
- Response: HTTP `200` / Length `42958` / Type `text/html; charset=UTF-8`
- Title: Search Results for “&quot;cff_marker_s_xss_reflection_probe_ac019a681b” – pallife
- Evidence: unique marker appeared in response body; unique marker reflected: cff_marker_s_xss_reflection_probe_ac019a681b
- Marker: `cff_marker_s_xss_reflection_probe_ac019a681b` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?s=%22cff_marker_s_xss_reflection_probe_ac019a681b` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42958`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; marker reflected: cff_marker_s_xss_reflection_probe_ac019a681b; marker hits: 1; unique marker appeared in response body; unique marker reflected: cff_marker_s_xss_reflection_probe_ac019a681b

### 2. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hiện tại.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?s=%3Ccff_marker_s_xss_reflection_probe_33daafe906%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_s_xss_reflection_probe_33daafe906&gt;`
- Response: HTTP `200` / Length `42969` / Type `text/html; charset=UTF-8`
- Title: Search Results for “&lt;cff_marker_s_xss_reflection_probe_33daafe906&gt;” – pallife
- Evidence: unique marker appeared in response body; unique marker reflected: cff_marker_s_xss_reflection_probe_33daafe906
- Marker: `cff_marker_s_xss_reflection_probe_33daafe906` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?s=%3Ccff_marker_s_xss_reflection_probe_33daafe906%3E` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42969`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; marker reflected: cff_marker_s_xss_reflection_probe_33daafe906; marker hits: 1; unique marker appeared in response body; unique marker reflected: cff_marker_s_xss_reflection_probe_33daafe906

### 3. Marker-based Input Reflection
- Kind: `parameter`
- Confirmation: `confirmed` | Level: `verified_reflection` | Confidence: `95`
- Confirmation reason: Marker duy nhất được phản chiếu trong response hiện tại.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Marker-based Input Reflection
- URL: `https://pallife.co/?s=cff_marker_s_text_canary_5bb0a59ab5`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_s_text_canary_5bb0a59ab5`
- Response: HTTP `200` / Length `42826` / Type `text/html; charset=UTF-8`
- Title: Search Results for “cff_marker_s_text_canary_5bb0a59ab5” – pallife
- Evidence: unique marker reflected: cff_marker_s_text_canary_5bb0a59ab5
- Marker: `cff_marker_s_text_canary_5bb0a59ab5` | Reflected: `True` | Hits: `1`
  - Hit: `https://pallife.co/?s=cff_marker_s_text_canary_5bb0a59ab5` / source `immediate_response`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42826`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; marker reflected: cff_marker_s_text_canary_5bb0a59ab5; marker hits: 1; unique marker reflected: cff_marker_s_text_canary_5bb0a59ab5

### 4. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?cat=-1_cff_marker_cat_numeric_boundary_c3dd9eec48`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_cat_numeric_boundary_c3dd9eec48`
- Response: HTTP `200` / Length `46917` / Type `text/html; charset=UTF-8`
- Title: pallife
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_cat_numeric_boundary_c3dd9eec48` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46917`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 5. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?p=-1_cff_marker_p_numeric_boundary_fac024f13f`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_p_numeric_boundary_fac024f13f`
- Response: HTTP `200` / Length `46733` / Type `text/html; charset=UTF-8`
- Title: Page not found – pallife
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_fac024f13f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46733`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 6. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?p=0_cff_marker_p_numeric_boundary_e39ea194e0`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_p_numeric_boundary_e39ea194e0`
- Response: HTTP `200` / Length `46917` / Type `text/html; charset=UTF-8`
- Title: pallife
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_p_numeric_boundary_e39ea194e0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46917`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 7. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?search=%22cff_marker_search_xss_reflection_probe_afcadfe08e`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_search_xss_reflection_probe_afcadfe08e`
- Response: HTTP `200` / Length `46917` / Type `text/html; charset=UTF-8`
- Title: pallife
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_afcadfe08e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46917`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 8. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?search=%27_cff_marker_search_sqli_probe_9fd595aabc`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_9fd595aabc`
- Response: HTTP `200` / Length `46917` / Type `text/html; charset=UTF-8`
- Title: pallife
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_9fd595aabc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46917`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 9. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?search=%27cff_marker_search_xss_reflection_probe_39a55878c9`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_search_xss_reflection_probe_39a55878c9`
- Response: HTTP `200` / Length `46917` / Type `text/html; charset=UTF-8`
- Title: pallife
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_39a55878c9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46917`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 10. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?search=%3Ccff_marker_search_xss_reflection_probe_700f21a1df%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_700f21a1df&gt;`
- Response: HTTP `200` / Length `46917` / Type `text/html; charset=UTF-8`
- Title: pallife
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_700f21a1df` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46917`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 11. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?search=cff_marker_search_text_canary_14ddb9eab5`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_14ddb9eab5`
- Response: HTTP `200` / Length `46917` / Type `text/html; charset=UTF-8`
- Title: pallife
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_text_canary_14ddb9eab5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46917`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 12. Interesting path / response anomaly
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

### 13. Interesting path / response anomaly
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

### 14. Interesting path / response anomaly
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

### 15. Interesting path / response anomaly
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

### 16. Interesting path / response anomaly
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

### 17. Interesting path / response anomaly
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

### 18. Interesting path / response anomaly
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

### 19. Interesting path / response anomaly
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

### 20. Interesting path / response anomaly
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

### 21. Interesting path / response anomaly
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

### 22. Interesting path / response anomaly
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

### 23. Interesting path / response anomaly
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

### 24. Interesting path / response anomaly
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

### 25. Interesting path / response anomaly
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

### 26. Interesting path / response anomaly
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

### 27. Interesting path / response anomaly
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

### 28. Interesting path / response anomaly
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

### 29. Interesting path / response anomaly
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

### 30. Interesting path / response anomaly
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

### 31. Interesting path / response anomaly
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

### 32. Interesting path / response anomaly
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

### 33. Interesting path / response anomaly
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

### 34. Interesting path / response anomaly
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

### 35. Interesting path / response anomaly
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

### 36. Interesting path / response anomaly
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

### 37. Interesting path / response anomaly
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

### 38. Interesting path / response anomaly
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

### 39. Interesting path / response anomaly
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

### 40. Interesting path / response anomaly
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

### 41. Interesting path / response anomaly
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

### 42. Interesting path / response anomaly
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

### 43. Interesting path / response anomaly
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

### 44. Interesting path / response anomaly
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

### 45. Interesting path / response anomaly
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

### 46. Interesting path / response anomaly
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

### 47. Interesting path / response anomaly
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

### 48. Interesting path / response anomaly
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

### 49. Interesting path / response anomaly
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

### 50. Interesting path / response anomaly
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

### 51. Interesting path / response anomaly
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

### 52. Interesting path / response anomaly
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

### 53. Interesting path / response anomaly
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

### 54. Interesting path / response anomaly
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

### 55. Interesting path / response anomaly
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

### 56. Interesting path / response anomaly
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

### 57. Interesting path / response anomaly
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

### 58. Interesting path / response anomaly
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

### 59. Interesting path / response anomaly
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

### 60. Interesting path / response anomaly
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

### 61. Interesting path / response anomaly
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

### 62. Interesting path / response anomaly
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

### 63. Interesting path / response anomaly
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

### 64. Interesting path / response anomaly
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

### 65. Interesting path / response anomaly
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

### 66. Interesting path / response anomaly
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

### 67. Interesting path / response anomaly
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

### 68. Interesting path / response anomaly
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

### 69. Interesting path / response anomaly
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

### 70. Interesting path / response anomaly
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

### 71. Interesting path / response anomaly
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

### 72. Interesting path / response anomaly
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

### 73. Interesting path / response anomaly
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

### 74. Interesting path / response anomaly
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

### 75. Interesting path / response anomaly
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

### 76. Interesting path / response anomaly
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

### 77. Interesting path / response anomaly
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

### 78. Interesting path / response anomaly
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

### 79. Interesting path / response anomaly
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

### 80. Interesting path / response anomaly
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

### 81. Interesting path / response anomaly
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

### 82. Interesting path / response anomaly
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

### 83. Interesting path / response anomaly
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

### 84. Interesting path / response anomaly
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

### 85. Interesting path / response anomaly
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

### 86. Interesting path / response anomaly
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

### 87. Interesting path / response anomaly
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

### 88. Interesting path / response anomaly
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

### 89. Interesting path / response anomaly
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

### 90. Interesting path / response anomaly
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

### 91. Interesting path / response anomaly
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

### 92. Interesting path / response anomaly
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

### 93. Interesting path / response anomaly
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

### 94. Interesting path / response anomaly
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

### 95. Interesting path / response anomaly
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

### 96. Interesting path / response anomaly
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

### 97. Interesting path / response anomaly
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

### 98. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://pallife.co/?page_id=0_cff_marker_page_id_numeric_boundary_0d61cf1303`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_id_numeric_boundary_0d61cf1303`
- Response: HTTP `301` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=301; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_id_numeric_boundary_0d61cf1303` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=301; different from 404 baseline; length delta; parameter changed response shape

### 99. Interesting path / response anomaly
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

### 100. Interesting path / response anomaly
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

### 101. Interesting path / response anomaly
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

### 102. Interesting path / response anomaly
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

### 103. Interesting path / response anomaly
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

### 104. Interesting path / response anomaly
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

### 105. Interesting path / response anomaly
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

### 106. Interesting path / response anomaly
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

### 107. Interesting path / response anomaly
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

### 108. Interesting path / response anomaly
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

### 109. Interesting path / response anomaly
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

### 110. Interesting path / response anomaly
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

### 111. Interesting path / response anomaly
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

### 112. Interesting path / response anomaly
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

### 113. Interesting path / response anomaly
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

### 114. Interesting path / response anomaly
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

### 115. Interesting path / response anomaly
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

### 116. Interesting path / response anomaly
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

### 117. Interesting path / response anomaly
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

### 118. Interesting path / response anomaly
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

### 119. Interesting path / response anomaly
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

### 120. Interesting path / response anomaly
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

### 121. Interesting path / response anomaly
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

### 122. Interesting path / response anomaly
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

### 123. Interesting path / response anomaly
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

### 124. Interesting path / response anomaly
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

### 125. Interesting path / response anomaly
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

### 126. Interesting path / response anomaly
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

### 127. Interesting path / response anomaly
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

### 128. Interesting path / response anomaly
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

### 129. Interesting path / response anomaly
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

### 130. Interesting path / response anomaly
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

### 131. Interesting path / response anomaly
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

### 132. Interesting path / response anomaly
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

### 133. Interesting path / response anomaly
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

### 134. Interesting path / response anomaly
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

### 135. Interesting path / response anomaly
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

### 136. Interesting path / response anomaly
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

### 137. Interesting path / response anomaly
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

### 138. Interesting path / response anomaly
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

### 139. Interesting path / response anomaly
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

### 140. Interesting path / response anomaly
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

### 141. Interesting path / response anomaly
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

### 142. Interesting path / response anomaly
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

### 143. Interesting path / response anomaly
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

### 144. Interesting path / response anomaly
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

### 145. Interesting path / response anomaly
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

### 146. Interesting path / response anomaly
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

### 147. Interesting path / response anomaly
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

### 148. Interesting path / response anomaly
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

### 149. Interesting path / response anomaly
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

### 150. Interesting path / response anomaly
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

### 151. Interesting path / response anomaly
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

### 152. Interesting path / response anomaly
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

### 153. Interesting path / response anomaly
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

### 154. Interesting path / response anomaly
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

### 155. Interesting path / response anomaly
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

### 156. Interesting path / response anomaly
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

### 157. Interesting path / response anomaly
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

### 158. Interesting path / response anomaly
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

### 159. Interesting path / response anomaly
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

### 160. Interesting path / response anomaly
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

### 161. Interesting path / response anomaly
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

### 162. Interesting path / response anomaly
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

### 163. Interesting path / response anomaly
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

### 164. Interesting path / response anomaly
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

### 165. Interesting path / response anomaly
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

### 166. Interesting path / response anomaly
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

### 167. Interesting path / response anomaly
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

### 168. Interesting path / response anomaly
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

### 169. Interesting path / response anomaly
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

### 170. Interesting path / response anomaly
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

### 171. Interesting path / response anomaly
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

### 172. Interesting path / response anomaly
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

### 173. Interesting path / response anomaly
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

### 174. Interesting path / response anomaly
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

### 175. Interesting path / response anomaly
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

### 176. Interesting path / response anomaly
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

### 177. Interesting path / response anomaly
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

### 178. Interesting path / response anomaly
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

### 179. Interesting path / response anomaly
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

### 180. Interesting path / response anomaly
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

### 181. Interesting path / response anomaly
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

### 182. Interesting path / response anomaly
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

### 183. Interesting path / response anomaly
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

### 184. Interesting path / response anomaly
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

### 185. Interesting path / response anomaly
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

### 186. Interesting path / response anomaly
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

### 187. Interesting path / response anomaly
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

### 188. Interesting path / response anomaly
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

### 189. Interesting path / response anomaly
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

### 190. Interesting path / response anomaly
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

### 191. Interesting path / response anomaly
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

### 192. Interesting path / response anomaly
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

### 193. Interesting path / response anomaly
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

### 194. Interesting path / response anomaly
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

### 195. Interesting path / response anomaly
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

### 196. Interesting path / response anomaly
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

### 197. Interesting path / response anomaly
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

### 198. Interesting path / response anomaly
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

### 199. Interesting path / response anomaly
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

### 200. Interesting path / response anomaly
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

### 201. Interesting path / response anomaly
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

### 202. Interesting path / response anomaly
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

### 203. Interesting path / response anomaly
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

### 204. Interesting path / response anomaly
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

### 205. Interesting path / response anomaly
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

### 206. Interesting path / response anomaly
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

### 207. Interesting path / response anomaly
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

### 208. Interesting path / response anomaly
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

### 209. Interesting path / response anomaly
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

### 210. Interesting path / response anomaly
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

### 211. Interesting path / response anomaly
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

### 212. Interesting path / response anomaly
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

### 213. Interesting path / response anomaly
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

### 214. Interesting path / response anomaly
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

### 215. Interesting path / response anomaly
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

### 216. Interesting path / response anomaly
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

### 217. Interesting path / response anomaly
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

### 218. Interesting path / response anomaly
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

### 219. Interesting path / response anomaly
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

### 220. Interesting path / response anomaly
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

### 221. Interesting path / response anomaly
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

### 222. Interesting path / response anomaly
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

### 223. Interesting path / response anomaly
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

### 224. Interesting path / response anomaly
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

### 225. Interesting path / response anomaly
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

### 226. Interesting path / response anomaly
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

### 227. Interesting path / response anomaly
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

### 228. Interesting path / response anomaly
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

### 229. Interesting path / response anomaly
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

### 230. Interesting path / response anomaly
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

### 231. Interesting path / response anomaly
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

### 232. Interesting path / response anomaly
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

### 233. Interesting path / response anomaly
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

### 234. Interesting path / response anomaly
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

### 235. Interesting path / response anomaly
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

### 236. Interesting path / response anomaly
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

### 237. Interesting path / response anomaly
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

### 238. Interesting path / response anomaly
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

### 239. Interesting path / response anomaly
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

### 240. Interesting path / response anomaly
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

### 241. Interesting path / response anomaly
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

### 242. Interesting path / response anomaly
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

### 243. Interesting path / response anomaly
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

### 244. Interesting path / response anomaly
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

### 245. Interesting path / response anomaly
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

