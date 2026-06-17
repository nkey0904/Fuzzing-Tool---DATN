# Context Feedback Fuzzer Report

- Target: `https://learn.ctseducation.org/`
- Detected Platform: **moodle**
- Platform type: `LMS`
- Scan status: `done`
- Requests sent: `400`
- Safety: GET-only, same-host scope, rate-limited, authorization flag required.
- Server technology hint: `php` / `unknown`
- Confirmed findings: `0`
- Possible findings: `200`
- Confirmation rate: `0.0%`
- Marker verified count: `0`
- Marker verification rate: `0.0%`
- Crawled links for verification: `80`

## Wordlist generation mechanism

Tool tạo wordlist theo 3 lớp: platform paths từ profile/wordlist, extension paths theo server technology, và payload values theo loại parameter.

- Path wordlist sources: `moodle.fuzz.txt`
- Server extension priority: `.php, .php.bak, .php.old`
- Parameter strategy examples:
  - `id` => `numeric`
  - `course` => `numeric`
  - `courseid` => `numeric`
  - `userid` => `numeric`
  - `user` => `numeric`
  - `page` => `numeric`
  - `section` => `numeric`
  - `search` => `text`
  - `q` => `text`
  - `sesskey` => `token`
  - `returnurl` => `redirect`
  - `redirect` => `redirect`
  - `wstoken` => `token`
  - `wsfunction` => `text`
  - `moodlewsrestformat` => `text`
  - `component` => `text`
  - `contextid` => `numeric`
  - `itemid` => `numeric`
  - `filearea` => `path`
  - `filepath` => `path`

- Payload strategy examples:
  - `id` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `course` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `courseid` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `userid` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `user` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `page` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `section` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `search` => `text_canary, xss_reflection_probe, xss_reflection_probe, xss_reflection_probe, sqli_probe`
  - `q` => `text_canary, xss_reflection_probe, xss_reflection_probe, xss_reflection_probe, sqli_probe`
  - `sesskey` => `token_canary, token_empty, token_invalid`
  - `returnurl` => `redirect_probe, redirect_probe`
  - `redirect` => `redirect_probe, redirect_probe`
  - `wstoken` => `token_canary, token_empty, token_invalid`
  - `wsfunction` => `text_canary, xss_reflection_probe, xss_reflection_probe, xss_reflection_probe, sqli_probe`
  - `moodlewsrestformat` => `text_canary, xss_reflection_probe, xss_reflection_probe, xss_reflection_probe, sqli_probe`
  - `component` => `text_canary, xss_reflection_probe, xss_reflection_probe, xss_reflection_probe, sqli_probe`
  - `contextid` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `itemid` => `numeric_boundary, numeric_boundary, numeric_boundary, numeric_boundary, sqli_probe, sqli_probe`
  - `filearea` => `path_canary, path_traversal_probe, path_traversal_probe`
  - `filepath` => `path_canary, path_traversal_probe, path_traversal_probe`

## Marker verification mechanism

Marker-based fuzzing gắn marker duy nhất vào từng payload. Sau fuzzing, verification engine crawl các link cùng host và kiểm tra marker có xuất hiện lại không. Nếu có bằng chứng marker, finding được phân loại là confirmed.

- Markers generated: `882`
- Markers verified: `0`
- Markers failed: `882`
- Marker verification rate: `0.0%`
- Crawled links: `80`

## Fingerprint scores

- wordpress: 0
- joomla: 3
- drupal: 0
- liferay: 0
- sharepoint: 0
- moodle: 62

## Findings

Các finding được chia theo trạng thái `confirmed` hoặc `possible`. Confirmed nghĩa là có bằng chứng marker-based reflection/verification; possible nghĩa là dựa trên feedback/anomaly nhưng chưa có marker xác nhận.

### 1. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?course=-1_cff_marker_course_numeric_boundary_ccb4c6d763`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_ccb4c6d763`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_ccb4c6d763` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 2. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?course=0_cff_marker_course_numeric_boundary_673db2dad2`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_673db2dad2`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_673db2dad2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 3. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?course=1_cff_marker_course_numeric_boundary_2f430eefee`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_2f430eefee`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_2f430eefee` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 4. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?course=999999_cff_marker_course_numeric_boundary_77049f16db`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_77049f16db`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_77049f16db` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 5. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?courseid=-1_cff_marker_courseid_numeric_boundary_b7c992efd8`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_b7c992efd8`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_b7c992efd8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 6. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?courseid=0_cff_marker_courseid_numeric_boundary_ebb20d445d`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_ebb20d445d`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_ebb20d445d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 7. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?courseid=1_cff_marker_courseid_numeric_boundary_3bdb167ba4`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_3bdb167ba4`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_3bdb167ba4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 8. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?courseid=999999_cff_marker_courseid_numeric_boundary_2281964d32`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_2281964d32`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_2281964d32` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 9. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?id=-1_cff_marker_id_numeric_boundary_002a8c8695`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_002a8c8695`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_002a8c8695` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 10. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?id=0_cff_marker_id_numeric_boundary_bb8e323d94`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_bb8e323d94`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_bb8e323d94` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 11. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?id=1_cff_marker_id_numeric_boundary_41db990802`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_41db990802`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_41db990802` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 12. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?id=999999_cff_marker_id_numeric_boundary_420341375e`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_420341375e`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_420341375e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 13. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?page=-1_cff_marker_page_numeric_boundary_5379455f47`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_5379455f47`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_5379455f47` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 14. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?page=0_cff_marker_page_numeric_boundary_3dcb0e50df`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_3dcb0e50df`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_3dcb0e50df` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 15. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?page=1_cff_marker_page_numeric_boundary_afb0e2fa0b`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_afb0e2fa0b`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_afb0e2fa0b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 16. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?page=999999_cff_marker_page_numeric_boundary_0552e72d55`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_0552e72d55`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_0552e72d55` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 17. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?q=%22cff_marker_q_xss_reflection_probe_5d94fe25e6`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_q_xss_reflection_probe_5d94fe25e6`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_reflection_probe_5d94fe25e6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 18. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?q=%27cff_marker_q_xss_reflection_probe_0826618427`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_q_xss_reflection_probe_0826618427`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_reflection_probe_0826618427` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 19. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?q=%3Ccff_marker_q_xss_reflection_probe_d6284b848d%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_d6284b848d&gt;`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_reflection_probe_d6284b848d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 20. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?q=cff_marker_q_text_canary_8473b9b228`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_8473b9b228`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_text_canary_8473b9b228` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 21. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_1baa83d27b`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_1baa83d27b`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_1baa83d27b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 22. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_fd8a4e1935`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_fd8a4e1935`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_fd8a4e1935` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 23. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_29140bced4`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_29140bced4`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_29140bced4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 24. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_899428c212`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_899428c212`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_899428c212` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 25. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?search=%22cff_marker_search_xss_reflection_probe_a18ccc8db2`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_search_xss_reflection_probe_a18ccc8db2`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_reflection_probe_a18ccc8db2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 26. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?search=%27cff_marker_search_xss_reflection_probe_c3a80cf3d8`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_search_xss_reflection_probe_c3a80cf3d8`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_reflection_probe_c3a80cf3d8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 27. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?search=%3Ccff_marker_search_xss_reflection_probe_e2461f9ea5%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_e2461f9ea5&gt;`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_reflection_probe_e2461f9ea5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 28. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?search=cff_marker_search_text_canary_4e05d3fd34`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_4e05d3fd34`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_text_canary_4e05d3fd34` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 29. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?section=-1_cff_marker_section_numeric_boundary_0ceca7a70b`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_0ceca7a70b`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_0ceca7a70b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 30. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?section=0_cff_marker_section_numeric_boundary_369ef3d7a9`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_369ef3d7a9`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_369ef3d7a9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 31. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?section=1_cff_marker_section_numeric_boundary_bed824e0bd`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_bed824e0bd`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_bed824e0bd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 32. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?section=999999_cff_marker_section_numeric_boundary_927374a9d5`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_927374a9d5`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_927374a9d5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 33. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?sesskey=cff_marker_sesskey_token_canary_83d39e7eb6`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_83d39e7eb6`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_canary_83d39e7eb6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 34. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?sesskey=cff_marker_sesskey_token_empty_97d74adb57`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_97d74adb57`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_empty_97d74adb57` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 35. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_d5157d3918`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_d5157d3918`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_invalid_d5157d3918` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 36. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?user=-1_cff_marker_user_numeric_boundary_1decc18636`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_1decc18636`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_1decc18636` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 37. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?user=0_cff_marker_user_numeric_boundary_e9ebcc3f16`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_e9ebcc3f16`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_e9ebcc3f16` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 38. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?user=1_cff_marker_user_numeric_boundary_ada0c678ab`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_ada0c678ab`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_ada0c678ab` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 39. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?user=999999_cff_marker_user_numeric_boundary_9f1c4078c4`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_9f1c4078c4`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_9f1c4078c4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 40. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?userid=-1_cff_marker_userid_numeric_boundary_eb669feda7`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_eb669feda7`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_eb669feda7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 41. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?userid=0_cff_marker_userid_numeric_boundary_3a42c7fa64`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_3a42c7fa64`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_3a42c7fa64` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 42. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?userid=1_cff_marker_userid_numeric_boundary_28d12b88b0`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_28d12b88b0`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_28d12b88b0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 43. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?userid=999999_cff_marker_userid_numeric_boundary_b2d564bcac`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_b2d564bcac`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_b2d564bcac` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 44. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?wsfunction=%22cff_marker_wsfunction_xss_reflection_probe_b866f0f573`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_marker_wsfunction_xss_reflection_probe_b866f0f573`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_reflection_probe_b866f0f573` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 45. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?wsfunction=%27cff_marker_wsfunction_xss_reflection_probe_a035990ec0`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_marker_wsfunction_xss_reflection_probe_a035990ec0`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_reflection_probe_a035990ec0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 46. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_aafdc85439%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_aafdc85439&gt;`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_reflection_probe_aafdc85439` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 47. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?wsfunction=cff_marker_wsfunction_text_canary_469751d7b8`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_469751d7b8`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_text_canary_469751d7b8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 48. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?wstoken=cff_marker_wstoken_token_canary_6a1fb106d9`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_6a1fb106d9`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_canary_6a1fb106d9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 49. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?wstoken=cff_marker_wstoken_token_empty_1182a5b5c4`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_1182a5b5c4`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_empty_1182a5b5c4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 50. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_8c2960d6d1`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_8c2960d6d1`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_invalid_8c2960d6d1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 51. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint

### 52. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/webservice/rest/server.php`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint

### 53. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?course=1%22_cff_marker_course_sqli_probe_c86c95f695`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_c86c95f695`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_c86c95f695` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 54. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?course=1%27_cff_marker_course_sqli_probe_7480f29e6a`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_7480f29e6a`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_7480f29e6a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 55. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?courseid=1%22_cff_marker_courseid_sqli_probe_f542bda6a2`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_f542bda6a2`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_f542bda6a2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 56. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?courseid=1%27_cff_marker_courseid_sqli_probe_33e14af471`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_33e14af471`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_33e14af471` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 57. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?id=1%22_cff_marker_id_sqli_probe_39fdfe3a70`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_39fdfe3a70`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_39fdfe3a70` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 58. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?id=1%27_cff_marker_id_sqli_probe_0fce51c7be`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_0fce51c7be`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_0fce51c7be` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 59. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?page=1%22_cff_marker_page_sqli_probe_5ef411fd66`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_5ef411fd66`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_5ef411fd66` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 60. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?page=1%27_cff_marker_page_sqli_probe_3a946955c3`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_3a946955c3`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_3a946955c3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 61. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?q=%27_cff_marker_q_sqli_probe_77e3333921`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_77e3333921`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_q_sqli_probe_77e3333921` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 62. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?search=%27_cff_marker_search_sqli_probe_8faf382473`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_8faf382473`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_8faf382473` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 63. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?section=1%22_cff_marker_section_sqli_probe_9369803545`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_9369803545`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_9369803545` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 64. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?section=1%27_cff_marker_section_sqli_probe_19ac7bb4d4`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_19ac7bb4d4`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_19ac7bb4d4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 65. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?user=1%22_cff_marker_user_sqli_probe_9869a4d1e1`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_9869a4d1e1`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_9869a4d1e1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 66. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?user=1%27_cff_marker_user_sqli_probe_f2780ef1cd`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_f2780ef1cd`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_f2780ef1cd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 67. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?userid=1%22_cff_marker_userid_sqli_probe_621daf3bcf`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_621daf3bcf`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_621daf3bcf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 68. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?userid=1%27_cff_marker_userid_sqli_probe_61348f2f0f`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_61348f2f0f`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_61348f2f0f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 69. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?wsfunction=%27_cff_marker_wsfunction_sqli_probe_456775bcbe`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_456775bcbe`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_wsfunction_sqli_probe_456775bcbe` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 70. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/classes/form/purge_caches.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 71. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/classes/form/testoutgoingmailconf_form.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 72. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/classes/local/externalpage/accesscallback.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 73. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/classes/local/settings/autocomplete.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 74. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/classes/local/settings/filesize.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 75. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/classes/privacy/provider.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 76. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/cron.php`
- Response: HTTP `200` / Length `84` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `84`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 77. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/lib.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 78. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/mailout-debugger.php`
- Response: HTTP `200` / Length `15` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `15`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 79. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/mnet/peer_forms.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 80. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/mnet/profilefields_form.php`
- Response: HTTP `200` / Length `42` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 81. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/mnet/services_form.php`
- Response: HTTP `200` / Length `42` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 82. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/mnet/tabs.php`
- Response: HTTP `200` / Length `42` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 83. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/mnet/trustedhosts.html`
- Response: HTTP `200` / Length `2254` / Type `text/html`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2254`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 84. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/registration/forms.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 85. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/registration/lib.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 86. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/admins_existing_selector.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 87. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/admins_potential_selector.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 88. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/allow_assign_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 89. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/allow_override_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 90. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/allow_role_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 91. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/allow_switch_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 92. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/allow_view_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 93. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/assign_user_selector_base.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 94. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/capability_table_base.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 95. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/capability_table_with_risks.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 96. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/check_capability_table.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 97. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/check_users_selector.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 98. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/define_role_table_advanced.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 99. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/define_role_table_basic.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 100. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/existing_role_holders.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 101. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/override_permissions_table_advanced.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 102. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/permission_allow_form.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 103. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/permission_prohibit_form.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 104. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/permissions_table.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 105. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/potential_assignees_below_course.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 106. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/potential_assignees_course_and_above.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 107. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/preset.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 108. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/preset_form.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 109. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/privacy/provider.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 110. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/view_role_definition_table.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 111. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/lib.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 112. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/managetabs.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 113. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/module.js`
- Response: HTTP `200` / Length `6873` / Type `application/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `application/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 114. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/role_schema.xml`
- Response: HTTP `200` / Length `3028` / Type `text/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `text/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 115. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/settings/analytics.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 116. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/settings/competency.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 117. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/settings/courses.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 118. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/settings/h5p.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 119. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/settings/language.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 120. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/settings/license.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 121. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/settings/location.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 122. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/settings/messaging.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 123. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/settings/mnet.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 124. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/settings/security.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 125. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/settings/server.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 126. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/settings/subsystems.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 127. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/settings/userfeedback.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 128. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/local/settings/autocomplete.mustache`
- Response: HTTP `200` / Length `2797` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2797`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 129. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting.mustache`
- Response: HTTP `200` / Length `3545` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3545`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 130. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configcheckbox.mustache`
- Response: HTTP `200` / Length `1444` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1444`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 131. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configcolourpicker.mustache`
- Response: HTTP `200` / Length `1790` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1790`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 132. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configdirectory.mustache`
- Response: HTTP `200` / Length `1339` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1339`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 133. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configduration.mustache`
- Response: HTTP `200` / Length `1903` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1903`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 134. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configempty.mustache`
- Response: HTTP `200` / Length `1068` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1068`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 135. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configexecutable.mustache`
- Response: HTTP `200` / Length `1334` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1334`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 136. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configfile.mustache`
- Response: HTTP `200` / Length `1904` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1904`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 137. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configfilesize.mustache`
- Response: HTTP `200` / Length `1899` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1899`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 138. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_confightmleditor.mustache`
- Response: HTTP `200` / Length `1236` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1236`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 139. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configmulticheckbox.mustache`
- Response: HTTP `200` / Length `1768` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1768`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 140. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configmultiselect.mustache`
- Response: HTTP `200` / Length `1710` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1710`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 141. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configmultiselect_optgroup.mustache`
- Response: HTTP `200` / Length `2679` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2679`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 142. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configpasswordunmask.mustache`
- Response: HTTP `200` / Length `2813` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2813`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 143. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configselect.mustache`
- Response: HTTP `200` / Length `1567` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1567`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 144. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configselect_optgroup.mustache`
- Response: HTTP `200` / Length `2538` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2538`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 145. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configtext.mustache`
- Response: HTTP `200` / Length `2076` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2076`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 146. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configtextarea.mustache`
- Response: HTTP `200` / Length `1518` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1518`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 147. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_configtime.mustache`
- Response: HTTP `200` / Length `2329` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2329`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 148. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_courselist_frontpage.mustache`
- Response: HTTP `200` / Length `1681` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1681`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 149. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_description.mustache`
- Response: HTTP `200` / Length `1370` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1370`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 150. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_emoticons.mustache`
- Response: HTTP `200` / Length `2221` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2221`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 151. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_encryptedpassword.mustache`
- Response: HTTP `200` / Length `2385` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2385`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 152. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_filetypes.mustache`
- Response: HTTP `200` / Length `1826` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1826`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 153. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_flag.mustache`
- Response: HTTP `200` / Length `1263` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1263`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 154. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_gradecat_combo.mustache`
- Response: HTTP `200` / Length `1654` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1654`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 155. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_heading.mustache`
- Response: HTTP `200` / Length `1263` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1263`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 156. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_manage_plugins.mustache`
- Response: HTTP `200` / Length `3996` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3996`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 157. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/setting_special_calendar_weekend.mustache`
- Response: HTTP `200` / Length `1808` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1808`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 158. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/settings.mustache`
- Response: HTTP `200` / Length `2050` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2050`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 159. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/settings_search_results.mustache`
- Response: HTTP `200` / Length `2707` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2707`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 160. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics/amd/build/log_info.min.js`
- Response: HTTP `200` / Length `981` / Type `application/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `981`
  - Content-Type: `application/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 161. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics/amd/build/log_info.min.js.map`
- Response: HTTP `200` / Length `2468` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2468`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 162. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics/amd/build/model.min.js`
- Response: HTTP `200` / Length `3668` / Type `application/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3668`
  - Content-Type: `application/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 163. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics/amd/build/model.min.js.map`
- Response: HTTP `200` / Length `11755` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `11755`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 164. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics/amd/build/potential-contexts.min.js`
- Response: HTTP `200` / Length `778` / Type `application/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `778`
  - Content-Type: `application/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 165. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics/amd/build/potential-contexts.min.js.map`
- Response: HTTP `200` / Length `2752` / Type `application/octet-stream`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2752`
  - Content-Type: `application/octet-stream`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 166. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics/amd/src/log_info.js`
- Response: HTTP `200` / Length `1793` / Type `application/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1793`
  - Content-Type: `application/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 167. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics/amd/src/model.js`
- Response: HTTP `200` / Length `8330` / Type `application/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `8330`
  - Content-Type: `application/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 168. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics/amd/src/potential-contexts.js`
- Response: HTTP `200` / Length `1934` / Type `application/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1934`
  - Content-Type: `application/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 169. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics/classes/clihelper.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 170. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/config.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 171. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/lib/ajax/service.php`
- Response: HTTP `200` / Length `191` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; API-like endpoint
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `191`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; API-like endpoint

### 172. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/login/index.php`
- Response: HTTP `200` / Length `21997` / Type `text/html; charset=utf-8`
- Title: Log in to the site | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `21997`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 173. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 174. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/classes`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 175. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/classes/form`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 176. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/classes/local`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 177. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/classes/local/externalpage`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 178. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/classes/local/settings`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 179. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/classes/privacy`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 180. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/mnet`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 181. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/registration`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 182. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 183. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 184. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/classes/privacy`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 185. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/tests`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 186. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/roles/tests/behat`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 187. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/settings`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 188. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 189. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/local`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 190. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/templates/local/settings`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 191. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tests`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 192. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tests/behat`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 193. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 194. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 195. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics/amd`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 196. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics/amd/build`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 197. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics/amd/src`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 198. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/admin/tool/analytics/classes`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path

### 199. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/course/index.php`
- Response: HTTP `200` / Length `37721` / Type `text/html; charset=utf-8`
- Title: Course categories | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `37721`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta

### 200. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/index.php`
- Response: HTTP `200` / Length `44158` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44158`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta

