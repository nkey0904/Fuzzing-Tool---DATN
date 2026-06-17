# Context Feedback Fuzzer Report

- Target: `https://moodle.sit.ac.in/moodle/`
- Detected Platform: **moodle**
- Platform type: `LMS`
- Scan status: `done`
- Requests sent: `1000`
- Safety: GET-only, same-host scope, rate-limited, authorization flag required.
- Server technology hint: `php` / `apache`
- Confirmed findings: `0`
- Possible findings: `844`
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
  - `search` => `text_canary, xss_reflection_probe, xss_trigger_probe, xss_trigger_probe, sqli_probe`
  - `q` => `text_canary, xss_reflection_probe, xss_trigger_probe, xss_trigger_probe, sqli_probe`
  - `sesskey` => `token_canary, token_empty, token_invalid`
  - `returnurl` => `redirect_probe, redirect_probe`
  - `redirect` => `redirect_probe, redirect_probe`
  - `wstoken` => `token_canary, token_empty, token_invalid`
  - `wsfunction` => `text_canary, xss_reflection_probe, xss_trigger_probe, xss_trigger_probe, sqli_probe`
  - `moodlewsrestformat` => `text_canary, xss_reflection_probe, xss_trigger_probe, xss_trigger_probe, sqli_probe`
  - `component` => `text_canary, xss_reflection_probe, xss_trigger_probe, xss_trigger_probe, sqli_probe`
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
- joomla: 2
- drupal: 0
- liferay: 0
- sharepoint: 0
- moodle: 75

## Findings

Các finding được chia theo trạng thái `confirmed` hoặc `possible`. Confirmed nghĩa là có bằng chứng marker-based reflection/verification; possible nghĩa là dựa trên feedback/anomaly nhưng chưa có marker xác nhận.

### 1. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?component=%27_cff_marker_component_sqli_probe_85fb0bed46`
- Parameter: `component` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_component_sqli_probe_85fb0bed46`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_component_sqli_probe_85fb0bed46` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 2. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?contextid=1%22_cff_marker_contextid_sqli_probe_1c1a111010`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_contextid_sqli_probe_1c1a111010`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_contextid_sqli_probe_1c1a111010` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 3. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?contextid=1%27_cff_marker_contextid_sqli_probe_5d6b5c349d`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_contextid_sqli_probe_5d6b5c349d`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_contextid_sqli_probe_5d6b5c349d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 4. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?course=1%22_cff_marker_course_sqli_probe_54004fd984`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_54004fd984`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_course_sqli_probe_54004fd984` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 5. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?course=1%27_cff_marker_course_sqli_probe_57edcbd56b`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_57edcbd56b`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_course_sqli_probe_57edcbd56b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 6. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?courseid=1%22_cff_marker_courseid_sqli_probe_e0dfd50825`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_e0dfd50825`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_courseid_sqli_probe_e0dfd50825` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 7. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?courseid=1%27_cff_marker_courseid_sqli_probe_2c8a8237db`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_2c8a8237db`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_courseid_sqli_probe_2c8a8237db` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 8. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?id=1%22_cff_marker_id_sqli_probe_77a9cb8555`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_77a9cb8555`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_id_sqli_probe_77a9cb8555` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 9. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?id=1%27_cff_marker_id_sqli_probe_4aa573750d`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_4aa573750d`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_id_sqli_probe_4aa573750d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 10. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?itemid=1%22_cff_marker_itemid_sqli_probe_08c2079ed5`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_itemid_sqli_probe_08c2079ed5`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_itemid_sqli_probe_08c2079ed5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 11. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?itemid=1%27_cff_marker_itemid_sqli_probe_ee9ca600a4`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_itemid_sqli_probe_ee9ca600a4`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_itemid_sqli_probe_ee9ca600a4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 12. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?moodlewsrestformat=%27_cff_marker_moodlewsrestformat_sqli_probe_a122c89ee9`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_moodlewsrestformat_sqli_probe_a122c89ee9`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_sqli_probe_a122c89ee9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 13. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?page=1%22_cff_marker_page_sqli_probe_eabcd20924`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_eabcd20924`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_sqli_probe_eabcd20924` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 14. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?page=1%27_cff_marker_page_sqli_probe_b196272161`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_b196272161`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_page_sqli_probe_b196272161` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 15. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?q=%27_cff_marker_q_sqli_probe_cc055ff976`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_cc055ff976`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_q_sqli_probe_cc055ff976` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 16. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?search=%27_cff_marker_search_sqli_probe_d142778055`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_d142778055`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_search_sqli_probe_d142778055` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 17. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?section=1%22_cff_marker_section_sqli_probe_5a80ff83e2`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_5a80ff83e2`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_section_sqli_probe_5a80ff83e2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 18. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?section=1%27_cff_marker_section_sqli_probe_b19de022ed`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_b19de022ed`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_section_sqli_probe_b19de022ed` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 19. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?user=1%22_cff_marker_user_sqli_probe_a8eb3c4ae6`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_a8eb3c4ae6`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_user_sqli_probe_a8eb3c4ae6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 20. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?user=1%27_cff_marker_user_sqli_probe_af6bf9946e`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_af6bf9946e`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_user_sqli_probe_af6bf9946e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 21. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?userid=1%22_cff_marker_userid_sqli_probe_805ccdd928`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_805ccdd928`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_userid_sqli_probe_805ccdd928` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 22. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?userid=1%27_cff_marker_userid_sqli_probe_8b456c7444`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_8b456c7444`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_userid_sqli_probe_8b456c7444` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 23. Possible SQL Injection
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?wsfunction=%27_cff_marker_wsfunction_sqli_probe_d17b0d7d7f`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_d17b0d7d7f`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: SQL-like error keyword appeared in response
- Marker: `cff_marker_wsfunction_sqli_probe_d17b0d7d7f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 24. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?filearea=..%2F..%2Fcff_marker_filearea_path_traversal_probe_ece9cbe609`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filearea_path_traversal_probe_ece9cbe609`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_traversal_probe_ece9cbe609` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 25. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?filearea=..%2Fcff_marker_filearea_path_traversal_probe_a87e143e7b`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filearea_path_traversal_probe_a87e143e7b`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_traversal_probe_a87e143e7b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 26. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?filename=..%2F..%2Fcff_marker_filename_path_traversal_probe_cfbe1d2bdb`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filename_path_traversal_probe_cfbe1d2bdb`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_traversal_probe_cfbe1d2bdb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 27. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?filename=..%2Fcff_marker_filename_path_traversal_probe_50c3f2ee69`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filename_path_traversal_probe_50c3f2ee69`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_traversal_probe_50c3f2ee69` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 28. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?filepath=..%2F..%2Fcff_marker_filepath_path_traversal_probe_b91ad397f9`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filepath_path_traversal_probe_b91ad397f9`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_traversal_probe_b91ad397f9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 29. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?filepath=..%2Fcff_marker_filepath_path_traversal_probe_9748a928d2`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filepath_path_traversal_probe_9748a928d2`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_traversal_probe_9748a928d2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 30. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/?filearea=..%2F..%2Fcff_marker_filearea_path_traversal_probe_5d3bf5c0c7`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filearea_path_traversal_probe_5d3bf5c0c7`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_traversal_probe_5d3bf5c0c7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 31. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/?filearea=..%2Fcff_marker_filearea_path_traversal_probe_da2b76acbd`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filearea_path_traversal_probe_da2b76acbd`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_traversal_probe_da2b76acbd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 32. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/?filename=..%2F..%2Fcff_marker_filename_path_traversal_probe_22f981c639`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filename_path_traversal_probe_22f981c639`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_traversal_probe_22f981c639` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 33. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/?filename=..%2Fcff_marker_filename_path_traversal_probe_a6d50caa42`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filename_path_traversal_probe_a6d50caa42`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_traversal_probe_a6d50caa42` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 34. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/?filepath=..%2F..%2Fcff_marker_filepath_path_traversal_probe_645107a1d2`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filepath_path_traversal_probe_645107a1d2`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_traversal_probe_645107a1d2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 35. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/?filepath=..%2Fcff_marker_filepath_path_traversal_probe_ad3404e982`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filepath_path_traversal_probe_ad3404e982`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_traversal_probe_ad3404e982` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 36. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?component=%3Ccff_marker_component_xss_reflection_probe_89a591d735%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_component_xss_reflection_probe_89a591d735&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_reflection_probe_89a591d735` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 37. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?component=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_component_xss_trigger_probe_f5d46db0bf%27%29%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_component_xss_trigger_probe_f5d46db0bf&#x27;)&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_trigger_probe_f5d46db0bf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 38. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?component=%3Cscript%3Ealert%28%27cff_marker_component_xss_trigger_probe_ac45e87dfa%27%29%3C%2Fscript%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_component_xss_trigger_probe_ac45e87dfa&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_trigger_probe_ac45e87dfa` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 39. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?component=cff_marker_component_text_canary_ac34c78df1`
- Parameter: `component` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_component_text_canary_ac34c78df1`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_text_canary_ac34c78df1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 40. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?contextid=-1_cff_marker_contextid_numeric_boundary_a08560c424`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_contextid_numeric_boundary_a08560c424`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_a08560c424` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 41. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?contextid=0_cff_marker_contextid_numeric_boundary_7dfecf6427`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_contextid_numeric_boundary_7dfecf6427`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_7dfecf6427` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 42. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?contextid=1_cff_marker_contextid_numeric_boundary_43f30d01a2`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_contextid_numeric_boundary_43f30d01a2`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_43f30d01a2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 43. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?contextid=999999_cff_marker_contextid_numeric_boundary_8f2c722d52`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_contextid_numeric_boundary_8f2c722d52`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_8f2c722d52` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 44. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?course=-1_cff_marker_course_numeric_boundary_87bdf718ba`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_87bdf718ba`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_87bdf718ba` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 45. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?course=0_cff_marker_course_numeric_boundary_0f56230915`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_0f56230915`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_0f56230915` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 46. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?course=1_cff_marker_course_numeric_boundary_c98eb01dfd`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_c98eb01dfd`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_c98eb01dfd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 47. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?course=999999_cff_marker_course_numeric_boundary_85e8c7457c`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_85e8c7457c`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_85e8c7457c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 48. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?courseid=-1_cff_marker_courseid_numeric_boundary_d5a9f7fafb`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_d5a9f7fafb`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_d5a9f7fafb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 49. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?courseid=0_cff_marker_courseid_numeric_boundary_fba0336d7b`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_fba0336d7b`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_fba0336d7b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 50. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?courseid=1_cff_marker_courseid_numeric_boundary_68ee541f7a`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_68ee541f7a`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_68ee541f7a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 51. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?courseid=999999_cff_marker_courseid_numeric_boundary_35238690b0`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_35238690b0`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_35238690b0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 52. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?filearea=cff_marker_filearea_path_canary_13996b99dd`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filearea_path_canary_13996b99dd`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_canary_13996b99dd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 53. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?filename=cff_marker_filename_path_canary_5e765f0ef6`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filename_path_canary_5e765f0ef6`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_canary_5e765f0ef6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 54. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?filepath=cff_marker_filepath_path_canary_046000a4a7`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filepath_path_canary_046000a4a7`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_canary_046000a4a7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 55. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?id=-1_cff_marker_id_numeric_boundary_d4b587b677`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_d4b587b677`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_d4b587b677` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 56. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?id=0_cff_marker_id_numeric_boundary_9e4c6c3068`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_9e4c6c3068`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_9e4c6c3068` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 57. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?id=1_cff_marker_id_numeric_boundary_e21fa126c9`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_e21fa126c9`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_e21fa126c9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 58. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?id=999999_cff_marker_id_numeric_boundary_0f75b4c937`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_0f75b4c937`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_0f75b4c937` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 59. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?itemid=-1_cff_marker_itemid_numeric_boundary_0392a62a61`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_itemid_numeric_boundary_0392a62a61`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_0392a62a61` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 60. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?itemid=0_cff_marker_itemid_numeric_boundary_e07901b97d`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_itemid_numeric_boundary_e07901b97d`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_e07901b97d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 61. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?itemid=1_cff_marker_itemid_numeric_boundary_4d59b399b1`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_itemid_numeric_boundary_4d59b399b1`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_4d59b399b1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 62. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?itemid=999999_cff_marker_itemid_numeric_boundary_aaef626a13`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_itemid_numeric_boundary_aaef626a13`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_aaef626a13` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 63. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?moodlewsrestformat=%3Ccff_marker_moodlewsrestformat_xss_reflection_probe_3cbca6ca22%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_moodlewsrestformat_xss_reflection_probe_3cbca6ca22&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_reflection_probe_3cbca6ca22` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 64. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?moodlewsrestformat=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_93c36e4763%27%29%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_93c36e4763&#x27;)&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_93c36e4763` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 65. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?moodlewsrestformat=%3Cscript%3Ealert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_5428f6d1d1%27%29%3C%2Fscript%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_5428f6d1d1&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_5428f6d1d1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 66. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?moodlewsrestformat=cff_marker_moodlewsrestformat_text_canary_994b7fa637`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_moodlewsrestformat_text_canary_994b7fa637`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_text_canary_994b7fa637` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 67. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?page=-1_cff_marker_page_numeric_boundary_30011ae59d`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_30011ae59d`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_30011ae59d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 68. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?page=0_cff_marker_page_numeric_boundary_18eaf95e5b`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_18eaf95e5b`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_18eaf95e5b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 69. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?page=1_cff_marker_page_numeric_boundary_faf6ba3829`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_faf6ba3829`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_faf6ba3829` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 70. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?page=999999_cff_marker_page_numeric_boundary_cab16eb316`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_cab16eb316`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_cab16eb316` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 71. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?q=%3Ccff_marker_q_xss_reflection_probe_bc07c1295f%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_bc07c1295f&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_reflection_probe_bc07c1295f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 72. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_q_xss_trigger_probe_9b485da53d%27%29%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_q_xss_trigger_probe_9b485da53d&#x27;)&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_trigger_probe_9b485da53d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 73. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?q=%3Cscript%3Ealert%28%27cff_marker_q_xss_trigger_probe_58cbb18093%27%29%3C%2Fscript%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_q_xss_trigger_probe_58cbb18093&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_trigger_probe_58cbb18093` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 74. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?q=cff_marker_q_text_canary_7c1697d9e1`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_7c1697d9e1`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_text_canary_7c1697d9e1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 75. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_58beaf126e`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_58beaf126e`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_58beaf126e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 76. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_aa6ba350b7`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_aa6ba350b7`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_aa6ba350b7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 77. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_4656200f59`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_4656200f59`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_4656200f59` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 78. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_91ffa97981`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_91ffa97981`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_91ffa97981` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 79. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?search=%3Ccff_marker_search_xss_reflection_probe_1a3d64bcb4%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_1a3d64bcb4&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_reflection_probe_1a3d64bcb4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 80. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_18df6263d7%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_18df6263d7&#x27;)&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_18df6263d7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 81. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_ba3b910b09%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_ba3b910b09&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_ba3b910b09` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 82. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?search=cff_marker_search_text_canary_127b87fcf7`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_127b87fcf7`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_text_canary_127b87fcf7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 83. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?section=-1_cff_marker_section_numeric_boundary_a3a05d6438`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_a3a05d6438`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_a3a05d6438` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 84. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?section=0_cff_marker_section_numeric_boundary_8b98d54ead`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_8b98d54ead`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_8b98d54ead` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 85. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?section=1_cff_marker_section_numeric_boundary_ba4cf3ea07`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_ba4cf3ea07`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_ba4cf3ea07` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 86. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?section=999999_cff_marker_section_numeric_boundary_e5e0b412c8`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_e5e0b412c8`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_e5e0b412c8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 87. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?sesskey=cff_marker_sesskey_token_canary_b6cbde2a3d`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_b6cbde2a3d`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_canary_b6cbde2a3d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 88. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?sesskey=cff_marker_sesskey_token_empty_c58f9485cc`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_c58f9485cc`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_empty_c58f9485cc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 89. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_644fec6cb1`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_644fec6cb1`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_invalid_644fec6cb1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 90. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?user=-1_cff_marker_user_numeric_boundary_a1e4ac3528`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_a1e4ac3528`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_a1e4ac3528` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 91. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?user=0_cff_marker_user_numeric_boundary_5d1a08a3fd`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_5d1a08a3fd`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_5d1a08a3fd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 92. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?user=1_cff_marker_user_numeric_boundary_b03fd6411c`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_b03fd6411c`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_b03fd6411c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 93. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?user=999999_cff_marker_user_numeric_boundary_0f1d911531`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_0f1d911531`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_0f1d911531` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 94. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?userid=-1_cff_marker_userid_numeric_boundary_ccfcef201d`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_ccfcef201d`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_ccfcef201d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 95. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?userid=0_cff_marker_userid_numeric_boundary_be7aa927db`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_be7aa927db`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_be7aa927db` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 96. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?userid=1_cff_marker_userid_numeric_boundary_07b767944f`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_07b767944f`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_07b767944f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 97. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?userid=999999_cff_marker_userid_numeric_boundary_abd7465abd`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_abd7465abd`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_abd7465abd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 98. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_8bb2e03b6f%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_8bb2e03b6f&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_reflection_probe_8bb2e03b6f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 99. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?wsfunction=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_wsfunction_xss_trigger_probe_9234c82aee%27%29%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_9234c82aee&#x27;)&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_trigger_probe_9234c82aee` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 100. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?wsfunction=%3Cscript%3Ealert%28%27cff_marker_wsfunction_xss_trigger_probe_c361bdce53%27%29%3C%2Fscript%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_c361bdce53&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_trigger_probe_c361bdce53` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 101. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?wsfunction=cff_marker_wsfunction_text_canary_870a212045`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_870a212045`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_text_canary_870a212045` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 102. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?wstoken=cff_marker_wstoken_token_canary_6de56c3fd4`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_6de56c3fd4`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_canary_6de56c3fd4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 103. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?wstoken=cff_marker_wstoken_token_empty_b34bfd349e`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_b34bfd349e`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_empty_b34bfd349e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 104. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_9adefd9181`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_9adefd9181`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_invalid_9adefd9181` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 105. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?filearea=..%2F..%2Fcff_marker_filearea_path_traversal_probe_1870fb3b8c`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filearea_path_traversal_probe_1870fb3b8c`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filearea_path_traversal_probe_1870fb3b8c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 106. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?filearea=..%2Fcff_marker_filearea_path_traversal_probe_51523ff050`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filearea_path_traversal_probe_51523ff050`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filearea_path_traversal_probe_51523ff050` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 107. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?filename=..%2F..%2Fcff_marker_filename_path_traversal_probe_af20a3426c`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filename_path_traversal_probe_af20a3426c`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filename_path_traversal_probe_af20a3426c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 108. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?filename=..%2Fcff_marker_filename_path_traversal_probe_50aed71dec`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filename_path_traversal_probe_50aed71dec`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filename_path_traversal_probe_50aed71dec` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 109. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?filepath=..%2F..%2Fcff_marker_filepath_path_traversal_probe_d97eb7c99b`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filepath_path_traversal_probe_d97eb7c99b`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filepath_path_traversal_probe_d97eb7c99b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 110. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?filepath=..%2Fcff_marker_filepath_path_traversal_probe_ad421e6886`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filepath_path_traversal_probe_ad421e6886`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filepath_path_traversal_probe_ad421e6886` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 111. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?filearea=..%2F..%2Fcff_marker_filearea_path_traversal_probe_4713c63ee9`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filearea_path_traversal_probe_4713c63ee9`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filearea_path_traversal_probe_4713c63ee9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 112. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?filearea=..%2Fcff_marker_filearea_path_traversal_probe_a8ba1d6de5`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filearea_path_traversal_probe_a8ba1d6de5`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filearea_path_traversal_probe_a8ba1d6de5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 113. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?filename=..%2F..%2Fcff_marker_filename_path_traversal_probe_b10c4df713`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filename_path_traversal_probe_b10c4df713`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filename_path_traversal_probe_b10c4df713` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 114. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?filename=..%2Fcff_marker_filename_path_traversal_probe_0197ee4175`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filename_path_traversal_probe_0197ee4175`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filename_path_traversal_probe_0197ee4175` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 115. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?filepath=..%2F..%2Fcff_marker_filepath_path_traversal_probe_99bbe6daf4`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filepath_path_traversal_probe_99bbe6daf4`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filepath_path_traversal_probe_99bbe6daf4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 116. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?filepath=..%2Fcff_marker_filepath_path_traversal_probe_f9574555c9`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filepath_path_traversal_probe_f9574555c9`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filepath_path_traversal_probe_f9574555c9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 117. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?component=%3Ccff_marker_component_xss_reflection_probe_8166e7a3a9%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_component_xss_reflection_probe_8166e7a3a9&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_reflection_probe_8166e7a3a9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 118. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?component=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_component_xss_trigger_probe_641021b0da%27%29%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_component_xss_trigger_probe_641021b0da&#x27;)&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_trigger_probe_641021b0da` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 119. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?component=%3Cscript%3Ealert%28%27cff_marker_component_xss_trigger_probe_b031029a85%27%29%3C%2Fscript%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_component_xss_trigger_probe_b031029a85&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_trigger_probe_b031029a85` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 120. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?component=cff_marker_component_text_canary_1cda6c6cad`
- Parameter: `component` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_component_text_canary_1cda6c6cad`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_text_canary_1cda6c6cad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 121. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?contextid=-1_cff_marker_contextid_numeric_boundary_80be0a0074`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_contextid_numeric_boundary_80be0a0074`
- Response: HTTP `200` / Length `148` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_80be0a0074` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `148`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 122. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?contextid=0_cff_marker_contextid_numeric_boundary_e94bf99384`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_contextid_numeric_boundary_e94bf99384`
- Response: HTTP `200` / Length `208` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_e94bf99384` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `208`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 123. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?contextid=1_cff_marker_contextid_numeric_boundary_fbe8d825ee`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_contextid_numeric_boundary_fbe8d825ee`
- Response: HTTP `200` / Length `137` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_fbe8d825ee` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `137`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 124. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?contextid=999999_cff_marker_contextid_numeric_boundary_1f51feb1b0`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_contextid_numeric_boundary_1f51feb1b0`
- Response: HTTP `200` / Length `148` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_1f51feb1b0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `148`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 125. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?course=-1_cff_marker_course_numeric_boundary_8e5a9db019`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_8e5a9db019`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_8e5a9db019` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 126. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?course=0_cff_marker_course_numeric_boundary_f8caa526e0`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_f8caa526e0`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_f8caa526e0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 127. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?course=1_cff_marker_course_numeric_boundary_3be6084950`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_3be6084950`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_3be6084950` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 128. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?course=999999_cff_marker_course_numeric_boundary_6e536c21b8`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_6e536c21b8`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_6e536c21b8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 129. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?courseid=-1_cff_marker_courseid_numeric_boundary_af80422910`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_af80422910`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_af80422910` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 130. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?courseid=0_cff_marker_courseid_numeric_boundary_e3952594e2`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_e3952594e2`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_e3952594e2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 131. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?courseid=1_cff_marker_courseid_numeric_boundary_6cea0fa4ae`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_6cea0fa4ae`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_6cea0fa4ae` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 132. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?courseid=999999_cff_marker_courseid_numeric_boundary_d71d7563fe`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_d71d7563fe`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_d71d7563fe` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 133. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?filearea=..%2F..%2Fcff_marker_filearea_path_traversal_probe_8c6e92ba80`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filearea_path_traversal_probe_8c6e92ba80`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_traversal_probe_8c6e92ba80` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 134. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?filearea=..%2Fcff_marker_filearea_path_traversal_probe_134b9ac897`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filearea_path_traversal_probe_134b9ac897`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_traversal_probe_134b9ac897` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 135. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?filearea=cff_marker_filearea_path_canary_a260b24452`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filearea_path_canary_a260b24452`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_canary_a260b24452` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 136. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?filename=..%2F..%2Fcff_marker_filename_path_traversal_probe_02bfc6bd8b`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filename_path_traversal_probe_02bfc6bd8b`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_traversal_probe_02bfc6bd8b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 137. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?filename=..%2Fcff_marker_filename_path_traversal_probe_5a6fc2e686`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filename_path_traversal_probe_5a6fc2e686`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_traversal_probe_5a6fc2e686` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 138. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?filename=cff_marker_filename_path_canary_bf0eab0805`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filename_path_canary_bf0eab0805`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_canary_bf0eab0805` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 139. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?filepath=..%2F..%2Fcff_marker_filepath_path_traversal_probe_3ecfa56bef`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filepath_path_traversal_probe_3ecfa56bef`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_traversal_probe_3ecfa56bef` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 140. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?filepath=..%2Fcff_marker_filepath_path_traversal_probe_ee242703a7`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filepath_path_traversal_probe_ee242703a7`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_traversal_probe_ee242703a7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 141. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?filepath=cff_marker_filepath_path_canary_24a218aac9`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filepath_path_canary_24a218aac9`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_canary_24a218aac9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 142. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?id=-1_cff_marker_id_numeric_boundary_c61e2f8d42`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_c61e2f8d42`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_c61e2f8d42` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 143. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?id=0_cff_marker_id_numeric_boundary_a0b4a2d118`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_a0b4a2d118`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_a0b4a2d118` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 144. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?id=1_cff_marker_id_numeric_boundary_9dc1a49d29`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_9dc1a49d29`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_9dc1a49d29` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 145. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?id=999999_cff_marker_id_numeric_boundary_9fed7deefd`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_9fed7deefd`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_9fed7deefd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 146. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?itemid=-1_cff_marker_itemid_numeric_boundary_c2d9733688`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_itemid_numeric_boundary_c2d9733688`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_c2d9733688` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 147. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?itemid=0_cff_marker_itemid_numeric_boundary_93dfe378e6`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_itemid_numeric_boundary_93dfe378e6`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_93dfe378e6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 148. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?itemid=1_cff_marker_itemid_numeric_boundary_48b08081a3`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_itemid_numeric_boundary_48b08081a3`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_48b08081a3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 149. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?itemid=999999_cff_marker_itemid_numeric_boundary_2ad7e4b1e0`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_itemid_numeric_boundary_2ad7e4b1e0`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_2ad7e4b1e0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 150. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?moodlewsrestformat=%3Ccff_marker_moodlewsrestformat_xss_reflection_probe_0e4d34531e%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_moodlewsrestformat_xss_reflection_probe_0e4d34531e&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_reflection_probe_0e4d34531e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 151. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?moodlewsrestformat=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_7bda72ee58%27%29%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_7bda72ee58&#x27;)&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_7bda72ee58` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 152. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?moodlewsrestformat=%3Cscript%3Ealert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_479b1bfb31%27%29%3C%2Fscript%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_479b1bfb31&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_479b1bfb31` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 153. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?moodlewsrestformat=cff_marker_moodlewsrestformat_text_canary_dbd64b2cdd`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_moodlewsrestformat_text_canary_dbd64b2cdd`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_text_canary_dbd64b2cdd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 154. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?page=-1_cff_marker_page_numeric_boundary_39d6cce3aa`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_39d6cce3aa`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_39d6cce3aa` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 155. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?page=0_cff_marker_page_numeric_boundary_314f515d03`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_314f515d03`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_314f515d03` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 156. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?page=1_cff_marker_page_numeric_boundary_97da7bd0e4`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_97da7bd0e4`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_97da7bd0e4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 157. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?page=999999_cff_marker_page_numeric_boundary_fb26f53f30`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_fb26f53f30`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_fb26f53f30` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 158. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?q=%3Ccff_marker_q_xss_reflection_probe_94ec169d6c%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_94ec169d6c&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_reflection_probe_94ec169d6c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 159. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_q_xss_trigger_probe_80a82e68e4%27%29%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_q_xss_trigger_probe_80a82e68e4&#x27;)&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_trigger_probe_80a82e68e4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 160. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?q=%3Cscript%3Ealert%28%27cff_marker_q_xss_trigger_probe_952242ad03%27%29%3C%2Fscript%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_q_xss_trigger_probe_952242ad03&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_trigger_probe_952242ad03` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 161. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?q=cff_marker_q_text_canary_1520e514a4`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_1520e514a4`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_text_canary_1520e514a4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 162. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_0e0b6353da`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_0e0b6353da`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_0e0b6353da` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 163. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_0b9b5dcf0a`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_0b9b5dcf0a`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_0b9b5dcf0a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 164. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_e7cfb18b45`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_e7cfb18b45`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_e7cfb18b45` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 165. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_141e2b4ae2`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_141e2b4ae2`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_141e2b4ae2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 166. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?search=%3Ccff_marker_search_xss_reflection_probe_b4eeef0324%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_b4eeef0324&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_reflection_probe_b4eeef0324` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 167. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_74d457bbcc%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_74d457bbcc&#x27;)&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_74d457bbcc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 168. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_10a2d8ee19%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_10a2d8ee19&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_10a2d8ee19` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 169. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?search=cff_marker_search_text_canary_b5e7f306ad`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_b5e7f306ad`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_text_canary_b5e7f306ad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 170. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?section=-1_cff_marker_section_numeric_boundary_9636a6b112`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_9636a6b112`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_9636a6b112` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 171. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?section=0_cff_marker_section_numeric_boundary_79d73e0324`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_79d73e0324`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_79d73e0324` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 172. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?section=1_cff_marker_section_numeric_boundary_54af4ba543`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_54af4ba543`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_54af4ba543` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 173. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?section=999999_cff_marker_section_numeric_boundary_3d67b2eb1e`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_3d67b2eb1e`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_3d67b2eb1e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 174. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?sesskey=cff_marker_sesskey_token_canary_10e0202d3e`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_10e0202d3e`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_canary_10e0202d3e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 175. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?sesskey=cff_marker_sesskey_token_empty_489d790f2d`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_489d790f2d`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_empty_489d790f2d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 176. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_bce3cefd61`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_bce3cefd61`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_invalid_bce3cefd61` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 177. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?user=-1_cff_marker_user_numeric_boundary_cffd911f2d`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_cffd911f2d`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_cffd911f2d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 178. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?user=0_cff_marker_user_numeric_boundary_6bb82ffcf2`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_6bb82ffcf2`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_6bb82ffcf2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 179. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?user=1_cff_marker_user_numeric_boundary_b4246e42c1`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_b4246e42c1`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_b4246e42c1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 180. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?user=999999_cff_marker_user_numeric_boundary_8f658c9e4c`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_8f658c9e4c`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_8f658c9e4c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 181. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?userid=-1_cff_marker_userid_numeric_boundary_aaf06a8ded`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_aaf06a8ded`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_aaf06a8ded` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 182. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?userid=0_cff_marker_userid_numeric_boundary_7a88c57bd3`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_7a88c57bd3`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_7a88c57bd3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 183. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?userid=1_cff_marker_userid_numeric_boundary_a556ca32fd`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_a556ca32fd`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_a556ca32fd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 184. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?userid=999999_cff_marker_userid_numeric_boundary_96bef56eee`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_96bef56eee`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_96bef56eee` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 185. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_b3f1cebe58%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_b3f1cebe58&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_reflection_probe_b3f1cebe58` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 186. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?wsfunction=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_wsfunction_xss_trigger_probe_9edc0813b8%27%29%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_9edc0813b8&#x27;)&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_trigger_probe_9edc0813b8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 187. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?wsfunction=%3Cscript%3Ealert%28%27cff_marker_wsfunction_xss_trigger_probe_63dc30a1a5%27%29%3C%2Fscript%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_63dc30a1a5&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_trigger_probe_63dc30a1a5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 188. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?wsfunction=cff_marker_wsfunction_text_canary_0aca49de60`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_0aca49de60`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_text_canary_0aca49de60` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 189. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?wstoken=cff_marker_wstoken_token_canary_ffd5b69259`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_ffd5b69259`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_canary_ffd5b69259` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 190. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?wstoken=cff_marker_wstoken_token_empty_872d3f177c`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_872d3f177c`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_empty_872d3f177c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 191. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_5e03b83fdc`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_5e03b83fdc`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_invalid_5e03b83fdc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint; debug/error keyword appeared in response

### 192. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?component=%3Ccff_marker_component_xss_reflection_probe_1894738029%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_component_xss_reflection_probe_1894738029&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_reflection_probe_1894738029` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 193. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?component=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_component_xss_trigger_probe_709166042d%27%29%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_component_xss_trigger_probe_709166042d&#x27;)&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_trigger_probe_709166042d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 194. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?component=%3Cscript%3Ealert%28%27cff_marker_component_xss_trigger_probe_3bfa675181%27%29%3C%2Fscript%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_component_xss_trigger_probe_3bfa675181&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_trigger_probe_3bfa675181` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 195. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?component=cff_marker_component_text_canary_d68f429b6c`
- Parameter: `component` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_component_text_canary_d68f429b6c`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_text_canary_d68f429b6c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 196. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?contextid=-1_cff_marker_contextid_numeric_boundary_1587316608`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_contextid_numeric_boundary_1587316608`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_1587316608` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 197. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?contextid=0_cff_marker_contextid_numeric_boundary_8ddefdd85f`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_contextid_numeric_boundary_8ddefdd85f`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_8ddefdd85f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 198. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?contextid=1_cff_marker_contextid_numeric_boundary_c6bb634227`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_contextid_numeric_boundary_c6bb634227`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_c6bb634227` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 199. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?contextid=999999_cff_marker_contextid_numeric_boundary_5860d75aa6`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_contextid_numeric_boundary_5860d75aa6`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_5860d75aa6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 200. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?course=-1_cff_marker_course_numeric_boundary_8c456ce4a8`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_8c456ce4a8`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_8c456ce4a8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 201. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?course=0_cff_marker_course_numeric_boundary_6d2dd4a876`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_6d2dd4a876`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_6d2dd4a876` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 202. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?course=1_cff_marker_course_numeric_boundary_77806e747d`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_77806e747d`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_77806e747d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 203. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?course=999999_cff_marker_course_numeric_boundary_1524428037`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_1524428037`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_1524428037` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 204. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?courseid=-1_cff_marker_courseid_numeric_boundary_385fec4b07`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_385fec4b07`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_385fec4b07` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 205. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?courseid=0_cff_marker_courseid_numeric_boundary_b53a9e0a04`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_b53a9e0a04`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_b53a9e0a04` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 206. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?courseid=1_cff_marker_courseid_numeric_boundary_c994b411d9`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_c994b411d9`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_c994b411d9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 207. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?courseid=999999_cff_marker_courseid_numeric_boundary_780faf0f58`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_780faf0f58`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_780faf0f58` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 208. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?filearea=cff_marker_filearea_path_canary_749d65babb`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filearea_path_canary_749d65babb`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_canary_749d65babb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 209. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?filename=cff_marker_filename_path_canary_d747de7f9e`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filename_path_canary_d747de7f9e`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_canary_d747de7f9e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 210. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?filepath=cff_marker_filepath_path_canary_5a3513f57f`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filepath_path_canary_5a3513f57f`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_canary_5a3513f57f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 211. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?id=-1_cff_marker_id_numeric_boundary_e92f88feec`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_e92f88feec`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_e92f88feec` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 212. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?id=0_cff_marker_id_numeric_boundary_f1d29f6b6f`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_f1d29f6b6f`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_f1d29f6b6f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 213. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?id=1_cff_marker_id_numeric_boundary_55ed660ae0`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_55ed660ae0`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_55ed660ae0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 214. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?id=999999_cff_marker_id_numeric_boundary_9043883f56`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_9043883f56`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_9043883f56` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 215. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?itemid=-1_cff_marker_itemid_numeric_boundary_f2db4a90f3`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_itemid_numeric_boundary_f2db4a90f3`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_f2db4a90f3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 216. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?itemid=0_cff_marker_itemid_numeric_boundary_802438f572`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_itemid_numeric_boundary_802438f572`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_802438f572` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 217. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?itemid=1_cff_marker_itemid_numeric_boundary_01b0a70b3c`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_itemid_numeric_boundary_01b0a70b3c`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_01b0a70b3c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 218. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?itemid=999999_cff_marker_itemid_numeric_boundary_610361d363`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_itemid_numeric_boundary_610361d363`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_610361d363` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 219. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?moodlewsrestformat=%3Ccff_marker_moodlewsrestformat_xss_reflection_probe_7312f51592%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_moodlewsrestformat_xss_reflection_probe_7312f51592&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_reflection_probe_7312f51592` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 220. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?moodlewsrestformat=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_99a7f8f427%27%29%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_99a7f8f427&#x27;)&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_99a7f8f427` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 221. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?moodlewsrestformat=%3Cscript%3Ealert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_06a9d2f5f2%27%29%3C%2Fscript%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_06a9d2f5f2&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_06a9d2f5f2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 222. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?moodlewsrestformat=cff_marker_moodlewsrestformat_text_canary_c0eb1b9c6b`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_moodlewsrestformat_text_canary_c0eb1b9c6b`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_text_canary_c0eb1b9c6b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 223. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?page=-1_cff_marker_page_numeric_boundary_a4ee9ae8bc`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_a4ee9ae8bc`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_a4ee9ae8bc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 224. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?page=0_cff_marker_page_numeric_boundary_7f0b7e0eee`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_7f0b7e0eee`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_7f0b7e0eee` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 225. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?page=1_cff_marker_page_numeric_boundary_5492fd2c4a`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_5492fd2c4a`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_5492fd2c4a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 226. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?page=999999_cff_marker_page_numeric_boundary_51364cb989`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_51364cb989`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_51364cb989` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 227. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?q=%3Ccff_marker_q_xss_reflection_probe_0fd5543ce7%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_0fd5543ce7&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_reflection_probe_0fd5543ce7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 228. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_q_xss_trigger_probe_ba9ae6b307%27%29%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_q_xss_trigger_probe_ba9ae6b307&#x27;)&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_trigger_probe_ba9ae6b307` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 229. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?q=%3Cscript%3Ealert%28%27cff_marker_q_xss_trigger_probe_b903109705%27%29%3C%2Fscript%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_q_xss_trigger_probe_b903109705&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_trigger_probe_b903109705` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 230. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?q=cff_marker_q_text_canary_b17ba70ede`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_b17ba70ede`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_text_canary_b17ba70ede` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 231. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_fd4cbdfbd5`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_fd4cbdfbd5`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_fd4cbdfbd5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 232. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_a1cc09dc05`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_a1cc09dc05`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_a1cc09dc05` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 233. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_9d3db0b36d`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_9d3db0b36d`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_9d3db0b36d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 234. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_348d72c326`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_348d72c326`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_348d72c326` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 235. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?search=%3Ccff_marker_search_xss_reflection_probe_bf91d87c35%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_bf91d87c35&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_reflection_probe_bf91d87c35` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 236. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_d4d21035f2%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_d4d21035f2&#x27;)&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_d4d21035f2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 237. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_6efe403e12%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_6efe403e12&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_6efe403e12` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 238. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?search=cff_marker_search_text_canary_bb1034c7bb`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_bb1034c7bb`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_text_canary_bb1034c7bb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 239. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?section=-1_cff_marker_section_numeric_boundary_d29f2c83b5`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_d29f2c83b5`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_d29f2c83b5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 240. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?section=0_cff_marker_section_numeric_boundary_3296715658`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_3296715658`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_3296715658` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 241. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?section=1_cff_marker_section_numeric_boundary_f4789f49f5`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_f4789f49f5`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_f4789f49f5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 242. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?section=999999_cff_marker_section_numeric_boundary_4ef5dab166`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_4ef5dab166`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_4ef5dab166` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 243. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?sesskey=cff_marker_sesskey_token_canary_c2c85f4de0`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_c2c85f4de0`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_canary_c2c85f4de0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 244. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?sesskey=cff_marker_sesskey_token_empty_6d628e855c`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_6d628e855c`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_empty_6d628e855c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 245. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_943e92d01c`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_943e92d01c`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_invalid_943e92d01c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 246. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?user=-1_cff_marker_user_numeric_boundary_aa5ff36201`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_aa5ff36201`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_aa5ff36201` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 247. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?user=0_cff_marker_user_numeric_boundary_59ded4bf27`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_59ded4bf27`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_59ded4bf27` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 248. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?user=1_cff_marker_user_numeric_boundary_d629e3a979`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_d629e3a979`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_d629e3a979` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 249. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?user=999999_cff_marker_user_numeric_boundary_5bb5e10742`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_5bb5e10742`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_5bb5e10742` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 250. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?userid=-1_cff_marker_userid_numeric_boundary_f9901b387f`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_f9901b387f`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_f9901b387f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 251. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?userid=0_cff_marker_userid_numeric_boundary_acbdf6f8a4`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_acbdf6f8a4`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_acbdf6f8a4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 252. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?userid=1_cff_marker_userid_numeric_boundary_f0b962de83`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_f0b962de83`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_f0b962de83` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 253. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?userid=999999_cff_marker_userid_numeric_boundary_eb9a637264`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_eb9a637264`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_eb9a637264` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 254. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_25cf270d33%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_25cf270d33&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_reflection_probe_25cf270d33` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 255. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?wsfunction=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_wsfunction_xss_trigger_probe_c60eafdd31%27%29%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_c60eafdd31&#x27;)&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_trigger_probe_c60eafdd31` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 256. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?wsfunction=%3Cscript%3Ealert%28%27cff_marker_wsfunction_xss_trigger_probe_3d67356d59%27%29%3C%2Fscript%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_3d67356d59&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_trigger_probe_3d67356d59` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 257. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?wsfunction=cff_marker_wsfunction_text_canary_26b526bd8a`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_26b526bd8a`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_text_canary_26b526bd8a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 258. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?wstoken=cff_marker_wstoken_token_canary_0894b718a7`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_0894b718a7`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_canary_0894b718a7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 259. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?wstoken=cff_marker_wstoken_token_empty_e1e20110fb`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_e1e20110fb`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_empty_e1e20110fb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 260. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_f36304372e`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_f36304372e`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_invalid_f36304372e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 261. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?component=%3Ccff_marker_component_xss_reflection_probe_8972274015%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_component_xss_reflection_probe_8972274015&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_reflection_probe_8972274015` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 262. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?component=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_component_xss_trigger_probe_477e0d4e7c%27%29%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_component_xss_trigger_probe_477e0d4e7c&#x27;)&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_trigger_probe_477e0d4e7c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 263. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?component=%3Cscript%3Ealert%28%27cff_marker_component_xss_trigger_probe_5b48ba5162%27%29%3C%2Fscript%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_component_xss_trigger_probe_5b48ba5162&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_trigger_probe_5b48ba5162` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 264. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?component=cff_marker_component_text_canary_23b83524aa`
- Parameter: `component` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_component_text_canary_23b83524aa`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_text_canary_23b83524aa` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 265. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?contextid=-1_cff_marker_contextid_numeric_boundary_0baf1b4c46`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_contextid_numeric_boundary_0baf1b4c46`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_0baf1b4c46` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 266. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?contextid=0_cff_marker_contextid_numeric_boundary_b4a74e51bd`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_contextid_numeric_boundary_b4a74e51bd`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_b4a74e51bd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 267. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?contextid=1_cff_marker_contextid_numeric_boundary_98a28f6fd0`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_contextid_numeric_boundary_98a28f6fd0`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_98a28f6fd0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 268. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?contextid=999999_cff_marker_contextid_numeric_boundary_df8d0237fb`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_contextid_numeric_boundary_df8d0237fb`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_df8d0237fb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 269. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?course=-1_cff_marker_course_numeric_boundary_525a9a9dee`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_525a9a9dee`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_525a9a9dee` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 270. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?course=0_cff_marker_course_numeric_boundary_e65eab313a`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_e65eab313a`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_e65eab313a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 271. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?course=1_cff_marker_course_numeric_boundary_92c922b724`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_92c922b724`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_92c922b724` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 272. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?course=999999_cff_marker_course_numeric_boundary_1e6dee977d`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_1e6dee977d`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_1e6dee977d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 273. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?courseid=-1_cff_marker_courseid_numeric_boundary_596517499c`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_596517499c`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_596517499c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 274. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?courseid=0_cff_marker_courseid_numeric_boundary_2f19aed9d7`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_2f19aed9d7`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_2f19aed9d7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 275. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?courseid=1_cff_marker_courseid_numeric_boundary_d885a3f660`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_d885a3f660`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_d885a3f660` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 276. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?courseid=999999_cff_marker_courseid_numeric_boundary_f436c49f42`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_f436c49f42`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_f436c49f42` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 277. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?filearea=..%2F..%2Fcff_marker_filearea_path_traversal_probe_fce65e9e53`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filearea_path_traversal_probe_fce65e9e53`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_traversal_probe_fce65e9e53` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 278. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?filearea=..%2Fcff_marker_filearea_path_traversal_probe_670b575629`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filearea_path_traversal_probe_670b575629`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_traversal_probe_670b575629` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 279. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?filearea=cff_marker_filearea_path_canary_6b28b41b20`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filearea_path_canary_6b28b41b20`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_canary_6b28b41b20` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 280. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?filename=..%2F..%2Fcff_marker_filename_path_traversal_probe_834316a899`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filename_path_traversal_probe_834316a899`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_traversal_probe_834316a899` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 281. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?filename=..%2Fcff_marker_filename_path_traversal_probe_f9be4caf08`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filename_path_traversal_probe_f9be4caf08`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_traversal_probe_f9be4caf08` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 282. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?filename=cff_marker_filename_path_canary_8a5499df6d`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filename_path_canary_8a5499df6d`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_canary_8a5499df6d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 283. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?filepath=..%2F..%2Fcff_marker_filepath_path_traversal_probe_8dbf0d98b5`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filepath_path_traversal_probe_8dbf0d98b5`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_traversal_probe_8dbf0d98b5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 284. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?filepath=..%2Fcff_marker_filepath_path_traversal_probe_a8719277db`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filepath_path_traversal_probe_a8719277db`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_traversal_probe_a8719277db` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 285. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?filepath=cff_marker_filepath_path_canary_2766b986f9`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filepath_path_canary_2766b986f9`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_canary_2766b986f9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 286. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?id=-1_cff_marker_id_numeric_boundary_6cbb4eac62`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_6cbb4eac62`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_6cbb4eac62` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 287. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?id=0_cff_marker_id_numeric_boundary_dffc1f7a98`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_dffc1f7a98`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_dffc1f7a98` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 288. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?id=1_cff_marker_id_numeric_boundary_9588508461`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_9588508461`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_9588508461` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 289. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?id=999999_cff_marker_id_numeric_boundary_1f0b6a6467`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_1f0b6a6467`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_1f0b6a6467` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 290. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?itemid=-1_cff_marker_itemid_numeric_boundary_534aad06a3`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_itemid_numeric_boundary_534aad06a3`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_534aad06a3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 291. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?itemid=0_cff_marker_itemid_numeric_boundary_689fd40504`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_itemid_numeric_boundary_689fd40504`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_689fd40504` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 292. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?itemid=1_cff_marker_itemid_numeric_boundary_bf8608b591`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_itemid_numeric_boundary_bf8608b591`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_bf8608b591` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 293. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?itemid=999999_cff_marker_itemid_numeric_boundary_a694d1a879`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_itemid_numeric_boundary_a694d1a879`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_a694d1a879` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 294. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?moodlewsrestformat=%3Ccff_marker_moodlewsrestformat_xss_reflection_probe_776252827c%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_moodlewsrestformat_xss_reflection_probe_776252827c&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_reflection_probe_776252827c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 295. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?moodlewsrestformat=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_b5f4e6424d%27%29%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_b5f4e6424d&#x27;)&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_b5f4e6424d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 296. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?moodlewsrestformat=%3Cscript%3Ealert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_c3b0e5bd24%27%29%3C%2Fscript%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_c3b0e5bd24&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_c3b0e5bd24` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 297. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?moodlewsrestformat=cff_marker_moodlewsrestformat_text_canary_9c59cc56e8`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_moodlewsrestformat_text_canary_9c59cc56e8`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_text_canary_9c59cc56e8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 298. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?page=-1_cff_marker_page_numeric_boundary_36c4050e21`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_36c4050e21`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_36c4050e21` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 299. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?page=0_cff_marker_page_numeric_boundary_eef22b2797`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_eef22b2797`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_eef22b2797` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 300. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?page=1_cff_marker_page_numeric_boundary_4112cbb49f`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_4112cbb49f`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_4112cbb49f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 301. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?page=999999_cff_marker_page_numeric_boundary_ed86a20065`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_ed86a20065`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_ed86a20065` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 302. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?q=%3Ccff_marker_q_xss_reflection_probe_62a5c51a15%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_62a5c51a15&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_reflection_probe_62a5c51a15` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 303. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_q_xss_trigger_probe_a265159aa1%27%29%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_q_xss_trigger_probe_a265159aa1&#x27;)&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_trigger_probe_a265159aa1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 304. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?q=%3Cscript%3Ealert%28%27cff_marker_q_xss_trigger_probe_58348bc4a8%27%29%3C%2Fscript%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_q_xss_trigger_probe_58348bc4a8&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_trigger_probe_58348bc4a8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 305. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?q=cff_marker_q_text_canary_1afe7abdbd`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_1afe7abdbd`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_text_canary_1afe7abdbd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 306. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_73d3372078`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_73d3372078`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_73d3372078` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 307. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_3fca0893f7`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_3fca0893f7`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_3fca0893f7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 308. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_d10149f4a5`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_d10149f4a5`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_d10149f4a5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 309. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_7f7b464e08`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_7f7b464e08`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_7f7b464e08` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 310. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?search=%3Ccff_marker_search_xss_reflection_probe_e5a0f099a1%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_e5a0f099a1&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_reflection_probe_e5a0f099a1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 311. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_95ae61822c%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_95ae61822c&#x27;)&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_95ae61822c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 312. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_a142fade5e%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_a142fade5e&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_a142fade5e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 313. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?search=cff_marker_search_text_canary_cccd462291`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_cccd462291`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_text_canary_cccd462291` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 314. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?section=-1_cff_marker_section_numeric_boundary_7b32d250ec`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_7b32d250ec`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_7b32d250ec` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 315. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?section=0_cff_marker_section_numeric_boundary_4b9e0924f0`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_4b9e0924f0`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_4b9e0924f0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 316. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?section=1_cff_marker_section_numeric_boundary_c21b896e8d`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_c21b896e8d`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_c21b896e8d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 317. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?section=999999_cff_marker_section_numeric_boundary_058f03342d`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_058f03342d`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_058f03342d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 318. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?sesskey=cff_marker_sesskey_token_canary_13af77883b`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_13af77883b`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_canary_13af77883b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 319. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?sesskey=cff_marker_sesskey_token_empty_b692075841`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_b692075841`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_empty_b692075841` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 320. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_d829c6f915`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_d829c6f915`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_invalid_d829c6f915` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 321. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?user=-1_cff_marker_user_numeric_boundary_d17663fa13`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_d17663fa13`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_d17663fa13` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 322. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?user=0_cff_marker_user_numeric_boundary_34c5624699`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_34c5624699`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_34c5624699` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 323. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?user=1_cff_marker_user_numeric_boundary_573d8a2d62`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_573d8a2d62`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_573d8a2d62` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 324. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?user=999999_cff_marker_user_numeric_boundary_b89e7ad301`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_b89e7ad301`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_b89e7ad301` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 325. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?userid=-1_cff_marker_userid_numeric_boundary_6f41f5a621`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_6f41f5a621`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_6f41f5a621` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 326. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?userid=0_cff_marker_userid_numeric_boundary_57cdb396d2`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_57cdb396d2`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_57cdb396d2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 327. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?userid=1_cff_marker_userid_numeric_boundary_ba6f3cc5ad`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_ba6f3cc5ad`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_ba6f3cc5ad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 328. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?userid=999999_cff_marker_userid_numeric_boundary_66defb4795`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_66defb4795`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_66defb4795` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 329. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_9bd16529ac%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_9bd16529ac&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_reflection_probe_9bd16529ac` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 330. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?wsfunction=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_wsfunction_xss_trigger_probe_19261fc4d8%27%29%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_19261fc4d8&#x27;)&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_trigger_probe_19261fc4d8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 331. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?wsfunction=%3Cscript%3Ealert%28%27cff_marker_wsfunction_xss_trigger_probe_29ed74727f%27%29%3C%2Fscript%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_29ed74727f&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_trigger_probe_29ed74727f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 332. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?wsfunction=cff_marker_wsfunction_text_canary_defd86fc56`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_defd86fc56`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_text_canary_defd86fc56` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 333. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?wstoken=cff_marker_wstoken_token_canary_1c4fd3127d`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_1c4fd3127d`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_canary_1c4fd3127d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 334. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?wstoken=cff_marker_wstoken_token_empty_ac0d0a3b8a`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_ac0d0a3b8a`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_empty_ac0d0a3b8a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 335. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_ae18f749b7`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_ae18f749b7`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_invalid_ae18f749b7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; debug/error keyword appeared in response

### 336. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?component=%3Ccff_marker_component_xss_reflection_probe_dc83a7b6bf%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_component_xss_reflection_probe_dc83a7b6bf&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_reflection_probe_dc83a7b6bf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 337. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?component=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_component_xss_trigger_probe_5c5a56de0d%27%29%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_component_xss_trigger_probe_5c5a56de0d&#x27;)&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_trigger_probe_5c5a56de0d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 338. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?component=%3Cscript%3Ealert%28%27cff_marker_component_xss_trigger_probe_02e2b53521%27%29%3C%2Fscript%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_component_xss_trigger_probe_02e2b53521&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_trigger_probe_02e2b53521` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 339. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?component=cff_marker_component_text_canary_482373e151`
- Parameter: `component` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_component_text_canary_482373e151`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_text_canary_482373e151` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 340. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?contextid=-1_cff_marker_contextid_numeric_boundary_602cc477d1`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_contextid_numeric_boundary_602cc477d1`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_602cc477d1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 341. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?contextid=0_cff_marker_contextid_numeric_boundary_7401558bb4`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_contextid_numeric_boundary_7401558bb4`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_7401558bb4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 342. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?contextid=1_cff_marker_contextid_numeric_boundary_4ab69e2e20`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_contextid_numeric_boundary_4ab69e2e20`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_4ab69e2e20` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 343. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?contextid=999999_cff_marker_contextid_numeric_boundary_404f09adfd`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_contextid_numeric_boundary_404f09adfd`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_404f09adfd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 344. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?course=-1_cff_marker_course_numeric_boundary_18cad89273`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_18cad89273`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_18cad89273` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 345. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?course=0_cff_marker_course_numeric_boundary_e8c475f21f`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_e8c475f21f`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_e8c475f21f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 346. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?course=1_cff_marker_course_numeric_boundary_68e1743fd5`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_68e1743fd5`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_68e1743fd5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 347. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?course=999999_cff_marker_course_numeric_boundary_8d0f8953b9`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_8d0f8953b9`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_8d0f8953b9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 348. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?courseid=-1_cff_marker_courseid_numeric_boundary_bebe5244e6`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_bebe5244e6`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_bebe5244e6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 349. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?courseid=0_cff_marker_courseid_numeric_boundary_15460a28ba`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_15460a28ba`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_15460a28ba` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 350. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?courseid=1_cff_marker_courseid_numeric_boundary_32e04d0b0c`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_32e04d0b0c`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_32e04d0b0c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 351. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?courseid=999999_cff_marker_courseid_numeric_boundary_f9b77144fd`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_f9b77144fd`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_f9b77144fd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 352. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?filearea=cff_marker_filearea_path_canary_519585e152`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filearea_path_canary_519585e152`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filearea_path_canary_519585e152` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 353. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?filename=cff_marker_filename_path_canary_d86a70eb8c`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filename_path_canary_d86a70eb8c`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filename_path_canary_d86a70eb8c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 354. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?filepath=cff_marker_filepath_path_canary_6e51b04ebd`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filepath_path_canary_6e51b04ebd`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filepath_path_canary_6e51b04ebd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 355. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?id=-1_cff_marker_id_numeric_boundary_dc132559dd`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_dc132559dd`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_dc132559dd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 356. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?id=0_cff_marker_id_numeric_boundary_a61fd1d146`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_a61fd1d146`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_a61fd1d146` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 357. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?id=1_cff_marker_id_numeric_boundary_b204b1346a`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_b204b1346a`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_b204b1346a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 358. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?id=999999_cff_marker_id_numeric_boundary_4fca910269`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_4fca910269`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_4fca910269` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 359. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?itemid=-1_cff_marker_itemid_numeric_boundary_6c6cf21ea6`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_itemid_numeric_boundary_6c6cf21ea6`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_6c6cf21ea6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 360. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?itemid=0_cff_marker_itemid_numeric_boundary_3220925c5f`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_itemid_numeric_boundary_3220925c5f`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_3220925c5f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 361. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?itemid=1_cff_marker_itemid_numeric_boundary_e06661c95a`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_itemid_numeric_boundary_e06661c95a`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_e06661c95a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 362. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?itemid=999999_cff_marker_itemid_numeric_boundary_80b9405bc9`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_itemid_numeric_boundary_80b9405bc9`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_80b9405bc9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 363. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?moodlewsrestformat=%3Ccff_marker_moodlewsrestformat_xss_reflection_probe_229845de7d%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_moodlewsrestformat_xss_reflection_probe_229845de7d&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_reflection_probe_229845de7d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 364. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?moodlewsrestformat=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_710c96f848%27%29%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_710c96f848&#x27;)&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_710c96f848` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 365. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?moodlewsrestformat=%3Cscript%3Ealert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_014fc84dda%27%29%3C%2Fscript%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_014fc84dda&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_014fc84dda` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 366. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?moodlewsrestformat=cff_marker_moodlewsrestformat_text_canary_71667665b0`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_moodlewsrestformat_text_canary_71667665b0`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_text_canary_71667665b0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 367. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?page=-1_cff_marker_page_numeric_boundary_17d7ba2462`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_17d7ba2462`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_17d7ba2462` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 368. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?page=0_cff_marker_page_numeric_boundary_c3b41a6674`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_c3b41a6674`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_c3b41a6674` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 369. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?page=1_cff_marker_page_numeric_boundary_9d41c65c5f`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_9d41c65c5f`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_9d41c65c5f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 370. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?page=999999_cff_marker_page_numeric_boundary_d35549314e`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_d35549314e`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_d35549314e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 371. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?q=%3Ccff_marker_q_xss_reflection_probe_b41c8d3807%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_b41c8d3807&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_reflection_probe_b41c8d3807` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 372. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_q_xss_trigger_probe_a852bf8833%27%29%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_q_xss_trigger_probe_a852bf8833&#x27;)&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_trigger_probe_a852bf8833` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 373. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?q=%3Cscript%3Ealert%28%27cff_marker_q_xss_trigger_probe_5e2920d3f2%27%29%3C%2Fscript%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_q_xss_trigger_probe_5e2920d3f2&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_trigger_probe_5e2920d3f2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 374. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?q=cff_marker_q_text_canary_d24e1f4399`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_d24e1f4399`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_text_canary_d24e1f4399` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 375. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_3f9b8d8f41`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_3f9b8d8f41`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_redirect_redirect_probe_3f9b8d8f41` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 376. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_631421e531`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_631421e531`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_redirect_redirect_probe_631421e531` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 377. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_ebad9806bc`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_ebad9806bc`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_returnurl_redirect_probe_ebad9806bc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 378. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_305d3df2c5`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_305d3df2c5`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_returnurl_redirect_probe_305d3df2c5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 379. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?search=%3Ccff_marker_search_xss_reflection_probe_27eb1f4648%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_27eb1f4648&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_27eb1f4648` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 380. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_5e66f1efe3%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_5e66f1efe3&#x27;)&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_5e66f1efe3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 381. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_676dce102e%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_676dce102e&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_676dce102e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 382. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?search=cff_marker_search_text_canary_fa289bc603`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_fa289bc603`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_text_canary_fa289bc603` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 383. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?section=-1_cff_marker_section_numeric_boundary_9b5921f079`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_9b5921f079`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_9b5921f079` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 384. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?section=0_cff_marker_section_numeric_boundary_617154f507`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_617154f507`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_617154f507` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 385. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?section=1_cff_marker_section_numeric_boundary_f00ab1f6f4`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_f00ab1f6f4`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_f00ab1f6f4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 386. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?section=999999_cff_marker_section_numeric_boundary_45814ed780`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_45814ed780`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_45814ed780` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 387. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?sesskey=cff_marker_sesskey_token_canary_8eb6cb81bb`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_8eb6cb81bb`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_canary_8eb6cb81bb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 388. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?sesskey=cff_marker_sesskey_token_empty_9b9b5d9904`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_9b9b5d9904`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_empty_9b9b5d9904` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 389. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_a34f1b8389`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_a34f1b8389`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_invalid_a34f1b8389` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 390. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?user=-1_cff_marker_user_numeric_boundary_61e4481aa2`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_61e4481aa2`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_61e4481aa2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 391. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?user=0_cff_marker_user_numeric_boundary_c3b2dd6d13`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_c3b2dd6d13`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_c3b2dd6d13` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 392. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?user=1_cff_marker_user_numeric_boundary_aa1329891a`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_aa1329891a`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_aa1329891a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 393. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?user=999999_cff_marker_user_numeric_boundary_52aae2bc3a`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_52aae2bc3a`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_52aae2bc3a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 394. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?userid=-1_cff_marker_userid_numeric_boundary_c96a08853e`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_c96a08853e`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_c96a08853e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 395. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?userid=0_cff_marker_userid_numeric_boundary_f2b4e05ed3`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_f2b4e05ed3`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_f2b4e05ed3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 396. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?userid=1_cff_marker_userid_numeric_boundary_1ac1916a5b`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_1ac1916a5b`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_1ac1916a5b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 397. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?userid=999999_cff_marker_userid_numeric_boundary_8688616205`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_8688616205`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_8688616205` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 398. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_ff7e9391c0%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_ff7e9391c0&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_reflection_probe_ff7e9391c0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 399. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?wsfunction=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_wsfunction_xss_trigger_probe_d323e14a58%27%29%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_d323e14a58&#x27;)&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_trigger_probe_d323e14a58` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 400. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?wsfunction=%3Cscript%3Ealert%28%27cff_marker_wsfunction_xss_trigger_probe_a71076a070%27%29%3C%2Fscript%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_a71076a070&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_trigger_probe_a71076a070` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 401. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?wsfunction=cff_marker_wsfunction_text_canary_d9e7561b7e`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_d9e7561b7e`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_text_canary_d9e7561b7e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 402. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?wstoken=cff_marker_wstoken_token_canary_a1ee887784`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_a1ee887784`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_canary_a1ee887784` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 403. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?wstoken=cff_marker_wstoken_token_empty_a53b71f42e`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_a53b71f42e`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_empty_a53b71f42e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 404. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_46136ba6bc`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_46136ba6bc`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_invalid_46136ba6bc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 405. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?component=%27_cff_marker_component_sqli_probe_f9a4e8b42a`
- Parameter: `component` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_component_sqli_probe_f9a4e8b42a`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_sqli_probe_f9a4e8b42a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 406. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?component=%3Ccff_marker_component_xss_reflection_probe_490d08eb1f%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_component_xss_reflection_probe_490d08eb1f&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_reflection_probe_490d08eb1f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 407. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?component=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_component_xss_trigger_probe_140b1cb65c%27%29%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_component_xss_trigger_probe_140b1cb65c&#x27;)&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_trigger_probe_140b1cb65c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 408. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?component=%3Cscript%3Ealert%28%27cff_marker_component_xss_trigger_probe_0fc0fd4fc9%27%29%3C%2Fscript%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_component_xss_trigger_probe_0fc0fd4fc9&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_trigger_probe_0fc0fd4fc9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 409. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?component=cff_marker_component_text_canary_4b1e4d8bbd`
- Parameter: `component` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_component_text_canary_4b1e4d8bbd`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_text_canary_4b1e4d8bbd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 410. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?contextid=-1_cff_marker_contextid_numeric_boundary_834da3243e`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_contextid_numeric_boundary_834da3243e`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_834da3243e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 411. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?contextid=0_cff_marker_contextid_numeric_boundary_355a5035a7`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_contextid_numeric_boundary_355a5035a7`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_355a5035a7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 412. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?contextid=1%22_cff_marker_contextid_sqli_probe_6eb21b0df4`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_contextid_sqli_probe_6eb21b0df4`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_6eb21b0df4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 413. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?contextid=1%27_cff_marker_contextid_sqli_probe_4c76cf3819`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_contextid_sqli_probe_4c76cf3819`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_4c76cf3819` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 414. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?contextid=1_cff_marker_contextid_numeric_boundary_a9e6edaf8b`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_contextid_numeric_boundary_a9e6edaf8b`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_a9e6edaf8b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 415. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?contextid=999999_cff_marker_contextid_numeric_boundary_8327f76290`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_contextid_numeric_boundary_8327f76290`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_8327f76290` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 416. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?course=-1_cff_marker_course_numeric_boundary_ab9ed8dc28`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_ab9ed8dc28`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_ab9ed8dc28` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 417. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?course=0_cff_marker_course_numeric_boundary_03ab5b31ed`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_03ab5b31ed`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_03ab5b31ed` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 418. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?course=1%22_cff_marker_course_sqli_probe_fe9f0ee312`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_fe9f0ee312`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_fe9f0ee312` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 419. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?course=1%27_cff_marker_course_sqli_probe_119846b046`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_119846b046`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_119846b046` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 420. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?course=1_cff_marker_course_numeric_boundary_ebab297c7e`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_ebab297c7e`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_ebab297c7e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 421. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?course=999999_cff_marker_course_numeric_boundary_a8c44a13cd`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_a8c44a13cd`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_a8c44a13cd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 422. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?courseid=-1_cff_marker_courseid_numeric_boundary_87d583ca58`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_87d583ca58`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_87d583ca58` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 423. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?courseid=0_cff_marker_courseid_numeric_boundary_2a9096acbf`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_2a9096acbf`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_2a9096acbf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 424. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?courseid=1%22_cff_marker_courseid_sqli_probe_52a2ea0287`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_52a2ea0287`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_52a2ea0287` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 425. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?courseid=1%27_cff_marker_courseid_sqli_probe_02f69c7cd3`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_02f69c7cd3`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_02f69c7cd3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 426. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?courseid=1_cff_marker_courseid_numeric_boundary_1d53ebbef6`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_1d53ebbef6`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_1d53ebbef6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 427. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?courseid=999999_cff_marker_courseid_numeric_boundary_6d291c23a5`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_6d291c23a5`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_6d291c23a5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 428. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?filearea=cff_marker_filearea_path_canary_f1dc298784`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filearea_path_canary_f1dc298784`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filearea_path_canary_f1dc298784` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 429. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?filename=cff_marker_filename_path_canary_327448e073`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filename_path_canary_327448e073`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filename_path_canary_327448e073` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 430. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?filepath=cff_marker_filepath_path_canary_33000b6611`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filepath_path_canary_33000b6611`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filepath_path_canary_33000b6611` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 431. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?id=-1_cff_marker_id_numeric_boundary_33d11017df`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_33d11017df`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_33d11017df` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 432. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?id=0_cff_marker_id_numeric_boundary_1613314f88`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_1613314f88`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_1613314f88` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 433. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?id=1%22_cff_marker_id_sqli_probe_ea2841e15d`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_ea2841e15d`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_ea2841e15d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 434. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?id=1%27_cff_marker_id_sqli_probe_089aa7f2a1`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_089aa7f2a1`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_089aa7f2a1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 435. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?id=1_cff_marker_id_numeric_boundary_889159470d`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_889159470d`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_889159470d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 436. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?id=999999_cff_marker_id_numeric_boundary_03063ec3f0`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_03063ec3f0`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_03063ec3f0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 437. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?itemid=-1_cff_marker_itemid_numeric_boundary_d2baeb9f64`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_itemid_numeric_boundary_d2baeb9f64`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_d2baeb9f64` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 438. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?itemid=0_cff_marker_itemid_numeric_boundary_8c2e7f27ee`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_itemid_numeric_boundary_8c2e7f27ee`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_8c2e7f27ee` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 439. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?itemid=1%22_cff_marker_itemid_sqli_probe_ed6eb76070`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_itemid_sqli_probe_ed6eb76070`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_ed6eb76070` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 440. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?itemid=1%27_cff_marker_itemid_sqli_probe_de5c3c69bd`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_itemid_sqli_probe_de5c3c69bd`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_de5c3c69bd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 441. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?itemid=1_cff_marker_itemid_numeric_boundary_d331dc1ad2`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_itemid_numeric_boundary_d331dc1ad2`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_d331dc1ad2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 442. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?itemid=999999_cff_marker_itemid_numeric_boundary_e30993a82d`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_itemid_numeric_boundary_e30993a82d`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_e30993a82d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 443. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?moodlewsrestformat=%27_cff_marker_moodlewsrestformat_sqli_probe_dfaa850397`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_moodlewsrestformat_sqli_probe_dfaa850397`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_sqli_probe_dfaa850397` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 444. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?moodlewsrestformat=%3Ccff_marker_moodlewsrestformat_xss_reflection_probe_ee93daebbe%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_moodlewsrestformat_xss_reflection_probe_ee93daebbe&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_reflection_probe_ee93daebbe` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 445. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?moodlewsrestformat=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_e38a4a9bfa%27%29%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_e38a4a9bfa&#x27;)&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_e38a4a9bfa` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 446. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?moodlewsrestformat=%3Cscript%3Ealert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_49f9ccf201%27%29%3C%2Fscript%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_49f9ccf201&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_49f9ccf201` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 447. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?moodlewsrestformat=cff_marker_moodlewsrestformat_text_canary_0a8213ca57`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_moodlewsrestformat_text_canary_0a8213ca57`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_text_canary_0a8213ca57` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 448. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?page=-1_cff_marker_page_numeric_boundary_0767a4ef99`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_0767a4ef99`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_0767a4ef99` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 449. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?page=0_cff_marker_page_numeric_boundary_a419a58e6e`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_a419a58e6e`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_a419a58e6e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 450. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?page=1%22_cff_marker_page_sqli_probe_6e31630bab`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_6e31630bab`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_6e31630bab` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 451. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?page=1%27_cff_marker_page_sqli_probe_aa2826e963`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_aa2826e963`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_aa2826e963` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 452. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?page=1_cff_marker_page_numeric_boundary_524bfcc084`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_524bfcc084`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_524bfcc084` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 453. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?page=999999_cff_marker_page_numeric_boundary_888d804c81`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_888d804c81`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_888d804c81` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 454. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?q=%27_cff_marker_q_sqli_probe_3272db8309`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_3272db8309`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_sqli_probe_3272db8309` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 455. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?q=%3Ccff_marker_q_xss_reflection_probe_832a4ac2df%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_832a4ac2df&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_reflection_probe_832a4ac2df` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 456. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_q_xss_trigger_probe_d8d014e43c%27%29%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_q_xss_trigger_probe_d8d014e43c&#x27;)&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_trigger_probe_d8d014e43c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 457. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?q=%3Cscript%3Ealert%28%27cff_marker_q_xss_trigger_probe_eef0c3ecf0%27%29%3C%2Fscript%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_q_xss_trigger_probe_eef0c3ecf0&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_trigger_probe_eef0c3ecf0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 458. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?q=cff_marker_q_text_canary_6089a35fdc`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_6089a35fdc`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_text_canary_6089a35fdc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 459. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_26122d70de`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_26122d70de`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_redirect_redirect_probe_26122d70de` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 460. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_dc323db37c`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_dc323db37c`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_redirect_redirect_probe_dc323db37c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 461. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_ff0f575615`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_ff0f575615`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_returnurl_redirect_probe_ff0f575615` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 462. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_510fcd0326`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_510fcd0326`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_returnurl_redirect_probe_510fcd0326` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 463. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?search=%27_cff_marker_search_sqli_probe_535ccd3b7f`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_535ccd3b7f`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_535ccd3b7f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 464. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?search=%3Ccff_marker_search_xss_reflection_probe_fdb7dec303%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_fdb7dec303&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_fdb7dec303` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 465. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_eb63b72583%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_eb63b72583&#x27;)&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_eb63b72583` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 466. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_6650323295%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_6650323295&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_6650323295` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 467. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?search=cff_marker_search_text_canary_c6624078e4`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_c6624078e4`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_text_canary_c6624078e4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 468. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?section=-1_cff_marker_section_numeric_boundary_3a8b342893`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_3a8b342893`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_3a8b342893` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 469. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?section=0_cff_marker_section_numeric_boundary_60133eef1d`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_60133eef1d`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_60133eef1d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 470. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?section=1%22_cff_marker_section_sqli_probe_e4776d9f0e`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_e4776d9f0e`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_e4776d9f0e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 471. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?section=1%27_cff_marker_section_sqli_probe_5c3aad94ec`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_5c3aad94ec`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_5c3aad94ec` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 472. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?section=1_cff_marker_section_numeric_boundary_43316d75e5`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_43316d75e5`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_43316d75e5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 473. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?section=999999_cff_marker_section_numeric_boundary_ce1f6d084c`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_ce1f6d084c`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_ce1f6d084c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 474. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?sesskey=cff_marker_sesskey_token_canary_514aa437bc`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_514aa437bc`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_canary_514aa437bc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 475. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?sesskey=cff_marker_sesskey_token_empty_16e296ef2a`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_16e296ef2a`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_empty_16e296ef2a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 476. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_00ef137274`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_00ef137274`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_invalid_00ef137274` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 477. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?user=-1_cff_marker_user_numeric_boundary_314c2813b2`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_314c2813b2`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_314c2813b2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 478. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?user=0_cff_marker_user_numeric_boundary_43750052b5`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_43750052b5`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_43750052b5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 479. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?user=1%22_cff_marker_user_sqli_probe_c5b1c59d56`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_c5b1c59d56`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_c5b1c59d56` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 480. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?user=1%27_cff_marker_user_sqli_probe_fc7c7676cc`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_fc7c7676cc`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_fc7c7676cc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 481. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?user=1_cff_marker_user_numeric_boundary_0528bb37cb`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_0528bb37cb`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_0528bb37cb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 482. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?user=999999_cff_marker_user_numeric_boundary_115d4473f4`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_115d4473f4`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_115d4473f4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 483. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?userid=-1_cff_marker_userid_numeric_boundary_c4a9e9f1dd`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_c4a9e9f1dd`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_c4a9e9f1dd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 484. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?userid=0_cff_marker_userid_numeric_boundary_c692bfc02f`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_c692bfc02f`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_c692bfc02f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 485. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?userid=1%22_cff_marker_userid_sqli_probe_99a02e7873`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_99a02e7873`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_99a02e7873` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 486. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?userid=1%27_cff_marker_userid_sqli_probe_a2e6056684`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_a2e6056684`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_a2e6056684` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 487. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?userid=1_cff_marker_userid_numeric_boundary_23edfbaa0c`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_23edfbaa0c`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_23edfbaa0c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 488. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?userid=999999_cff_marker_userid_numeric_boundary_97fcb90afa`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_97fcb90afa`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_97fcb90afa` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 489. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?wsfunction=%27_cff_marker_wsfunction_sqli_probe_de44531efb`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_de44531efb`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_sqli_probe_de44531efb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 490. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_1759bea827%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_1759bea827&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_reflection_probe_1759bea827` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 491. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?wsfunction=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_wsfunction_xss_trigger_probe_0e468fd209%27%29%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_0e468fd209&#x27;)&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_trigger_probe_0e468fd209` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 492. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?wsfunction=%3Cscript%3Ealert%28%27cff_marker_wsfunction_xss_trigger_probe_9ab3ecfbc6%27%29%3C%2Fscript%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_9ab3ecfbc6&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_trigger_probe_9ab3ecfbc6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 493. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?wsfunction=cff_marker_wsfunction_text_canary_b6c407609b`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_b6c407609b`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_text_canary_b6c407609b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 494. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?wstoken=cff_marker_wstoken_token_canary_5fda6bf264`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_5fda6bf264`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_canary_5fda6bf264` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 495. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?wstoken=cff_marker_wstoken_token_empty_dad2da0315`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_dad2da0315`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_empty_dad2da0315` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 496. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_36150f7ee8`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_36150f7ee8`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_invalid_36150f7ee8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 497. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?component=%27_cff_marker_component_sqli_probe_1ec58cbb07`
- Parameter: `component` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_component_sqli_probe_1ec58cbb07`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_sqli_probe_1ec58cbb07` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 498. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?component=%3Ccff_marker_component_xss_reflection_probe_7f99295d45%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_component_xss_reflection_probe_7f99295d45&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_reflection_probe_7f99295d45` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 499. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?component=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_component_xss_trigger_probe_a06047d3af%27%29%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_component_xss_trigger_probe_a06047d3af&#x27;)&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_trigger_probe_a06047d3af` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 500. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?component=%3Cscript%3Ealert%28%27cff_marker_component_xss_trigger_probe_b856864f03%27%29%3C%2Fscript%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_component_xss_trigger_probe_b856864f03&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_trigger_probe_b856864f03` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 501. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?component=cff_marker_component_text_canary_d38f2897b3`
- Parameter: `component` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_component_text_canary_d38f2897b3`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_text_canary_d38f2897b3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 502. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?contextid=0_cff_marker_contextid_numeric_boundary_60d2aebe92`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_contextid_numeric_boundary_60d2aebe92`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_60d2aebe92` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 503. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?contextid=1_cff_marker_contextid_numeric_boundary_1c8568a343`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_contextid_numeric_boundary_1c8568a343`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_1c8568a343` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 504. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?course=-1_cff_marker_course_numeric_boundary_dfeda552cf`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_dfeda552cf`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_dfeda552cf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 505. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?course=0_cff_marker_course_numeric_boundary_b09249d550`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_b09249d550`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_b09249d550` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 506. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?course=1%22_cff_marker_course_sqli_probe_ebe3d2ef03`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_ebe3d2ef03`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_ebe3d2ef03` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 507. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?course=1%27_cff_marker_course_sqli_probe_afe5c825e5`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_afe5c825e5`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_afe5c825e5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 508. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?course=1_cff_marker_course_numeric_boundary_30fc2da560`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_30fc2da560`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_30fc2da560` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 509. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?course=999999_cff_marker_course_numeric_boundary_e0bc4c6b5e`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_e0bc4c6b5e`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_e0bc4c6b5e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 510. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?courseid=-1_cff_marker_courseid_numeric_boundary_190e5155b1`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_190e5155b1`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_190e5155b1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 511. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?courseid=0_cff_marker_courseid_numeric_boundary_df4faa51a0`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_df4faa51a0`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_df4faa51a0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 512. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?courseid=1%22_cff_marker_courseid_sqli_probe_f57ca28ab8`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_f57ca28ab8`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_f57ca28ab8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 513. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?courseid=1%27_cff_marker_courseid_sqli_probe_319f3d7aa0`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_319f3d7aa0`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_319f3d7aa0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 514. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?courseid=1_cff_marker_courseid_numeric_boundary_abd647968a`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_abd647968a`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_abd647968a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 515. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?courseid=999999_cff_marker_courseid_numeric_boundary_eb897c73ef`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_eb897c73ef`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_eb897c73ef` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 516. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?id=-1_cff_marker_id_numeric_boundary_866298b978`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_866298b978`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_866298b978` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 517. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?id=0_cff_marker_id_numeric_boundary_7c96eb06bb`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_7c96eb06bb`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_7c96eb06bb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 518. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?id=1%22_cff_marker_id_sqli_probe_3a681afd51`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_3a681afd51`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_3a681afd51` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 519. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?id=1%27_cff_marker_id_sqli_probe_529de32bd3`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_529de32bd3`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_529de32bd3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 520. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?id=1_cff_marker_id_numeric_boundary_bbae4166ec`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_bbae4166ec`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_bbae4166ec` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 521. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?id=999999_cff_marker_id_numeric_boundary_3f181e008c`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_3f181e008c`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_3f181e008c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 522. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?moodlewsrestformat=%27_cff_marker_moodlewsrestformat_sqli_probe_e3d73fa15c`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_moodlewsrestformat_sqli_probe_e3d73fa15c`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_sqli_probe_e3d73fa15c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 523. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?moodlewsrestformat=%3Ccff_marker_moodlewsrestformat_xss_reflection_probe_40c755a9fb%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_moodlewsrestformat_xss_reflection_probe_40c755a9fb&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_reflection_probe_40c755a9fb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 524. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?moodlewsrestformat=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_8b38595a9d%27%29%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_8b38595a9d&#x27;)&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_8b38595a9d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 525. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?moodlewsrestformat=%3Cscript%3Ealert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_6d5066e6ff%27%29%3C%2Fscript%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_6d5066e6ff&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_6d5066e6ff` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 526. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?moodlewsrestformat=cff_marker_moodlewsrestformat_text_canary_2096eff1b7`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_moodlewsrestformat_text_canary_2096eff1b7`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_text_canary_2096eff1b7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 527. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?page=-1_cff_marker_page_numeric_boundary_8e6a2632a9`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_8e6a2632a9`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_8e6a2632a9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 528. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?page=0_cff_marker_page_numeric_boundary_49ea7f3565`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_49ea7f3565`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_49ea7f3565` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 529. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?page=1%22_cff_marker_page_sqli_probe_d42a927b0d`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_d42a927b0d`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_d42a927b0d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 530. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?page=1%27_cff_marker_page_sqli_probe_abee42d8b5`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_abee42d8b5`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_abee42d8b5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 531. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?page=1_cff_marker_page_numeric_boundary_e715329110`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_e715329110`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_e715329110` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 532. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?page=999999_cff_marker_page_numeric_boundary_571f6618bb`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_571f6618bb`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_571f6618bb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 533. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?q=%27_cff_marker_q_sqli_probe_ecef116b5c`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_ecef116b5c`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_sqli_probe_ecef116b5c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 534. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?q=%3Ccff_marker_q_xss_reflection_probe_ab6ae0f2a9%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_ab6ae0f2a9&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_reflection_probe_ab6ae0f2a9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 535. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_q_xss_trigger_probe_6dd1ddbb1c%27%29%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_q_xss_trigger_probe_6dd1ddbb1c&#x27;)&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_trigger_probe_6dd1ddbb1c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 536. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?q=%3Cscript%3Ealert%28%27cff_marker_q_xss_trigger_probe_5f2656068b%27%29%3C%2Fscript%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_q_xss_trigger_probe_5f2656068b&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_trigger_probe_5f2656068b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 537. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?q=cff_marker_q_text_canary_a0253d237f`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_a0253d237f`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_text_canary_a0253d237f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 538. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_da95f02532`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_da95f02532`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_redirect_redirect_probe_da95f02532` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 539. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_4c7c5bcbef`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_4c7c5bcbef`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_redirect_redirect_probe_4c7c5bcbef` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 540. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_07b86c45dd`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_07b86c45dd`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_returnurl_redirect_probe_07b86c45dd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 541. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_9d846b4280`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_9d846b4280`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_returnurl_redirect_probe_9d846b4280` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 542. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?search=%27_cff_marker_search_sqli_probe_dc43beae69`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_dc43beae69`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_dc43beae69` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 543. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?search=%3Ccff_marker_search_xss_reflection_probe_b59294a329%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_b59294a329&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_b59294a329` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 544. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_abc01e8e76%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_abc01e8e76&#x27;)&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_abc01e8e76` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 545. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_f692a6ef98%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_f692a6ef98&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_f692a6ef98` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 546. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?search=cff_marker_search_text_canary_69cd6b8aa7`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_69cd6b8aa7`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_text_canary_69cd6b8aa7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 547. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?section=-1_cff_marker_section_numeric_boundary_53265ed917`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_53265ed917`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_53265ed917` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 548. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?section=0_cff_marker_section_numeric_boundary_fefdc98b14`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_fefdc98b14`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_fefdc98b14` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 549. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?section=1%22_cff_marker_section_sqli_probe_729559afaf`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_729559afaf`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_729559afaf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 550. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?section=1%27_cff_marker_section_sqli_probe_24b5b97321`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_24b5b97321`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_24b5b97321` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 551. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?section=1_cff_marker_section_numeric_boundary_e957a6ee74`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_e957a6ee74`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_e957a6ee74` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 552. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?section=999999_cff_marker_section_numeric_boundary_55d0d57829`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_55d0d57829`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_55d0d57829` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 553. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?sesskey=cff_marker_sesskey_token_canary_40671b4a08`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_40671b4a08`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_canary_40671b4a08` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 554. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?sesskey=cff_marker_sesskey_token_empty_883b5f55e1`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_883b5f55e1`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_empty_883b5f55e1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 555. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_b4b4cc1ff1`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_b4b4cc1ff1`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_invalid_b4b4cc1ff1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 556. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?user=-1_cff_marker_user_numeric_boundary_efa138b4fd`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_efa138b4fd`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_efa138b4fd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 557. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?user=0_cff_marker_user_numeric_boundary_798abd870c`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_798abd870c`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_798abd870c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 558. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?user=1%22_cff_marker_user_sqli_probe_5b3a1711dd`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_5b3a1711dd`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_5b3a1711dd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 559. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?user=1%27_cff_marker_user_sqli_probe_ca85d85d2f`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_ca85d85d2f`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_ca85d85d2f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 560. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?user=1_cff_marker_user_numeric_boundary_1c5dde26fb`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_1c5dde26fb`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_1c5dde26fb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 561. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?user=999999_cff_marker_user_numeric_boundary_c5cf5b4ee2`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_c5cf5b4ee2`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_c5cf5b4ee2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 562. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?userid=-1_cff_marker_userid_numeric_boundary_e6685ddfe8`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_e6685ddfe8`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_e6685ddfe8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 563. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?userid=0_cff_marker_userid_numeric_boundary_0dc3d24daf`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_0dc3d24daf`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_0dc3d24daf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 564. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?userid=1%22_cff_marker_userid_sqli_probe_f14c6f2f91`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_f14c6f2f91`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_f14c6f2f91` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 565. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?userid=1%27_cff_marker_userid_sqli_probe_b97b2f4be6`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_b97b2f4be6`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_b97b2f4be6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 566. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?userid=1_cff_marker_userid_numeric_boundary_7bf42a86c1`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_7bf42a86c1`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_7bf42a86c1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 567. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?userid=999999_cff_marker_userid_numeric_boundary_fba2500957`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_fba2500957`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_fba2500957` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 568. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?wsfunction=%27_cff_marker_wsfunction_sqli_probe_0fbd6c3da3`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_0fbd6c3da3`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_sqli_probe_0fbd6c3da3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 569. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_9a69704d2a%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_9a69704d2a&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_reflection_probe_9a69704d2a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 570. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?wsfunction=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_wsfunction_xss_trigger_probe_6aa04209d8%27%29%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_6aa04209d8&#x27;)&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_trigger_probe_6aa04209d8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 571. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?wsfunction=%3Cscript%3Ealert%28%27cff_marker_wsfunction_xss_trigger_probe_d70ef31da0%27%29%3C%2Fscript%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_d70ef31da0&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_trigger_probe_d70ef31da0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 572. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?wsfunction=cff_marker_wsfunction_text_canary_90c31ac377`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_90c31ac377`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_text_canary_90c31ac377` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 573. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?wstoken=cff_marker_wstoken_token_canary_2cbb178808`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_2cbb178808`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_canary_2cbb178808` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 574. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?wstoken=cff_marker_wstoken_token_empty_8305027d4d`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_8305027d4d`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_empty_8305027d4d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 575. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_8a23d4b7e0`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_8a23d4b7e0`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_invalid_8a23d4b7e0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 576. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?component=%27_cff_marker_component_sqli_probe_de73e8fb73`
- Parameter: `component` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_component_sqli_probe_de73e8fb73`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_sqli_probe_de73e8fb73` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 577. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?contextid=1%22_cff_marker_contextid_sqli_probe_275c2ca99f`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_contextid_sqli_probe_275c2ca99f`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_275c2ca99f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 578. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?contextid=1%27_cff_marker_contextid_sqli_probe_8a1e3db4a5`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_contextid_sqli_probe_8a1e3db4a5`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_8a1e3db4a5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 579. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?course=1%22_cff_marker_course_sqli_probe_7b792b06c6`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_7b792b06c6`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_7b792b06c6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 580. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?course=1%27_cff_marker_course_sqli_probe_9357146dd8`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_9357146dd8`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_9357146dd8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 581. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?courseid=1%22_cff_marker_courseid_sqli_probe_5073b9d6d8`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_5073b9d6d8`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_5073b9d6d8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 582. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?courseid=1%27_cff_marker_courseid_sqli_probe_99b9559058`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_99b9559058`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_99b9559058` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 583. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?id=1%22_cff_marker_id_sqli_probe_9998602ea0`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_9998602ea0`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_9998602ea0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 584. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?id=1%27_cff_marker_id_sqli_probe_03a11afeec`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_03a11afeec`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_03a11afeec` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 585. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?itemid=1%22_cff_marker_itemid_sqli_probe_897f399c10`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_itemid_sqli_probe_897f399c10`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_897f399c10` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 586. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?itemid=1%27_cff_marker_itemid_sqli_probe_67a1eff054`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_itemid_sqli_probe_67a1eff054`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_67a1eff054` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 587. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?moodlewsrestformat=%27_cff_marker_moodlewsrestformat_sqli_probe_3652b6da8c`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_moodlewsrestformat_sqli_probe_3652b6da8c`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_sqli_probe_3652b6da8c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 588. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?page=1%22_cff_marker_page_sqli_probe_df437d1efe`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_df437d1efe`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_df437d1efe` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 589. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?page=1%27_cff_marker_page_sqli_probe_44d34767b1`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_44d34767b1`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_44d34767b1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 590. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?q=%27_cff_marker_q_sqli_probe_f7ac694f30`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_f7ac694f30`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_sqli_probe_f7ac694f30` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 591. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?search=%27_cff_marker_search_sqli_probe_3e0cd0b931`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_3e0cd0b931`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_3e0cd0b931` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 592. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?section=1%22_cff_marker_section_sqli_probe_dfe30f4681`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_dfe30f4681`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_dfe30f4681` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 593. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?section=1%27_cff_marker_section_sqli_probe_1c8f335f59`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_1c8f335f59`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_1c8f335f59` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 594. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?user=1%22_cff_marker_user_sqli_probe_c652fd8595`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_c652fd8595`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_c652fd8595` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 595. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?user=1%27_cff_marker_user_sqli_probe_f08764977e`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_f08764977e`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_f08764977e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 596. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?userid=1%22_cff_marker_userid_sqli_probe_bc7a7441f8`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_bc7a7441f8`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_bc7a7441f8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 597. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?userid=1%27_cff_marker_userid_sqli_probe_3767897eab`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_3767897eab`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_3767897eab` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 598. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/login/index.php?wsfunction=%27_cff_marker_wsfunction_sqli_probe_d7ab8556f6`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_d7ab8556f6`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_sqli_probe_d7ab8556f6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 599. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 600. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?component=%27_cff_marker_component_sqli_probe_210619cf87`
- Parameter: `component` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_component_sqli_probe_210619cf87`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_component_sqli_probe_210619cf87` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 601. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?contextid=1%22_cff_marker_contextid_sqli_probe_8045f35cbe`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_contextid_sqli_probe_8045f35cbe`
- Response: HTTP `200` / Length `137` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_contextid_sqli_probe_8045f35cbe` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `137`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 602. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?contextid=1%27_cff_marker_contextid_sqli_probe_afc330586b`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_contextid_sqli_probe_afc330586b`
- Response: HTTP `200` / Length `137` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_contextid_sqli_probe_afc330586b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `137`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 603. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?course=1%22_cff_marker_course_sqli_probe_4023c53c0e`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_4023c53c0e`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_course_sqli_probe_4023c53c0e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 604. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?course=1%27_cff_marker_course_sqli_probe_a37613ebb7`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_a37613ebb7`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_course_sqli_probe_a37613ebb7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 605. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?courseid=1%22_cff_marker_courseid_sqli_probe_c2969d5dec`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_c2969d5dec`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_courseid_sqli_probe_c2969d5dec` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 606. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?courseid=1%27_cff_marker_courseid_sqli_probe_77c6a28886`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_77c6a28886`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_courseid_sqli_probe_77c6a28886` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 607. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?id=1%22_cff_marker_id_sqli_probe_a6f9866092`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_a6f9866092`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_id_sqli_probe_a6f9866092` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 608. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?id=1%27_cff_marker_id_sqli_probe_cea9fd02a0`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_cea9fd02a0`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_id_sqli_probe_cea9fd02a0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 609. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?itemid=1%22_cff_marker_itemid_sqli_probe_de8abfa2ce`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_itemid_sqli_probe_de8abfa2ce`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_itemid_sqli_probe_de8abfa2ce` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 610. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?itemid=1%27_cff_marker_itemid_sqli_probe_02ac6aec37`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_itemid_sqli_probe_02ac6aec37`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_itemid_sqli_probe_02ac6aec37` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 611. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?moodlewsrestformat=%27_cff_marker_moodlewsrestformat_sqli_probe_b854e4e2fb`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_moodlewsrestformat_sqli_probe_b854e4e2fb`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_moodlewsrestformat_sqli_probe_b854e4e2fb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 612. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?page=1%22_cff_marker_page_sqli_probe_390bb4f1b0`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_390bb4f1b0`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_page_sqli_probe_390bb4f1b0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 613. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?page=1%27_cff_marker_page_sqli_probe_71d19a2321`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_71d19a2321`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_page_sqli_probe_71d19a2321` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 614. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?q=%27_cff_marker_q_sqli_probe_a8c25b9a67`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_a8c25b9a67`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_q_sqli_probe_a8c25b9a67` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 615. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?search=%27_cff_marker_search_sqli_probe_476864e63a`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_476864e63a`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_search_sqli_probe_476864e63a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 616. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?section=1%22_cff_marker_section_sqli_probe_8cb5f3a333`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_8cb5f3a333`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_section_sqli_probe_8cb5f3a333` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 617. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?section=1%27_cff_marker_section_sqli_probe_ca9821092a`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_ca9821092a`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_section_sqli_probe_ca9821092a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 618. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?user=1%22_cff_marker_user_sqli_probe_bac94bf76c`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_bac94bf76c`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_user_sqli_probe_bac94bf76c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 619. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?user=1%27_cff_marker_user_sqli_probe_eeb6786f07`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_eeb6786f07`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_user_sqli_probe_eeb6786f07` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 620. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?userid=1%22_cff_marker_userid_sqli_probe_cf6782747d`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_cf6782747d`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_userid_sqli_probe_cf6782747d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 621. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?userid=1%27_cff_marker_userid_sqli_probe_4f1a392ef9`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_4f1a392ef9`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_userid_sqli_probe_4f1a392ef9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 622. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/ajax.php?wsfunction=%27_cff_marker_wsfunction_sqli_probe_4ce2fc0f66`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_4ce2fc0f66`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Marker: `cff_marker_wsfunction_sqli_probe_4ce2fc0f66` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 623. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 624. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?contextid=1%22_cff_marker_contextid_sqli_probe_629024f9e9`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_contextid_sqli_probe_629024f9e9`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_629024f9e9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 625. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?contextid=1%27_cff_marker_contextid_sqli_probe_4dea2f7161`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_contextid_sqli_probe_4dea2f7161`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_4dea2f7161` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 626. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?course=1%22_cff_marker_course_sqli_probe_b46d70eec2`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_b46d70eec2`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_b46d70eec2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 627. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?course=1%27_cff_marker_course_sqli_probe_abb078b7bd`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_abb078b7bd`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_abb078b7bd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 628. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?courseid=1%22_cff_marker_courseid_sqli_probe_630f1215a7`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_630f1215a7`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_630f1215a7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 629. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?courseid=1%27_cff_marker_courseid_sqli_probe_d06e337f7f`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_d06e337f7f`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_d06e337f7f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 630. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?id=1%22_cff_marker_id_sqli_probe_7d25cedea7`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_7d25cedea7`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_7d25cedea7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 631. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?id=1%27_cff_marker_id_sqli_probe_356e6804b3`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_356e6804b3`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_356e6804b3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 632. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?itemid=1%22_cff_marker_itemid_sqli_probe_f28aaafe2e`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_itemid_sqli_probe_f28aaafe2e`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_f28aaafe2e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 633. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?itemid=1%27_cff_marker_itemid_sqli_probe_7f77e40d13`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_itemid_sqli_probe_7f77e40d13`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_7f77e40d13` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 634. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?moodlewsrestformat=%27_cff_marker_moodlewsrestformat_sqli_probe_d0a7863492`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_moodlewsrestformat_sqli_probe_d0a7863492`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_sqli_probe_d0a7863492` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 635. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?page=1%22_cff_marker_page_sqli_probe_d6075615b1`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_d6075615b1`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_d6075615b1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 636. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?page=1%27_cff_marker_page_sqli_probe_889df552b8`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_889df552b8`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_889df552b8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 637. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?q=%27_cff_marker_q_sqli_probe_812b4dec4e`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_812b4dec4e`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_q_sqli_probe_812b4dec4e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 638. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?search=%27_cff_marker_search_sqli_probe_41e998506f`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_41e998506f`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_41e998506f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 639. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?section=1%22_cff_marker_section_sqli_probe_09760dbbc6`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_09760dbbc6`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_09760dbbc6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 640. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?section=1%27_cff_marker_section_sqli_probe_36203d2ea3`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_36203d2ea3`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_36203d2ea3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 641. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?user=1%22_cff_marker_user_sqli_probe_828976ce23`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_828976ce23`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_828976ce23` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 642. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?user=1%27_cff_marker_user_sqli_probe_4eb5ca5011`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_4eb5ca5011`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_4eb5ca5011` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 643. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?userid=1%22_cff_marker_userid_sqli_probe_82be44b5e0`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_82be44b5e0`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_82be44b5e0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 644. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?userid=1%27_cff_marker_userid_sqli_probe_38fe12c0ea`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_38fe12c0ea`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_38fe12c0ea` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 645. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/?wsfunction=%27_cff_marker_wsfunction_sqli_probe_d687ef6817`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_d687ef6817`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_wsfunction_sqli_probe_d687ef6817` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 646. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/environment.xml`
- Response: HTTP `200` / Length `193373` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `193373`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 647. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/mnet/trustedhosts.html`
- Response: HTTP `200` / Length `2264` / Type `text/html`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2264`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 648. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/module.js`
- Response: HTTP `200` / Length `6873` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6873`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 649. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/role_schema.xml`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 650. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/tests/behat/override_roles_highlighting.feature`
- Response: HTTP `200` / Length `893` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `893`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 651. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/local/settings/autocomplete.mustache`
- Response: HTTP `200` / Length `2811` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2811`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 652. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting.mustache`
- Response: HTTP `200` / Length `3554` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3554`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 653. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configcheckbox.mustache`
- Response: HTTP `200` / Length `1444` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1444`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 654. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configcolourpicker.mustache`
- Response: HTTP `200` / Length `1790` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1790`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 655. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configdirectory.mustache`
- Response: HTTP `200` / Length `1339` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1339`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 656. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configduration.mustache`
- Response: HTTP `200` / Length `1897` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1897`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 657. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configempty.mustache`
- Response: HTTP `200` / Length `1068` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1068`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 658. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configexecutable.mustache`
- Response: HTTP `200` / Length `1334` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1334`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 659. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configfile.mustache`
- Response: HTTP `200` / Length `1904` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1904`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 660. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configfilesize.mustache`
- Response: HTTP `200` / Length `1893` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1893`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 661. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_confightmleditor.mustache`
- Response: HTTP `200` / Length `1236` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1236`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 662. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configmulticheckbox.mustache`
- Response: HTTP `200` / Length `1768` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1768`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 663. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configmultiselect.mustache`
- Response: HTTP `200` / Length `1730` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1730`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 664. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configmultiselect_optgroup.mustache`
- Response: HTTP `200` / Length `2699` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2699`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 665. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configpasswordunmask.mustache`
- Response: HTTP `200` / Length `2813` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2813`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 666. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configselect.mustache`
- Response: HTTP `200` / Length `1581` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1581`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 667. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configselect_optgroup.mustache`
- Response: HTTP `200` / Length `2552` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2552`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 668. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configtext.mustache`
- Response: HTTP `200` / Length `2076` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2076`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 669. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configtextarea.mustache`
- Response: HTTP `200` / Length `1518` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1518`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 670. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_configtime.mustache`
- Response: HTTP `200` / Length `2317` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2317`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 671. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_courselist_frontpage.mustache`
- Response: HTTP `200` / Length `1683` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1683`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 672. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_description.mustache`
- Response: HTTP `200` / Length `1379` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1379`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 673. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_devicedetectregex.mustache`
- Response: HTTP `200` / Length `1933` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1933`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 674. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_emoticons.mustache`
- Response: HTTP `200` / Length `2215` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2215`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 675. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_encryptedpassword.mustache`
- Response: HTTP `200` / Length `2385` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2385`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 676. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_filetypes.mustache`
- Response: HTTP `200` / Length `1826` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1826`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 677. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_flag.mustache`
- Response: HTTP `200` / Length `1263` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1263`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 678. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_gradecat_combo.mustache`
- Response: HTTP `200` / Length `1668` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1668`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 679. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_heading.mustache`
- Response: HTTP `200` / Length `1263` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1263`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 680. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_manage_plugins.mustache`
- Response: HTTP `200` / Length `3990` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3990`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 681. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/setting_special_calendar_weekend.mustache`
- Response: HTTP `200` / Length `1808` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1808`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 682. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/settings.mustache`
- Response: HTTP `200` / Length `2050` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2050`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 683. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/settings_search_results.mustache`
- Response: HTTP `200` / Length `2707` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2707`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 684. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tests/behat/browse_users.feature`
- Response: HTTP `200` / Length `12272` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `12272`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 685. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tests/behat/enable_multiple_accounts_use_same_email.feature`
- Response: HTTP `200` / Length `3306` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3306`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 686. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tests/behat/filter_users.feature`
- Response: HTTP `200` / Length `11443` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `11443`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 687. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tests/behat/invalid_allcountrycodes.feature`
- Response: HTTP `200` / Length `1443` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1443`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 688. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tests/behat/language_settings.feature`
- Response: HTTP `200` / Length `1386` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1386`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 689. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tests/behat/manage_tokens.feature`
- Response: HTTP `200` / Length `5299` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `5299`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 690. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tests/behat/purge_caches.feature`
- Response: HTTP `200` / Length `1429` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1429`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 691. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tests/behat/search_areas.feature`
- Response: HTTP `200` / Length `1046` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1046`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 692. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tests/behat/set_admin_settings_value.feature`
- Response: HTTP `200` / Length `895` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `895`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 693. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tests/behat/webservice_users.feature`
- Response: HTTP `200` / Length `2020` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2020`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 694. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics/amd/build/log_info.min.js`
- Response: HTTP `200` / Length `981` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `981`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 695. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics/amd/build/log_info.min.js.map`
- Response: HTTP `200` / Length `2468` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2468`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 696. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics/amd/build/model.min.js`
- Response: HTTP `200` / Length `3668` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3668`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 697. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics/amd/build/model.min.js.map`
- Response: HTTP `200` / Length `11755` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `11755`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 698. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics/amd/build/potential-contexts.min.js.map`
- Response: HTTP `200` / Length `2752` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2752`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 699. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics/amd/src/log_info.js`
- Response: HTTP `200` / Length `1793` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1793`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 700. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics/amd/src/model.js`
- Response: HTTP `200` / Length `8330` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `8330`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 701. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics/amd/src/potential-contexts.js`
- Response: HTTP `200` / Length `1934` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1934`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 702. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/login/index.php`
- Response: HTTP `200` / Length `27603` / Type `text/html; charset=utf-8`
- Title: Log in to the site | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `27603`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 703. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/classes/form/purge_caches.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 704. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/classes/form/testoutgoingmailconf_form.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 705. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/classes/local/externalpage/accesscallback.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 706. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/classes/local/settings/autocomplete.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 707. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/classes/local/settings/filesize.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 708. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/classes/privacy/provider.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 709. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/adhoc_task.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 710. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/alternative_component_cache.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 711. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/automated_backups.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 712. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/backup.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 713. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/build_theme_css.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 714. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/cfg.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 715. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/check_database_schema.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 716. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/checks.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 717. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/cron.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 718. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/dashboard_reset.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 719. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/fix_course_sequence.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 720. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/fix_deleted_users.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 721. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/fix_orphaned_calendar_events.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 722. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/fix_orphaned_question_categories.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 723. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/generate_key.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 724. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/install.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 725. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/install_database.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 726. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/kill_all_sessions.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 727. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/maintenance.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 728. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/mysql_collation.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 729. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/mysql_compressed_rows.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 730. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/purge_caches.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 731. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/reset_password.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 732. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/restore_backup.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 733. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/scheduled_task.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 734. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/svgtool.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 735. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/uninstall_plugins.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 736. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli/upgrade.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 737. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cron.php`
- Response: HTTP `200` / Length `74` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `74`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 738. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/lib.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 739. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/mailout-debugger.php`
- Response: HTTP `200` / Length `15` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `15`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 740. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/mnet/peer_forms.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 741. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/mnet/profilefields_form.php`
- Response: HTTP `200` / Length `42` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 742. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/mnet/services_form.php`
- Response: HTTP `200` / Length `42` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 743. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/mnet/tabs.php`
- Response: HTTP `200` / Length `42` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 744. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/process_email.php`
- Response: HTTP `200` / Length `37` / Type `text/html; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `37`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 745. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/registration/forms.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 746. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/registration/lib.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 747. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/admins_existing_selector.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 748. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/admins_potential_selector.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 749. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/allow_assign_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 750. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/allow_override_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 751. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/allow_role_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 752. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/allow_switch_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 753. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/allow_view_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 754. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/assign_user_selector_base.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 755. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/capability_table_base.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 756. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/capability_table_with_risks.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 757. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/check_capability_table.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 758. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/check_users_selector.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 759. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/define_role_table_advanced.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 760. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/define_role_table_basic.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 761. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/existing_role_holders.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 762. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/override_permissions_table_advanced.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 763. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/permission_allow_form.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 764. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/permission_prohibit_form.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 765. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/permissions_table.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 766. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/potential_assignees_below_course.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 767. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/potential_assignees_course_and_above.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 768. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/preset.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 769. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/preset_form.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 770. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/privacy/provider.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 771. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/view_role_definition_table.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 772. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/lib.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 773. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/managetabs.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 774. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings/analytics.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 775. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings/competency.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 776. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings/courses.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 777. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings/development.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 778. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings/h5p.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 779. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings/language.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 780. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings/license.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 781. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings/location.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 782. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings/messaging.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 783. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings/mnet.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 784. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings/security.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 785. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings/server.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 786. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings/subsystems.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 787. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings/userfeedback.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 788. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tests/behat/display_short_names.feature`
- Response: HTTP `200` / Length `858` / Type ``
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `858`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 789. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics/amd/build/potential-contexts.min.js`
- Response: HTTP `200` / Length `778` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `778`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 790. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics/classes/clihelper.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 791. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/config.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 792. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/lib/ajax/service.php`
- Response: HTTP `200` / Length `191` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; API-like endpoint
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `191`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; API-like endpoint

### 793. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?component=%27_cff_marker_component_sqli_probe_461e115163`
- Parameter: `component` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_component_sqli_probe_461e115163`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_component_sqli_probe_461e115163` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 794. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?contextid=1%22_cff_marker_contextid_sqli_probe_57eadde5fa`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_contextid_sqli_probe_57eadde5fa`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_contextid_sqli_probe_57eadde5fa` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 795. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?contextid=1%27_cff_marker_contextid_sqli_probe_87e494377a`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_contextid_sqli_probe_87e494377a`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_contextid_sqli_probe_87e494377a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 796. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?course=1%22_cff_marker_course_sqli_probe_b8393ea095`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_b8393ea095`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_course_sqli_probe_b8393ea095` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 797. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?course=1%27_cff_marker_course_sqli_probe_c5b2bd7de8`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_c5b2bd7de8`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_course_sqli_probe_c5b2bd7de8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 798. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?courseid=1%22_cff_marker_courseid_sqli_probe_91ff392a5e`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_91ff392a5e`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_courseid_sqli_probe_91ff392a5e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 799. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?courseid=1%27_cff_marker_courseid_sqli_probe_11d977078e`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_11d977078e`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_courseid_sqli_probe_11d977078e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 800. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?id=1%22_cff_marker_id_sqli_probe_d9d9632dfc`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_d9d9632dfc`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_id_sqli_probe_d9d9632dfc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 801. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?id=1%27_cff_marker_id_sqli_probe_157eb4b8e4`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_157eb4b8e4`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_id_sqli_probe_157eb4b8e4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 802. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?itemid=1%22_cff_marker_itemid_sqli_probe_a2c3188255`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_itemid_sqli_probe_a2c3188255`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_itemid_sqli_probe_a2c3188255` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 803. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?itemid=1%27_cff_marker_itemid_sqli_probe_42830d52f0`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_itemid_sqli_probe_42830d52f0`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_itemid_sqli_probe_42830d52f0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 804. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?moodlewsrestformat=%27_cff_marker_moodlewsrestformat_sqli_probe_2e3d35b7d5`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_moodlewsrestformat_sqli_probe_2e3d35b7d5`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_moodlewsrestformat_sqli_probe_2e3d35b7d5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 805. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?page=1%22_cff_marker_page_sqli_probe_b8043876e8`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_b8043876e8`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_page_sqli_probe_b8043876e8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 806. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?page=1%27_cff_marker_page_sqli_probe_4c142f1787`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_4c142f1787`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_page_sqli_probe_4c142f1787` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 807. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?q=%27_cff_marker_q_sqli_probe_a8ba535fb1`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_a8ba535fb1`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_q_sqli_probe_a8ba535fb1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 808. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?search=%27_cff_marker_search_sqli_probe_508003c34f`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_508003c34f`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_search_sqli_probe_508003c34f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 809. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?section=1%22_cff_marker_section_sqli_probe_39d767ead6`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_39d767ead6`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_section_sqli_probe_39d767ead6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 810. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?section=1%27_cff_marker_section_sqli_probe_86fc47f2ad`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_86fc47f2ad`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_section_sqli_probe_86fc47f2ad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 811. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?user=1%22_cff_marker_user_sqli_probe_88d8d3df0f`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_88d8d3df0f`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_user_sqli_probe_88d8d3df0f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 812. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?user=1%27_cff_marker_user_sqli_probe_c43de1ee8d`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_c43de1ee8d`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_user_sqli_probe_c43de1ee8d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 813. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?userid=1%22_cff_marker_userid_sqli_probe_953b2ef744`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_953b2ef744`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_userid_sqli_probe_953b2ef744` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 814. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?userid=1%27_cff_marker_userid_sqli_probe_e793b8399d`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_e793b8399d`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_userid_sqli_probe_e793b8399d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 815. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://moodle.sit.ac.in/moodle/webservice/rest/server.php?wsfunction=%27_cff_marker_wsfunction_sqli_probe_85db62934a`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_85db62934a`
- Response: HTTP `200` / Length `177` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Marker: `cff_marker_wsfunction_sqli_probe_85db62934a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `177`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 816. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin`
- Response: HTTP `301` / Length `329` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `329`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 817. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/classes`
- Response: HTTP `301` / Length `337` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `337`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 818. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/classes/form`
- Response: HTTP `301` / Length `342` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `342`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 819. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/classes/local`
- Response: HTTP `301` / Length `343` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `343`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 820. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/classes/local/externalpage`
- Response: HTTP `301` / Length `356` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `356`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 821. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/classes/local/settings`
- Response: HTTP `301` / Length `352` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `352`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 822. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/classes/privacy`
- Response: HTTP `301` / Length `345` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `345`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 823. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/cli`
- Response: HTTP `301` / Length `333` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `333`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 824. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/mnet`
- Response: HTTP `301` / Length `334` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `334`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 825. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/registration`
- Response: HTTP `301` / Length `342` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `342`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 826. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles`
- Response: HTTP `301` / Length `335` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `335`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 827. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes`
- Response: HTTP `301` / Length `343` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `343`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 828. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/classes/privacy`
- Response: HTTP `301` / Length `351` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `351`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 829. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/tests`
- Response: HTTP `301` / Length `341` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `341`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 830. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/roles/tests/behat`
- Response: HTTP `301` / Length `347` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `347`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 831. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/settings`
- Response: HTTP `301` / Length `338` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `338`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 832. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates`
- Response: HTTP `301` / Length `339` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `339`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 833. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/local`
- Response: HTTP `301` / Length `345` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `345`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 834. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/templates/local/settings`
- Response: HTTP `301` / Length `354` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `354`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 835. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tests`
- Response: HTTP `301` / Length `335` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `335`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 836. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tests/behat`
- Response: HTTP `301` / Length `341` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `341`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 837. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool`
- Response: HTTP `301` / Length `334` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `334`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 838. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics`
- Response: HTTP `301` / Length `344` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `344`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 839. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics/amd`
- Response: HTTP `301` / Length `348` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `348`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 840. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics/amd/build`
- Response: HTTP `301` / Length `354` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `354`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 841. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics/amd/src`
- Response: HTTP `301` / Length `352` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `352`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 842. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/admin/tool/analytics/classes`
- Response: HTTP `301` / Length `352` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `352`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 843. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/course/index.php`
- Response: HTTP `200` / Length `46940` / Type `text/html; charset=utf-8`
- Title: Course categories | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `46940`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta

### 844. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://moodle.sit.ac.in/moodle/index.php`
- Response: HTTP `200` / Length `2602588` / Type `text/html; charset=utf-8`
- Title: Home | SIT, Tumakuru
- Evidence: status=200; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2602588`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta

