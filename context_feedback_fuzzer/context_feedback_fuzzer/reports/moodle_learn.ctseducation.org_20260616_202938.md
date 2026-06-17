# Context Feedback Fuzzer Report

- Target: `https://learn.ctseducation.org/`
- Detected Platform: **moodle**
- Platform type: `LMS`
- Scan status: `done`
- Requests sent: `1000`
- Safety: GET-only, same-host scope, rate-limited, authorization flag required.
- Server technology hint: `php` / `unknown`
- Confirmed findings: `0`
- Possible findings: `800`
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
- joomla: 3
- drupal: 0
- liferay: 0
- sharepoint: 0
- moodle: 71

## Findings

Các finding được chia theo trạng thái `confirmed` hoặc `possible`. Confirmed nghĩa là có bằng chứng marker-based reflection/verification; possible nghĩa là dựa trên feedback/anomaly nhưng chưa có marker xác nhận.

### 1. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin/mnet?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_edb7584133`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_edb7584133`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_redirect_redirect_probe_edb7584133` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 2. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin/mnet?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_1bdecd933a`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_1bdecd933a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_redirect_redirect_probe_1bdecd933a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 3. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin/mnet?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_ec7f10104c`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_ec7f10104c`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_returnurl_redirect_probe_ec7f10104c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 4. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin/mnet?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_e5b3a84362`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_e5b3a84362`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_returnurl_redirect_probe_e5b3a84362` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 5. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin/roles?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_7350ad7d20`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_7350ad7d20`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_redirect_redirect_probe_7350ad7d20` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 6. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin/roles?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_7db99dac01`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_7db99dac01`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_redirect_redirect_probe_7db99dac01` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 7. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin/roles?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_b16da7d3ac`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_b16da7d3ac`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_returnurl_redirect_probe_b16da7d3ac` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 8. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin/roles?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_eac2c9943b`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_eac2c9943b`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_returnurl_redirect_probe_eac2c9943b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 9. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin/tool?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_fff2d00733`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_fff2d00733`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_redirect_redirect_probe_fff2d00733` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 10. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin/tool?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_97cfd1f4f9`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_97cfd1f4f9`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_redirect_redirect_probe_97cfd1f4f9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 11. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin/tool?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_91bffa733f`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_91bffa733f`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_returnurl_redirect_probe_91bffa733f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 12. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin/tool?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_c0ad8142f8`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_c0ad8142f8`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_returnurl_redirect_probe_c0ad8142f8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 13. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_cc24b2c056`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_cc24b2c056`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_redirect_redirect_probe_cc24b2c056` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 14. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_e480a7ef60`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_e480a7ef60`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_redirect_redirect_probe_e480a7ef60` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 15. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_6a3fd24c84`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_6a3fd24c84`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_returnurl_redirect_probe_6a3fd24c84` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 16. Possible Open Redirect
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible Open Redirect
- URL: `https://learn.ctseducation.org/admin?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_19206e4052`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_19206e4052`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: unique marker appeared in Location header
- Marker: `cff_marker_returnurl_redirect_probe_19206e4052` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; unique marker appeared in Location header

### 17. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?filearea=..%2F..%2Fcff_marker_filearea_path_traversal_probe_4e80c3e387`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filearea_path_traversal_probe_4e80c3e387`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_traversal_probe_4e80c3e387` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 18. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?filearea=..%2Fcff_marker_filearea_path_traversal_probe_9f773716bc`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filearea_path_traversal_probe_9f773716bc`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_traversal_probe_9f773716bc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 19. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?filename=..%2F..%2Fcff_marker_filename_path_traversal_probe_c0427d78fe`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filename_path_traversal_probe_c0427d78fe`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_traversal_probe_c0427d78fe` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 20. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?filename=..%2Fcff_marker_filename_path_traversal_probe_dabd0c059e`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filename_path_traversal_probe_dabd0c059e`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_traversal_probe_dabd0c059e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 21. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?filepath=..%2F..%2Fcff_marker_filepath_path_traversal_probe_39cf8a495d`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filepath_path_traversal_probe_39cf8a495d`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_traversal_probe_39cf8a495d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 22. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?filepath=..%2Fcff_marker_filepath_path_traversal_probe_7d33118817`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filepath_path_traversal_probe_7d33118817`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_traversal_probe_7d33118817` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 23. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?filearea=..%2F..%2Fcff_marker_filearea_path_traversal_probe_29ba264b6b`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filearea_path_traversal_probe_29ba264b6b`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_traversal_probe_29ba264b6b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 24. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?filearea=..%2Fcff_marker_filearea_path_traversal_probe_1f582001a8`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filearea_path_traversal_probe_1f582001a8`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_traversal_probe_1f582001a8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 25. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?filename=..%2F..%2Fcff_marker_filename_path_traversal_probe_b71223e121`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filename_path_traversal_probe_b71223e121`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_traversal_probe_b71223e121` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 26. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?filename=..%2Fcff_marker_filename_path_traversal_probe_229df2cce6`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filename_path_traversal_probe_229df2cce6`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_traversal_probe_229df2cce6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 27. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?filepath=..%2F..%2Fcff_marker_filepath_path_traversal_probe_c611ddf947`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filepath_path_traversal_probe_c611ddf947`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_traversal_probe_c611ddf947` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 28. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?filepath=..%2Fcff_marker_filepath_path_traversal_probe_ca57193fcf`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filepath_path_traversal_probe_ca57193fcf`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_traversal_probe_ca57193fcf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 29. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?component=%3Ccff_marker_component_xss_reflection_probe_f1e58aa8fc%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_component_xss_reflection_probe_f1e58aa8fc&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_reflection_probe_f1e58aa8fc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 30. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?component=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_component_xss_trigger_probe_35403d2441%27%29%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_component_xss_trigger_probe_35403d2441&#x27;)&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_trigger_probe_35403d2441` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 31. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?component=%3Cscript%3Ealert%28%27cff_marker_component_xss_trigger_probe_818ee1efb5%27%29%3C%2Fscript%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_component_xss_trigger_probe_818ee1efb5&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_trigger_probe_818ee1efb5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 32. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?component=cff_marker_component_text_canary_f70548689b`
- Parameter: `component` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_component_text_canary_f70548689b`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_text_canary_f70548689b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 33. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?contextid=-1_cff_marker_contextid_numeric_boundary_c86c7357d6`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_contextid_numeric_boundary_c86c7357d6`
- Response: HTTP `200` / Length `141` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_c86c7357d6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `141`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 34. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?contextid=0_cff_marker_contextid_numeric_boundary_92774096e9`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_contextid_numeric_boundary_92774096e9`
- Response: HTTP `200` / Length `208` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_92774096e9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `208`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 35. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?contextid=1_cff_marker_contextid_numeric_boundary_093c2a9229`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_contextid_numeric_boundary_093c2a9229`
- Response: HTTP `200` / Length `137` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_093c2a9229` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `137`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 36. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?contextid=999999_cff_marker_contextid_numeric_boundary_37a3bebe7c`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_contextid_numeric_boundary_37a3bebe7c`
- Response: HTTP `200` / Length `141` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_37a3bebe7c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `141`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 37. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?course=-1_cff_marker_course_numeric_boundary_0bbc3f86e2`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_0bbc3f86e2`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_0bbc3f86e2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 38. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?course=0_cff_marker_course_numeric_boundary_9e62541ed1`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_9e62541ed1`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_9e62541ed1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 39. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?course=1_cff_marker_course_numeric_boundary_967a0f501f`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_967a0f501f`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_967a0f501f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 40. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?course=999999_cff_marker_course_numeric_boundary_8e58aa685d`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_8e58aa685d`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_8e58aa685d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 41. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?courseid=-1_cff_marker_courseid_numeric_boundary_ea3c9e32da`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_ea3c9e32da`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_ea3c9e32da` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 42. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?courseid=0_cff_marker_courseid_numeric_boundary_260982aec3`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_260982aec3`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_260982aec3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 43. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?courseid=1_cff_marker_courseid_numeric_boundary_b91fa9e1c8`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_b91fa9e1c8`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_b91fa9e1c8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 44. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?courseid=999999_cff_marker_courseid_numeric_boundary_9a42ed0614`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_9a42ed0614`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_9a42ed0614` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 45. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?filearea=cff_marker_filearea_path_canary_5bcd7c11af`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filearea_path_canary_5bcd7c11af`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_canary_5bcd7c11af` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 46. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?filename=cff_marker_filename_path_canary_50fecc8221`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filename_path_canary_50fecc8221`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_canary_50fecc8221` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 47. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?filepath=cff_marker_filepath_path_canary_d008fe924e`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filepath_path_canary_d008fe924e`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_canary_d008fe924e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 48. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?id=-1_cff_marker_id_numeric_boundary_260b430c5c`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_260b430c5c`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_260b430c5c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 49. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?id=0_cff_marker_id_numeric_boundary_e4e346e6ae`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_e4e346e6ae`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_e4e346e6ae` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 50. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?id=1_cff_marker_id_numeric_boundary_8a625c9a82`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_8a625c9a82`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_8a625c9a82` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 51. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?id=999999_cff_marker_id_numeric_boundary_d9bcd19c5a`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_d9bcd19c5a`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_d9bcd19c5a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 52. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?itemid=-1_cff_marker_itemid_numeric_boundary_d03512323d`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_itemid_numeric_boundary_d03512323d`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_d03512323d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 53. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?itemid=0_cff_marker_itemid_numeric_boundary_b123f8e4f0`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_itemid_numeric_boundary_b123f8e4f0`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_b123f8e4f0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 54. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?itemid=1_cff_marker_itemid_numeric_boundary_02cdd208e2`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_itemid_numeric_boundary_02cdd208e2`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_02cdd208e2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 55. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?itemid=999999_cff_marker_itemid_numeric_boundary_1834c06813`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_itemid_numeric_boundary_1834c06813`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_1834c06813` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 56. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?moodlewsrestformat=%3Ccff_marker_moodlewsrestformat_xss_reflection_probe_ca90ece780%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_moodlewsrestformat_xss_reflection_probe_ca90ece780&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_reflection_probe_ca90ece780` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 57. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?moodlewsrestformat=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_55ba281ac2%27%29%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_55ba281ac2&#x27;)&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_55ba281ac2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 58. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?moodlewsrestformat=%3Cscript%3Ealert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_b9f95fb024%27%29%3C%2Fscript%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_b9f95fb024&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_b9f95fb024` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 59. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?moodlewsrestformat=cff_marker_moodlewsrestformat_text_canary_7e6db08431`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_moodlewsrestformat_text_canary_7e6db08431`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_text_canary_7e6db08431` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 60. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?page=-1_cff_marker_page_numeric_boundary_a3dc461bfc`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_a3dc461bfc`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_a3dc461bfc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 61. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?page=0_cff_marker_page_numeric_boundary_83d46f410c`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_83d46f410c`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_83d46f410c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 62. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?page=1_cff_marker_page_numeric_boundary_59aa478a5d`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_59aa478a5d`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_59aa478a5d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 63. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?page=999999_cff_marker_page_numeric_boundary_9270a5ba9f`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_9270a5ba9f`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_9270a5ba9f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 64. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?q=%3Ccff_marker_q_xss_reflection_probe_aa178dcd3c%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_aa178dcd3c&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_reflection_probe_aa178dcd3c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 65. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_q_xss_trigger_probe_86f5c162b2%27%29%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_q_xss_trigger_probe_86f5c162b2&#x27;)&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_trigger_probe_86f5c162b2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 66. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?q=%3Cscript%3Ealert%28%27cff_marker_q_xss_trigger_probe_e9f41d6ee0%27%29%3C%2Fscript%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_q_xss_trigger_probe_e9f41d6ee0&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_trigger_probe_e9f41d6ee0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 67. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?q=cff_marker_q_text_canary_c0ff36d1a0`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_c0ff36d1a0`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_text_canary_c0ff36d1a0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 68. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_c821e2b0d9`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_c821e2b0d9`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_c821e2b0d9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 69. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_bbd47002ad`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_bbd47002ad`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_bbd47002ad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 70. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_cadf42cf17`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_cadf42cf17`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_cadf42cf17` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 71. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_acd3ea8969`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_acd3ea8969`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_acd3ea8969` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 72. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?search=%3Ccff_marker_search_xss_reflection_probe_d47a940049%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_d47a940049&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_reflection_probe_d47a940049` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 73. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_bd0cbe5136%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_bd0cbe5136&#x27;)&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_bd0cbe5136` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 74. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_e67730f51e%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_e67730f51e&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_e67730f51e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 75. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?search=cff_marker_search_text_canary_9fbb7d197d`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_9fbb7d197d`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_text_canary_9fbb7d197d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 76. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?section=-1_cff_marker_section_numeric_boundary_3f187149bc`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_3f187149bc`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_3f187149bc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 77. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?section=0_cff_marker_section_numeric_boundary_149d2d9102`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_149d2d9102`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_149d2d9102` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 78. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?section=1_cff_marker_section_numeric_boundary_ec104107f2`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_ec104107f2`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_ec104107f2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 79. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?section=999999_cff_marker_section_numeric_boundary_e76ff2d7a2`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_e76ff2d7a2`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_e76ff2d7a2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 80. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?sesskey=cff_marker_sesskey_token_canary_6ce4f79e51`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_6ce4f79e51`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_canary_6ce4f79e51` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 81. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?sesskey=cff_marker_sesskey_token_empty_12d5be2b32`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_12d5be2b32`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_empty_12d5be2b32` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 82. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_b2113ac018`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_b2113ac018`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_invalid_b2113ac018` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 83. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?user=-1_cff_marker_user_numeric_boundary_7d0652b7db`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_7d0652b7db`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_7d0652b7db` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 84. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?user=0_cff_marker_user_numeric_boundary_754c935092`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_754c935092`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_754c935092` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 85. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?user=1_cff_marker_user_numeric_boundary_2acd2cc84d`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_2acd2cc84d`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_2acd2cc84d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 86. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?user=999999_cff_marker_user_numeric_boundary_f6981decbe`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_f6981decbe`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_f6981decbe` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 87. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?userid=-1_cff_marker_userid_numeric_boundary_3f695915bd`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_3f695915bd`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_3f695915bd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 88. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?userid=0_cff_marker_userid_numeric_boundary_9ee9d8190e`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_9ee9d8190e`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_9ee9d8190e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 89. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?userid=1_cff_marker_userid_numeric_boundary_323372d9c3`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_323372d9c3`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_323372d9c3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 90. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?userid=999999_cff_marker_userid_numeric_boundary_0a4fc4e3d9`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_0a4fc4e3d9`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_0a4fc4e3d9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 91. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_ea3ce96924%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_ea3ce96924&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_reflection_probe_ea3ce96924` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 92. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?wsfunction=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_wsfunction_xss_trigger_probe_1c0cd4a7f2%27%29%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_1c0cd4a7f2&#x27;)&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_trigger_probe_1c0cd4a7f2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 93. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?wsfunction=%3Cscript%3Ealert%28%27cff_marker_wsfunction_xss_trigger_probe_1249b9ccd1%27%29%3C%2Fscript%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_1249b9ccd1&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_trigger_probe_1249b9ccd1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 94. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?wsfunction=cff_marker_wsfunction_text_canary_f182cc4f50`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_f182cc4f50`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_text_canary_f182cc4f50` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 95. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?wstoken=cff_marker_wstoken_token_canary_58abf69bcb`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_58abf69bcb`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_canary_58abf69bcb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 96. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?wstoken=cff_marker_wstoken_token_empty_dd0251a115`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_dd0251a115`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_empty_dd0251a115` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 97. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_9ddcc5bf7f`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_9ddcc5bf7f`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_invalid_9ddcc5bf7f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape; debug/error keyword appeared in response

### 98. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/?filearea=..%2F..%2Fcff_marker_filearea_path_traversal_probe_ba3f296a6e`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filearea_path_traversal_probe_ba3f296a6e`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_traversal_probe_ba3f296a6e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 99. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/?filearea=..%2Fcff_marker_filearea_path_traversal_probe_7d9dfd1c61`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filearea_path_traversal_probe_7d9dfd1c61`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_traversal_probe_7d9dfd1c61` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 100. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/?filename=..%2F..%2Fcff_marker_filename_path_traversal_probe_b6a7315457`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filename_path_traversal_probe_b6a7315457`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_traversal_probe_b6a7315457` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 101. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/?filename=..%2Fcff_marker_filename_path_traversal_probe_fbba4bf965`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filename_path_traversal_probe_fbba4bf965`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_traversal_probe_fbba4bf965` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 102. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/?filepath=..%2F..%2Fcff_marker_filepath_path_traversal_probe_1c3fb0fa32`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filepath_path_traversal_probe_1c3fb0fa32`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_traversal_probe_1c3fb0fa32` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 103. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `70`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/?filepath=..%2Fcff_marker_filepath_path_traversal_probe_833cd70c3f`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filepath_path_traversal_probe_833cd70c3f`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: path-like input changed response size compared with baseline; debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_traversal_probe_833cd70c3f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; path-like input changed response size compared with baseline; debug/error keyword appeared in response

### 104. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?component=%3Ccff_marker_component_xss_reflection_probe_7178a8d36d%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_component_xss_reflection_probe_7178a8d36d&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_reflection_probe_7178a8d36d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 105. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?component=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_component_xss_trigger_probe_2ad454230e%27%29%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_component_xss_trigger_probe_2ad454230e&#x27;)&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_trigger_probe_2ad454230e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 106. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?component=%3Cscript%3Ealert%28%27cff_marker_component_xss_trigger_probe_ede1e14cb2%27%29%3C%2Fscript%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_component_xss_trigger_probe_ede1e14cb2&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_trigger_probe_ede1e14cb2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 107. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?component=cff_marker_component_text_canary_8807d6b082`
- Parameter: `component` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_component_text_canary_8807d6b082`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_text_canary_8807d6b082` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 108. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?contextid=-1_cff_marker_contextid_numeric_boundary_df20f7f262`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_contextid_numeric_boundary_df20f7f262`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_df20f7f262` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 109. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?contextid=0_cff_marker_contextid_numeric_boundary_eb87b43951`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_contextid_numeric_boundary_eb87b43951`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_eb87b43951` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 110. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?contextid=1_cff_marker_contextid_numeric_boundary_83446e5e17`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_contextid_numeric_boundary_83446e5e17`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_83446e5e17` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 111. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?contextid=999999_cff_marker_contextid_numeric_boundary_ad2e1d615c`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_contextid_numeric_boundary_ad2e1d615c`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_ad2e1d615c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 112. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?course=-1_cff_marker_course_numeric_boundary_f694871cc7`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_f694871cc7`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_f694871cc7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 113. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?course=0_cff_marker_course_numeric_boundary_1bb31c1d6d`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_1bb31c1d6d`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_1bb31c1d6d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 114. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?course=1_cff_marker_course_numeric_boundary_abd18f7291`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_abd18f7291`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_abd18f7291` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 115. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?course=999999_cff_marker_course_numeric_boundary_08e913c7fc`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_08e913c7fc`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_08e913c7fc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 116. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?courseid=-1_cff_marker_courseid_numeric_boundary_83ccec0b01`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_83ccec0b01`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_83ccec0b01` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 117. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?courseid=0_cff_marker_courseid_numeric_boundary_332c5d217f`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_332c5d217f`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_332c5d217f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 118. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?courseid=1_cff_marker_courseid_numeric_boundary_85e0a10c73`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_85e0a10c73`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_85e0a10c73` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 119. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?courseid=999999_cff_marker_courseid_numeric_boundary_0a0ec820c7`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_0a0ec820c7`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_0a0ec820c7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 120. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?filearea=cff_marker_filearea_path_canary_d384646442`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filearea_path_canary_d384646442`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_canary_d384646442` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 121. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?filename=cff_marker_filename_path_canary_67d0b2a0b3`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filename_path_canary_67d0b2a0b3`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_canary_67d0b2a0b3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 122. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?filepath=cff_marker_filepath_path_canary_0f5fccd103`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filepath_path_canary_0f5fccd103`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_canary_0f5fccd103` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 123. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?id=-1_cff_marker_id_numeric_boundary_d0c23879af`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_d0c23879af`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_d0c23879af` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 124. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?id=0_cff_marker_id_numeric_boundary_897747359e`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_897747359e`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_897747359e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 125. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?id=1_cff_marker_id_numeric_boundary_0311acf5cf`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_0311acf5cf`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_0311acf5cf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 126. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?id=999999_cff_marker_id_numeric_boundary_9e1fcc3ee9`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_9e1fcc3ee9`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_9e1fcc3ee9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 127. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?itemid=-1_cff_marker_itemid_numeric_boundary_35ae89e45d`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_itemid_numeric_boundary_35ae89e45d`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_35ae89e45d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 128. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?itemid=0_cff_marker_itemid_numeric_boundary_248a8bf024`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_itemid_numeric_boundary_248a8bf024`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_248a8bf024` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 129. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?itemid=1_cff_marker_itemid_numeric_boundary_8552677371`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_itemid_numeric_boundary_8552677371`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_8552677371` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 130. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?itemid=999999_cff_marker_itemid_numeric_boundary_a02a7f8999`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_itemid_numeric_boundary_a02a7f8999`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_a02a7f8999` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 131. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?moodlewsrestformat=%3Ccff_marker_moodlewsrestformat_xss_reflection_probe_312140e183%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_moodlewsrestformat_xss_reflection_probe_312140e183&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_reflection_probe_312140e183` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 132. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?moodlewsrestformat=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_226bd22dcb%27%29%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_226bd22dcb&#x27;)&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_226bd22dcb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 133. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?moodlewsrestformat=%3Cscript%3Ealert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_59d6824c1b%27%29%3C%2Fscript%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_59d6824c1b&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_59d6824c1b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 134. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?moodlewsrestformat=cff_marker_moodlewsrestformat_text_canary_38a8d7774e`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_moodlewsrestformat_text_canary_38a8d7774e`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_text_canary_38a8d7774e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 135. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?page=-1_cff_marker_page_numeric_boundary_72199d744d`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_72199d744d`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_72199d744d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 136. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?page=0_cff_marker_page_numeric_boundary_71666e07b8`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_71666e07b8`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_71666e07b8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 137. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?page=1_cff_marker_page_numeric_boundary_773e92d8d6`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_773e92d8d6`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_773e92d8d6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 138. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?page=999999_cff_marker_page_numeric_boundary_33dfa18b51`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_33dfa18b51`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_33dfa18b51` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 139. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?q=%3Ccff_marker_q_xss_reflection_probe_be0cebf3f9%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_be0cebf3f9&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_reflection_probe_be0cebf3f9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 140. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_q_xss_trigger_probe_e122746d4c%27%29%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_q_xss_trigger_probe_e122746d4c&#x27;)&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_trigger_probe_e122746d4c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 141. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?q=%3Cscript%3Ealert%28%27cff_marker_q_xss_trigger_probe_430b1769c9%27%29%3C%2Fscript%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_q_xss_trigger_probe_430b1769c9&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_trigger_probe_430b1769c9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 142. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?q=cff_marker_q_text_canary_30076d0860`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_30076d0860`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_text_canary_30076d0860` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 143. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_fe81d77bf6`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_fe81d77bf6`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_fe81d77bf6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 144. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_77a648e177`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_77a648e177`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_77a648e177` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 145. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_c4833fbe40`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_c4833fbe40`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_c4833fbe40` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 146. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_2879483a8c`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_2879483a8c`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_2879483a8c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 147. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?search=%3Ccff_marker_search_xss_reflection_probe_ad823db445%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_ad823db445&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_reflection_probe_ad823db445` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 148. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_276fdb5945%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_276fdb5945&#x27;)&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_276fdb5945` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 149. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_0e1736d13c%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_0e1736d13c&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_0e1736d13c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 150. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?search=cff_marker_search_text_canary_fb72272683`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_fb72272683`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_text_canary_fb72272683` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 151. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?section=-1_cff_marker_section_numeric_boundary_b39a417f6e`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_b39a417f6e`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_b39a417f6e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 152. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?section=0_cff_marker_section_numeric_boundary_128e4d591c`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_128e4d591c`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_128e4d591c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 153. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?section=1_cff_marker_section_numeric_boundary_234c119f3b`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_234c119f3b`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_234c119f3b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 154. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?section=999999_cff_marker_section_numeric_boundary_509cb585ca`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_509cb585ca`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_509cb585ca` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 155. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?sesskey=cff_marker_sesskey_token_canary_ab10ffa534`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_ab10ffa534`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_canary_ab10ffa534` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 156. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?sesskey=cff_marker_sesskey_token_empty_c63131d77a`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_c63131d77a`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_empty_c63131d77a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 157. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_3a4e8283a8`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_3a4e8283a8`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_invalid_3a4e8283a8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 158. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?user=-1_cff_marker_user_numeric_boundary_d7a48a38fb`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_d7a48a38fb`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_d7a48a38fb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 159. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?user=0_cff_marker_user_numeric_boundary_8c9e0e7b9d`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_8c9e0e7b9d`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_8c9e0e7b9d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 160. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?user=1_cff_marker_user_numeric_boundary_4d5355e744`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_4d5355e744`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_4d5355e744` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 161. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?user=999999_cff_marker_user_numeric_boundary_28afd0c4d8`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_28afd0c4d8`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_28afd0c4d8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 162. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?userid=-1_cff_marker_userid_numeric_boundary_02a6444f40`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_02a6444f40`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_02a6444f40` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 163. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?userid=0_cff_marker_userid_numeric_boundary_b8bb8f0fc3`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_b8bb8f0fc3`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_b8bb8f0fc3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 164. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?userid=1_cff_marker_userid_numeric_boundary_2d10c2b624`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_2d10c2b624`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_2d10c2b624` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 165. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?userid=999999_cff_marker_userid_numeric_boundary_a8e81d4926`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_a8e81d4926`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_a8e81d4926` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 166. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_9a5af33739%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_9a5af33739&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_reflection_probe_9a5af33739` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 167. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?wsfunction=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_wsfunction_xss_trigger_probe_9be68ef43d%27%29%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_9be68ef43d&#x27;)&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_trigger_probe_9be68ef43d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 168. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?wsfunction=%3Cscript%3Ealert%28%27cff_marker_wsfunction_xss_trigger_probe_01d77d0444%27%29%3C%2Fscript%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_01d77d0444&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_trigger_probe_01d77d0444` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 169. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?wsfunction=cff_marker_wsfunction_text_canary_48df435f10`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_48df435f10`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_text_canary_48df435f10` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 170. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?wstoken=cff_marker_wstoken_token_canary_51c6b6e71d`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_51c6b6e71d`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_canary_51c6b6e71d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 171. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?wstoken=cff_marker_wstoken_token_empty_ea3dfc1833`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_ea3dfc1833`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_empty_ea3dfc1833` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 172. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_740cdad7b3`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_740cdad7b3`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_invalid_740cdad7b3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; debug/error keyword appeared in response

### 173. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/mnet?filearea=..%2F..%2Fcff_marker_filearea_path_traversal_probe_1d5c52f379`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filearea_path_traversal_probe_1d5c52f379`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filearea_path_traversal_probe_1d5c52f379` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 174. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/mnet?filearea=..%2Fcff_marker_filearea_path_traversal_probe_ada129d64c`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filearea_path_traversal_probe_ada129d64c`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filearea_path_traversal_probe_ada129d64c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 175. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/mnet?filename=..%2F..%2Fcff_marker_filename_path_traversal_probe_8160f9b614`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filename_path_traversal_probe_8160f9b614`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filename_path_traversal_probe_8160f9b614` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 176. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/mnet?filename=..%2Fcff_marker_filename_path_traversal_probe_d38d5ee9b5`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filename_path_traversal_probe_d38d5ee9b5`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filename_path_traversal_probe_d38d5ee9b5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 177. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/mnet?filepath=..%2F..%2Fcff_marker_filepath_path_traversal_probe_bae84f5ed0`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filepath_path_traversal_probe_bae84f5ed0`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filepath_path_traversal_probe_bae84f5ed0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 178. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/mnet?filepath=..%2Fcff_marker_filepath_path_traversal_probe_3265b020ff`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filepath_path_traversal_probe_3265b020ff`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filepath_path_traversal_probe_3265b020ff` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 179. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/tool?filearea=..%2F..%2Fcff_marker_filearea_path_traversal_probe_711896c304`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filearea_path_traversal_probe_711896c304`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filearea_path_traversal_probe_711896c304` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 180. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/tool?filearea=..%2Fcff_marker_filearea_path_traversal_probe_a2bbd25668`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filearea_path_traversal_probe_a2bbd25668`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filearea_path_traversal_probe_a2bbd25668` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 181. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/tool?filename=..%2F..%2Fcff_marker_filename_path_traversal_probe_2b08415b85`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filename_path_traversal_probe_2b08415b85`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filename_path_traversal_probe_2b08415b85` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 182. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/tool?filename=..%2Fcff_marker_filename_path_traversal_probe_df3de51bf3`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filename_path_traversal_probe_df3de51bf3`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filename_path_traversal_probe_df3de51bf3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 183. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/tool?filepath=..%2F..%2Fcff_marker_filepath_path_traversal_probe_2e3b304139`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filepath_path_traversal_probe_2e3b304139`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filepath_path_traversal_probe_2e3b304139` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 184. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin/tool?filepath=..%2Fcff_marker_filepath_path_traversal_probe_e164c6e327`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filepath_path_traversal_probe_e164c6e327`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filepath_path_traversal_probe_e164c6e327` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 185. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin?filearea=..%2F..%2Fcff_marker_filearea_path_traversal_probe_9dae934702`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filearea_path_traversal_probe_9dae934702`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filearea_path_traversal_probe_9dae934702` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 186. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin?filearea=..%2Fcff_marker_filearea_path_traversal_probe_39fc2fd63a`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filearea_path_traversal_probe_39fc2fd63a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filearea_path_traversal_probe_39fc2fd63a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 187. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin?filename=..%2F..%2Fcff_marker_filename_path_traversal_probe_065450b848`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filename_path_traversal_probe_065450b848`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filename_path_traversal_probe_065450b848` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 188. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin?filename=..%2Fcff_marker_filename_path_traversal_probe_6e4a0146d8`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filename_path_traversal_probe_6e4a0146d8`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filename_path_traversal_probe_6e4a0146d8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 189. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin?filepath=..%2F..%2Fcff_marker_filepath_path_traversal_probe_dbbe06c244`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../../cff_marker_filepath_path_traversal_probe_dbbe06c244`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filepath_path_traversal_probe_dbbe06c244` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 190. Path Input Behavior Change
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Path Input Behavior Change
- URL: `https://learn.ctseducation.org/admin?filepath=..%2Fcff_marker_filepath_path_traversal_probe_9af62c80dd`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_traversal_probe` | Payload: `../cff_marker_filepath_path_traversal_probe_9af62c80dd`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: path-like input changed response size compared with baseline
- Marker: `cff_marker_filepath_path_traversal_probe_9af62c80dd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; path-like input changed response size compared with baseline

### 191. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?component=%3Ccff_marker_component_xss_reflection_probe_81716de8db%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_component_xss_reflection_probe_81716de8db&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_reflection_probe_81716de8db` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 192. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?component=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_component_xss_trigger_probe_aa09c8bb49%27%29%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_component_xss_trigger_probe_aa09c8bb49&#x27;)&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_trigger_probe_aa09c8bb49` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 193. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?component=%3Cscript%3Ealert%28%27cff_marker_component_xss_trigger_probe_cebb93f850%27%29%3C%2Fscript%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_component_xss_trigger_probe_cebb93f850&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_xss_trigger_probe_cebb93f850` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 194. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?component=cff_marker_component_text_canary_2bef3ec16d`
- Parameter: `component` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_component_text_canary_2bef3ec16d`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_component_text_canary_2bef3ec16d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 195. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?contextid=-1_cff_marker_contextid_numeric_boundary_f3a53d85e5`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_contextid_numeric_boundary_f3a53d85e5`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_f3a53d85e5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 196. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?contextid=0_cff_marker_contextid_numeric_boundary_62b59ce612`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_contextid_numeric_boundary_62b59ce612`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_62b59ce612` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 197. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?contextid=1_cff_marker_contextid_numeric_boundary_d05e1426a9`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_contextid_numeric_boundary_d05e1426a9`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_d05e1426a9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 198. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?contextid=999999_cff_marker_contextid_numeric_boundary_2d94bee387`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_contextid_numeric_boundary_2d94bee387`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_contextid_numeric_boundary_2d94bee387` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 199. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?course=-1_cff_marker_course_numeric_boundary_444ebfee76`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_444ebfee76`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_444ebfee76` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 200. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?course=0_cff_marker_course_numeric_boundary_ee5a1350d1`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_ee5a1350d1`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_ee5a1350d1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 201. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?course=1_cff_marker_course_numeric_boundary_673f70f0da`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_673f70f0da`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_673f70f0da` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 202. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?course=999999_cff_marker_course_numeric_boundary_7a59e7d3b9`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_7a59e7d3b9`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_course_numeric_boundary_7a59e7d3b9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 203. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?courseid=-1_cff_marker_courseid_numeric_boundary_d6ad4a50df`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_d6ad4a50df`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_d6ad4a50df` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 204. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?courseid=0_cff_marker_courseid_numeric_boundary_8586388456`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_8586388456`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_8586388456` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 205. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?courseid=1_cff_marker_courseid_numeric_boundary_05ff752a16`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_05ff752a16`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_05ff752a16` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 206. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?courseid=999999_cff_marker_courseid_numeric_boundary_29c9ced71c`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_29c9ced71c`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_courseid_numeric_boundary_29c9ced71c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 207. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?filearea=cff_marker_filearea_path_canary_cfb5f89109`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filearea_path_canary_cfb5f89109`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filearea_path_canary_cfb5f89109` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 208. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?filename=cff_marker_filename_path_canary_d338c0723e`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filename_path_canary_d338c0723e`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filename_path_canary_d338c0723e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 209. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?filepath=cff_marker_filepath_path_canary_75d225fe5d`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filepath_path_canary_75d225fe5d`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_filepath_path_canary_75d225fe5d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 210. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?id=-1_cff_marker_id_numeric_boundary_a2406e6520`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_a2406e6520`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_a2406e6520` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 211. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?id=0_cff_marker_id_numeric_boundary_22cd5e4deb`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_22cd5e4deb`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_22cd5e4deb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 212. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?id=1_cff_marker_id_numeric_boundary_b3a3b0d4e7`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_b3a3b0d4e7`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_b3a3b0d4e7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 213. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?id=999999_cff_marker_id_numeric_boundary_45c75d5dad`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_45c75d5dad`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_id_numeric_boundary_45c75d5dad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 214. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?itemid=-1_cff_marker_itemid_numeric_boundary_b500a31150`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_itemid_numeric_boundary_b500a31150`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_b500a31150` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 215. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?itemid=0_cff_marker_itemid_numeric_boundary_aa93c614f5`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_itemid_numeric_boundary_aa93c614f5`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_aa93c614f5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 216. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?itemid=1_cff_marker_itemid_numeric_boundary_437867ab31`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_itemid_numeric_boundary_437867ab31`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_437867ab31` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 217. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?itemid=999999_cff_marker_itemid_numeric_boundary_0bd9cae27e`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_itemid_numeric_boundary_0bd9cae27e`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_itemid_numeric_boundary_0bd9cae27e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 218. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?moodlewsrestformat=%3Ccff_marker_moodlewsrestformat_xss_reflection_probe_ee70f6c241%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_moodlewsrestformat_xss_reflection_probe_ee70f6c241&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_reflection_probe_ee70f6c241` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 219. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?moodlewsrestformat=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_8b6a1525cd%27%29%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_8b6a1525cd&#x27;)&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_8b6a1525cd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 220. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?moodlewsrestformat=%3Cscript%3Ealert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_aa115d5a03%27%29%3C%2Fscript%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_aa115d5a03&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_aa115d5a03` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 221. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?moodlewsrestformat=cff_marker_moodlewsrestformat_text_canary_5bc3d3d06f`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_moodlewsrestformat_text_canary_5bc3d3d06f`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_moodlewsrestformat_text_canary_5bc3d3d06f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 222. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?page=-1_cff_marker_page_numeric_boundary_390d113052`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_390d113052`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_390d113052` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 223. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?page=0_cff_marker_page_numeric_boundary_00c700bc0a`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_00c700bc0a`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_00c700bc0a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 224. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?page=1_cff_marker_page_numeric_boundary_65fd8d694e`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_65fd8d694e`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_65fd8d694e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 225. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?page=999999_cff_marker_page_numeric_boundary_0015b924c4`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_0015b924c4`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_page_numeric_boundary_0015b924c4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 226. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?q=%3Ccff_marker_q_xss_reflection_probe_ff85f0fc61%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_ff85f0fc61&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_reflection_probe_ff85f0fc61` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 227. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_q_xss_trigger_probe_e4c9b18b38%27%29%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_q_xss_trigger_probe_e4c9b18b38&#x27;)&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_trigger_probe_e4c9b18b38` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 228. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?q=%3Cscript%3Ealert%28%27cff_marker_q_xss_trigger_probe_ec33084194%27%29%3C%2Fscript%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_q_xss_trigger_probe_ec33084194&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_xss_trigger_probe_ec33084194` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 229. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?q=cff_marker_q_text_canary_22c7aa68c9`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_22c7aa68c9`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_q_text_canary_22c7aa68c9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 230. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?redirect=%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_c085b36ba0`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_redirect_redirect_probe_c085b36ba0`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_c085b36ba0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 231. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?redirect=https%3A%2F%2Fexample.com%2Fcff_marker_redirect_redirect_probe_6ae1599d83`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_redirect_redirect_probe_6ae1599d83`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_redirect_redirect_probe_6ae1599d83` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 232. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?returnurl=%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_6c9420249e`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_marker_returnurl_redirect_probe_6c9420249e`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_6c9420249e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 233. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?returnurl=https%3A%2F%2Fexample.com%2Fcff_marker_returnurl_redirect_probe_ef75e313d3`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_marker_returnurl_redirect_probe_ef75e313d3`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_returnurl_redirect_probe_ef75e313d3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 234. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?search=%3Ccff_marker_search_xss_reflection_probe_2db762bcf5%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_2db762bcf5&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_reflection_probe_2db762bcf5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 235. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_ff4355fea6%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_ff4355fea6&#x27;)&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_ff4355fea6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 236. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_545d535926%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_545d535926&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_xss_trigger_probe_545d535926` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 237. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?search=cff_marker_search_text_canary_2f60bca5c7`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_2f60bca5c7`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_search_text_canary_2f60bca5c7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 238. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?section=-1_cff_marker_section_numeric_boundary_328e39279f`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_328e39279f`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_328e39279f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 239. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?section=0_cff_marker_section_numeric_boundary_69997ee8b3`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_69997ee8b3`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_69997ee8b3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 240. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?section=1_cff_marker_section_numeric_boundary_bdeb8a1414`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_bdeb8a1414`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_bdeb8a1414` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 241. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?section=999999_cff_marker_section_numeric_boundary_978fae393d`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_978fae393d`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_section_numeric_boundary_978fae393d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 242. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?sesskey=cff_marker_sesskey_token_canary_74cf044f6e`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_74cf044f6e`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_canary_74cf044f6e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 243. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?sesskey=cff_marker_sesskey_token_empty_b25134fc87`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_b25134fc87`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_empty_b25134fc87` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 244. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_5a78cf98da`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_5a78cf98da`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_sesskey_token_invalid_5a78cf98da` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 245. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?user=-1_cff_marker_user_numeric_boundary_df4d837a95`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_df4d837a95`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_df4d837a95` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 246. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?user=0_cff_marker_user_numeric_boundary_135372bff6`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_135372bff6`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_135372bff6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 247. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?user=1_cff_marker_user_numeric_boundary_37e681c904`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_37e681c904`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_37e681c904` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 248. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?user=999999_cff_marker_user_numeric_boundary_9392e84ec3`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_9392e84ec3`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_user_numeric_boundary_9392e84ec3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 249. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?userid=-1_cff_marker_userid_numeric_boundary_b90fba4e4c`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_b90fba4e4c`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_b90fba4e4c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 250. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?userid=0_cff_marker_userid_numeric_boundary_2fae8817fb`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_2fae8817fb`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_2fae8817fb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 251. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?userid=1_cff_marker_userid_numeric_boundary_0d29366720`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_0d29366720`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_0d29366720` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 252. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?userid=999999_cff_marker_userid_numeric_boundary_8c20d815ce`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_8c20d815ce`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_userid_numeric_boundary_8c20d815ce` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 253. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_1e5a115023%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_1e5a115023&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_reflection_probe_1e5a115023` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 254. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?wsfunction=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_wsfunction_xss_trigger_probe_5648145f38%27%29%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_5648145f38&#x27;)&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_trigger_probe_5648145f38` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 255. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?wsfunction=%3Cscript%3Ealert%28%27cff_marker_wsfunction_xss_trigger_probe_86f07adc6d%27%29%3C%2Fscript%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_86f07adc6d&#x27;)&lt;/script&gt;`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_xss_trigger_probe_86f07adc6d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 256. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?wsfunction=cff_marker_wsfunction_text_canary_aa2e1012a1`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_aa2e1012a1`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wsfunction_text_canary_aa2e1012a1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 257. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?wstoken=cff_marker_wstoken_token_canary_d831e4fcdb`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_d831e4fcdb`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_canary_d831e4fcdb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 258. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?wstoken=cff_marker_wstoken_token_empty_8969f0cf4a`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_8969f0cf4a`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_empty_8969f0cf4a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 259. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `https://learn.ctseducation.org/?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_3e1cffe674`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_3e1cffe674`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: debug/error keyword appeared in response
- Marker: `cff_marker_wstoken_token_invalid_3e1cffe674` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 260. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?component=%27_cff_marker_component_sqli_probe_20aebe1f34`
- Parameter: `component` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_component_sqli_probe_20aebe1f34`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_component_sqli_probe_20aebe1f34` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 261. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?contextid=1%22_cff_marker_contextid_sqli_probe_e1b3085977`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_contextid_sqli_probe_e1b3085977`
- Response: HTTP `200` / Length `137` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_e1b3085977` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `137`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 262. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?contextid=1%27_cff_marker_contextid_sqli_probe_cb69b762bc`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_contextid_sqli_probe_cb69b762bc`
- Response: HTTP `200` / Length `137` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_cb69b762bc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `137`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 263. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?course=1%22_cff_marker_course_sqli_probe_04aa95d4bb`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_04aa95d4bb`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_04aa95d4bb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 264. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?course=1%27_cff_marker_course_sqli_probe_6b25e5011f`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_6b25e5011f`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_6b25e5011f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 265. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?courseid=1%22_cff_marker_courseid_sqli_probe_02369ea836`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_02369ea836`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_02369ea836` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 266. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?courseid=1%27_cff_marker_courseid_sqli_probe_a9482e87c4`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_a9482e87c4`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_a9482e87c4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 267. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?id=1%22_cff_marker_id_sqli_probe_bfecde3a4d`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_bfecde3a4d`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_bfecde3a4d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 268. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?id=1%27_cff_marker_id_sqli_probe_6ece6ad4f0`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_6ece6ad4f0`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_6ece6ad4f0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 269. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?itemid=1%22_cff_marker_itemid_sqli_probe_91f457f810`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_itemid_sqli_probe_91f457f810`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_91f457f810` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 270. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?itemid=1%27_cff_marker_itemid_sqli_probe_bcf4b6e68f`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_itemid_sqli_probe_bcf4b6e68f`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_bcf4b6e68f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 271. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?moodlewsrestformat=%27_cff_marker_moodlewsrestformat_sqli_probe_cbe24b474f`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_moodlewsrestformat_sqli_probe_cbe24b474f`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_sqli_probe_cbe24b474f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 272. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?page=1%22_cff_marker_page_sqli_probe_44bae58c00`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_44bae58c00`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_44bae58c00` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 273. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?page=1%27_cff_marker_page_sqli_probe_771ad3a0ad`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_771ad3a0ad`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_771ad3a0ad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 274. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?q=%27_cff_marker_q_sqli_probe_a54b133ce4`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_a54b133ce4`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_q_sqli_probe_a54b133ce4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 275. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?search=%27_cff_marker_search_sqli_probe_83f2d9f851`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_83f2d9f851`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_83f2d9f851` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 276. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?section=1%22_cff_marker_section_sqli_probe_1d91aadd65`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_1d91aadd65`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_1d91aadd65` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 277. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?section=1%27_cff_marker_section_sqli_probe_5f7cdaa248`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_5f7cdaa248`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_5f7cdaa248` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 278. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?user=1%22_cff_marker_user_sqli_probe_0f2a138a33`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_0f2a138a33`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_0f2a138a33` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 279. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?user=1%27_cff_marker_user_sqli_probe_bcfc433d5a`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_bcfc433d5a`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_bcfc433d5a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 280. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?userid=1%22_cff_marker_userid_sqli_probe_6f4c706347`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_6f4c706347`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_6f4c706347` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 281. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?userid=1%27_cff_marker_userid_sqli_probe_137f5a0e86`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_137f5a0e86`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_137f5a0e86` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 282. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles/ajax.php?wsfunction=%27_cff_marker_wsfunction_sqli_probe_dfb5d06efe`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_dfb5d06efe`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape
- Marker: `cff_marker_wsfunction_sqli_probe_dfb5d06efe` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; API-like endpoint; parameter changed response shape

### 283. Interesting path / response anomaly
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

### 284. Interesting path / response anomaly
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

### 285. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?component=%27_cff_marker_component_sqli_probe_2955a19b68`
- Parameter: `component` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_component_sqli_probe_2955a19b68`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_sqli_probe_2955a19b68` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 286. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?contextid=1%22_cff_marker_contextid_sqli_probe_223605cad3`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_contextid_sqli_probe_223605cad3`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_223605cad3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 287. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?contextid=1%27_cff_marker_contextid_sqli_probe_b2306cccad`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_contextid_sqli_probe_b2306cccad`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_b2306cccad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 288. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?course=1%22_cff_marker_course_sqli_probe_0b0ca3f739`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_0b0ca3f739`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_0b0ca3f739` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 289. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?course=1%27_cff_marker_course_sqli_probe_59b24861e3`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_59b24861e3`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_59b24861e3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 290. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?courseid=1%22_cff_marker_courseid_sqli_probe_b95d71e88a`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_b95d71e88a`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_b95d71e88a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 291. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?courseid=1%27_cff_marker_courseid_sqli_probe_6c53f57584`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_6c53f57584`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_6c53f57584` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 292. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?id=1%22_cff_marker_id_sqli_probe_3c5c1c9ee5`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_3c5c1c9ee5`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_3c5c1c9ee5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 293. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?id=1%27_cff_marker_id_sqli_probe_b13c3b786c`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_b13c3b786c`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_b13c3b786c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 294. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?itemid=1%22_cff_marker_itemid_sqli_probe_1e0c9aac35`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_itemid_sqli_probe_1e0c9aac35`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_1e0c9aac35` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 295. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?itemid=1%27_cff_marker_itemid_sqli_probe_4001b4cf3a`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_itemid_sqli_probe_4001b4cf3a`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_4001b4cf3a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 296. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?moodlewsrestformat=%27_cff_marker_moodlewsrestformat_sqli_probe_df8ad75fb5`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_moodlewsrestformat_sqli_probe_df8ad75fb5`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_sqli_probe_df8ad75fb5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 297. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?page=1%22_cff_marker_page_sqli_probe_f903595325`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_f903595325`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_f903595325` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 298. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?page=1%27_cff_marker_page_sqli_probe_9b0f5e9ab0`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_9b0f5e9ab0`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_9b0f5e9ab0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 299. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?q=%27_cff_marker_q_sqli_probe_f1d21d0a55`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_f1d21d0a55`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_sqli_probe_f1d21d0a55` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 300. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?search=%27_cff_marker_search_sqli_probe_6c78584904`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_6c78584904`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_6c78584904` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 301. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?section=1%22_cff_marker_section_sqli_probe_ce1c968db9`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_ce1c968db9`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_ce1c968db9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 302. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?section=1%27_cff_marker_section_sqli_probe_74d34283ee`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_74d34283ee`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_74d34283ee` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 303. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?user=1%22_cff_marker_user_sqli_probe_805597312e`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_805597312e`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_805597312e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 304. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?user=1%27_cff_marker_user_sqli_probe_23f6849d8f`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_23f6849d8f`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_23f6849d8f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 305. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?userid=1%22_cff_marker_userid_sqli_probe_b3f587f30c`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_b3f587f30c`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_b3f587f30c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 306. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?userid=1%27_cff_marker_userid_sqli_probe_ae8f0740eb`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_ae8f0740eb`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_ae8f0740eb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 307. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/webservice/rest/server.php?wsfunction=%27_cff_marker_wsfunction_sqli_probe_402851c785`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_402851c785`
- Response: HTTP `200` / Length `192` / Type `application/xml; charset=utf-8`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_sqli_probe_402851c785` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `192`
  - Content-Type: `application/xml; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 308. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?component=%27_cff_marker_component_sqli_probe_e0d97ef919`
- Parameter: `component` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_component_sqli_probe_e0d97ef919`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_sqli_probe_e0d97ef919` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 309. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?component=%3Ccff_marker_component_xss_reflection_probe_d1889508aa%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_component_xss_reflection_probe_d1889508aa&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_reflection_probe_d1889508aa` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 310. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?component=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_component_xss_trigger_probe_af9133948c%27%29%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_component_xss_trigger_probe_af9133948c&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_trigger_probe_af9133948c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 311. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?component=%3Cscript%3Ealert%28%27cff_marker_component_xss_trigger_probe_1e74cccdd1%27%29%3C%2Fscript%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_component_xss_trigger_probe_1e74cccdd1&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_trigger_probe_1e74cccdd1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 312. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?component=cff_marker_component_text_canary_0f69513fd6`
- Parameter: `component` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_component_text_canary_0f69513fd6`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_text_canary_0f69513fd6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 313. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?contextid=-1_cff_marker_contextid_numeric_boundary_36b50dd265`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_contextid_numeric_boundary_36b50dd265`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_36b50dd265` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 314. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?contextid=0_cff_marker_contextid_numeric_boundary_48c1df8687`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_contextid_numeric_boundary_48c1df8687`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_48c1df8687` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 315. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?contextid=1%22_cff_marker_contextid_sqli_probe_d385d6a54d`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_contextid_sqli_probe_d385d6a54d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_d385d6a54d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 316. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?contextid=1%27_cff_marker_contextid_sqli_probe_dae7e2f4f2`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_contextid_sqli_probe_dae7e2f4f2`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_dae7e2f4f2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 317. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?contextid=1_cff_marker_contextid_numeric_boundary_96d5696600`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_contextid_numeric_boundary_96d5696600`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_96d5696600` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 318. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?contextid=999999_cff_marker_contextid_numeric_boundary_f643e7e491`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_contextid_numeric_boundary_f643e7e491`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_f643e7e491` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 319. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?course=-1_cff_marker_course_numeric_boundary_f4695e5dbf`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_f4695e5dbf`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_f4695e5dbf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 320. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?course=0_cff_marker_course_numeric_boundary_e1d99d9ac6`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_e1d99d9ac6`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_e1d99d9ac6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 321. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?course=1%22_cff_marker_course_sqli_probe_244f11d867`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_244f11d867`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_244f11d867` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 322. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?course=1%27_cff_marker_course_sqli_probe_c0b5ce3952`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_c0b5ce3952`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_c0b5ce3952` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 323. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?course=1_cff_marker_course_numeric_boundary_6309af1aae`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_6309af1aae`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_6309af1aae` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 324. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?course=999999_cff_marker_course_numeric_boundary_f46920a771`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_f46920a771`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_f46920a771` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 325. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?courseid=-1_cff_marker_courseid_numeric_boundary_abfba5d78f`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_abfba5d78f`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_abfba5d78f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 326. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?courseid=0_cff_marker_courseid_numeric_boundary_f723d483f5`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_f723d483f5`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_f723d483f5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 327. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?courseid=1%22_cff_marker_courseid_sqli_probe_5c3afc67bf`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_5c3afc67bf`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_5c3afc67bf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 328. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?courseid=1%27_cff_marker_courseid_sqli_probe_61997ca841`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_61997ca841`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_61997ca841` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 329. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?courseid=1_cff_marker_courseid_numeric_boundary_fc3d2ab8b8`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_fc3d2ab8b8`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_fc3d2ab8b8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 330. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?courseid=999999_cff_marker_courseid_numeric_boundary_ff1b8fd837`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_ff1b8fd837`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_ff1b8fd837` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 331. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?filearea=cff_marker_filearea_path_canary_1010265a77`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filearea_path_canary_1010265a77`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filearea_path_canary_1010265a77` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 332. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?filename=cff_marker_filename_path_canary_4d985187fd`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filename_path_canary_4d985187fd`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filename_path_canary_4d985187fd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 333. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?filepath=cff_marker_filepath_path_canary_50d4ef2932`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filepath_path_canary_50d4ef2932`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filepath_path_canary_50d4ef2932` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 334. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?id=-1_cff_marker_id_numeric_boundary_1c50061291`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_1c50061291`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_1c50061291` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 335. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?id=0_cff_marker_id_numeric_boundary_33a2998282`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_33a2998282`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_33a2998282` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 336. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?id=1%22_cff_marker_id_sqli_probe_4f07998da8`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_4f07998da8`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_4f07998da8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 337. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?id=1%27_cff_marker_id_sqli_probe_2cfc0a3e0a`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_2cfc0a3e0a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_2cfc0a3e0a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 338. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?id=1_cff_marker_id_numeric_boundary_4b21d2a732`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_4b21d2a732`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_4b21d2a732` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 339. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?id=999999_cff_marker_id_numeric_boundary_5e144dcb9d`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_5e144dcb9d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_5e144dcb9d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 340. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?itemid=-1_cff_marker_itemid_numeric_boundary_37be83d41e`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_itemid_numeric_boundary_37be83d41e`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_37be83d41e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 341. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?itemid=0_cff_marker_itemid_numeric_boundary_d02d39baa7`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_itemid_numeric_boundary_d02d39baa7`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_d02d39baa7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 342. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?itemid=1%22_cff_marker_itemid_sqli_probe_eb8ef963e7`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_itemid_sqli_probe_eb8ef963e7`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_eb8ef963e7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 343. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?itemid=1%27_cff_marker_itemid_sqli_probe_3b367e690a`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_itemid_sqli_probe_3b367e690a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_3b367e690a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 344. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?itemid=1_cff_marker_itemid_numeric_boundary_889c020417`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_itemid_numeric_boundary_889c020417`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_889c020417` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 345. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?itemid=999999_cff_marker_itemid_numeric_boundary_aa2b146728`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_itemid_numeric_boundary_aa2b146728`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_aa2b146728` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 346. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?moodlewsrestformat=%27_cff_marker_moodlewsrestformat_sqli_probe_ecfe9d262b`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_moodlewsrestformat_sqli_probe_ecfe9d262b`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_sqli_probe_ecfe9d262b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 347. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?moodlewsrestformat=%3Ccff_marker_moodlewsrestformat_xss_reflection_probe_4fc3cdec2f%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_moodlewsrestformat_xss_reflection_probe_4fc3cdec2f&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_reflection_probe_4fc3cdec2f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 348. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?moodlewsrestformat=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_2ddfde9b32%27%29%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_2ddfde9b32&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_2ddfde9b32` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 349. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?moodlewsrestformat=%3Cscript%3Ealert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_c4802d80f2%27%29%3C%2Fscript%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_c4802d80f2&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_c4802d80f2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 350. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?moodlewsrestformat=cff_marker_moodlewsrestformat_text_canary_5a0a1b6a6c`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_moodlewsrestformat_text_canary_5a0a1b6a6c`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_text_canary_5a0a1b6a6c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 351. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?page=-1_cff_marker_page_numeric_boundary_327a3df01e`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_327a3df01e`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_327a3df01e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 352. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?page=0_cff_marker_page_numeric_boundary_2b17c8f7f1`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_2b17c8f7f1`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_2b17c8f7f1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 353. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?page=1%22_cff_marker_page_sqli_probe_f5b3422cbe`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_f5b3422cbe`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_f5b3422cbe` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 354. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?page=1%27_cff_marker_page_sqli_probe_7fdfa9455b`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_7fdfa9455b`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_7fdfa9455b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 355. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?page=1_cff_marker_page_numeric_boundary_300e7dc4f1`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_300e7dc4f1`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_300e7dc4f1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 356. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?page=999999_cff_marker_page_numeric_boundary_426b6d5a8d`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_426b6d5a8d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_426b6d5a8d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 357. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?q=%27_cff_marker_q_sqli_probe_bf59629608`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_bf59629608`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_sqli_probe_bf59629608` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 358. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?q=%3Ccff_marker_q_xss_reflection_probe_09c255320c%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_09c255320c&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_reflection_probe_09c255320c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 359. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_q_xss_trigger_probe_e2c40080dd%27%29%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_q_xss_trigger_probe_e2c40080dd&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_trigger_probe_e2c40080dd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 360. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?q=%3Cscript%3Ealert%28%27cff_marker_q_xss_trigger_probe_f089847862%27%29%3C%2Fscript%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_q_xss_trigger_probe_f089847862&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_trigger_probe_f089847862` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 361. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?q=cff_marker_q_text_canary_01c9d2652a`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_01c9d2652a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_text_canary_01c9d2652a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 362. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?search=%27_cff_marker_search_sqli_probe_000ab2c63f`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_000ab2c63f`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_000ab2c63f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 363. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?search=%3Ccff_marker_search_xss_reflection_probe_2b11d7e15f%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_2b11d7e15f&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_2b11d7e15f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 364. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_2eb5316d24%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_2eb5316d24&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_2eb5316d24` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 365. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_9a0551472b%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_9a0551472b&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_9a0551472b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 366. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?search=cff_marker_search_text_canary_4453db336e`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_4453db336e`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_text_canary_4453db336e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 367. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?section=-1_cff_marker_section_numeric_boundary_8fb813b278`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_8fb813b278`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_8fb813b278` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 368. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?section=0_cff_marker_section_numeric_boundary_aba88e45ea`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_aba88e45ea`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_aba88e45ea` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 369. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?section=1%22_cff_marker_section_sqli_probe_b580ef3287`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_b580ef3287`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_b580ef3287` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 370. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?section=1%27_cff_marker_section_sqli_probe_4413750061`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_4413750061`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_4413750061` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 371. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?section=1_cff_marker_section_numeric_boundary_66f5df9692`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_66f5df9692`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_66f5df9692` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 372. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?section=999999_cff_marker_section_numeric_boundary_39bd8ed7d1`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_39bd8ed7d1`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_39bd8ed7d1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 373. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?sesskey=cff_marker_sesskey_token_canary_fe00218932`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_fe00218932`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_canary_fe00218932` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 374. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?sesskey=cff_marker_sesskey_token_empty_cdbb970d42`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_cdbb970d42`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_empty_cdbb970d42` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 375. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_bf41de3be2`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_bf41de3be2`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_invalid_bf41de3be2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 376. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?user=-1_cff_marker_user_numeric_boundary_00d83db9f7`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_00d83db9f7`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_00d83db9f7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 377. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?user=0_cff_marker_user_numeric_boundary_08ecd9cd0a`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_08ecd9cd0a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_08ecd9cd0a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 378. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?user=1%22_cff_marker_user_sqli_probe_a162f5ec59`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_a162f5ec59`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_a162f5ec59` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 379. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?user=1%27_cff_marker_user_sqli_probe_f62d83720c`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_f62d83720c`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_f62d83720c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 380. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?user=1_cff_marker_user_numeric_boundary_dc51a33bc0`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_dc51a33bc0`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_dc51a33bc0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 381. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?user=999999_cff_marker_user_numeric_boundary_805a10c9e5`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_805a10c9e5`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_805a10c9e5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 382. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?userid=-1_cff_marker_userid_numeric_boundary_814bda831f`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_814bda831f`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_814bda831f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 383. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?userid=0_cff_marker_userid_numeric_boundary_29bd49d439`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_29bd49d439`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_29bd49d439` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 384. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?userid=1%22_cff_marker_userid_sqli_probe_49e96f1e25`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_49e96f1e25`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_49e96f1e25` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 385. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?userid=1%27_cff_marker_userid_sqli_probe_08503e35d4`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_08503e35d4`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_08503e35d4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 386. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?userid=1_cff_marker_userid_numeric_boundary_117d5cd06d`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_117d5cd06d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_117d5cd06d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 387. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?userid=999999_cff_marker_userid_numeric_boundary_c50f3fa661`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_c50f3fa661`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_c50f3fa661` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 388. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?wsfunction=%27_cff_marker_wsfunction_sqli_probe_47924055b0`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_47924055b0`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_sqli_probe_47924055b0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 389. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_9e45ba121b%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_9e45ba121b&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_reflection_probe_9e45ba121b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 390. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?wsfunction=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_wsfunction_xss_trigger_probe_2a9cc76161%27%29%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_2a9cc76161&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_trigger_probe_2a9cc76161` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 391. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?wsfunction=%3Cscript%3Ealert%28%27cff_marker_wsfunction_xss_trigger_probe_86b2234482%27%29%3C%2Fscript%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_86b2234482&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_trigger_probe_86b2234482` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 392. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?wsfunction=cff_marker_wsfunction_text_canary_491f8cee3f`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_491f8cee3f`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_text_canary_491f8cee3f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 393. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?wstoken=cff_marker_wstoken_token_canary_cd90000a41`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_cd90000a41`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_canary_cd90000a41` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 394. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?wstoken=cff_marker_wstoken_token_empty_cb4ea9f549`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_cb4ea9f549`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_empty_cb4ea9f549` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 395. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/mnet?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_b4932d5a2d`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_b4932d5a2d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_invalid_b4932d5a2d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 396. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?component=%27_cff_marker_component_sqli_probe_878dd89884`
- Parameter: `component` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_component_sqli_probe_878dd89884`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_sqli_probe_878dd89884` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 397. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?component=%3Ccff_marker_component_xss_reflection_probe_fe6e8f3ee0%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_component_xss_reflection_probe_fe6e8f3ee0&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_reflection_probe_fe6e8f3ee0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 398. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?component=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_component_xss_trigger_probe_754e968fc6%27%29%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_component_xss_trigger_probe_754e968fc6&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_trigger_probe_754e968fc6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 399. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?component=%3Cscript%3Ealert%28%27cff_marker_component_xss_trigger_probe_4cc6363aa3%27%29%3C%2Fscript%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_component_xss_trigger_probe_4cc6363aa3&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_trigger_probe_4cc6363aa3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 400. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?component=cff_marker_component_text_canary_dc9cc5bc06`
- Parameter: `component` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_component_text_canary_dc9cc5bc06`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_text_canary_dc9cc5bc06` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 401. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?contextid=0_cff_marker_contextid_numeric_boundary_2e8d1922c7`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_contextid_numeric_boundary_2e8d1922c7`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_2e8d1922c7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 402. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?contextid=1_cff_marker_contextid_numeric_boundary_9b0082f33a`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_contextid_numeric_boundary_9b0082f33a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_9b0082f33a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 403. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?course=-1_cff_marker_course_numeric_boundary_172b9125ea`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_172b9125ea`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_172b9125ea` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 404. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?course=0_cff_marker_course_numeric_boundary_d47f6f00bd`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_d47f6f00bd`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_d47f6f00bd` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 405. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?course=1%22_cff_marker_course_sqli_probe_6b9800eaa3`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_6b9800eaa3`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_6b9800eaa3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 406. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?course=1%27_cff_marker_course_sqli_probe_97cfd68808`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_97cfd68808`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_97cfd68808` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 407. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?course=1_cff_marker_course_numeric_boundary_da7b722fe3`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_da7b722fe3`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_da7b722fe3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 408. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?course=999999_cff_marker_course_numeric_boundary_65e0b76d52`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_65e0b76d52`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_65e0b76d52` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 409. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?courseid=-1_cff_marker_courseid_numeric_boundary_938cb92a17`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_938cb92a17`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_938cb92a17` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 410. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?courseid=0_cff_marker_courseid_numeric_boundary_275b47e19b`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_275b47e19b`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_275b47e19b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 411. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?courseid=1%22_cff_marker_courseid_sqli_probe_6581719d48`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_6581719d48`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_6581719d48` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 412. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?courseid=1%27_cff_marker_courseid_sqli_probe_804a0053e4`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_804a0053e4`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_804a0053e4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 413. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?courseid=1_cff_marker_courseid_numeric_boundary_c35b2d9694`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_c35b2d9694`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_c35b2d9694` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 414. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?courseid=999999_cff_marker_courseid_numeric_boundary_d1f6c1dacb`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_d1f6c1dacb`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_d1f6c1dacb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 415. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?id=-1_cff_marker_id_numeric_boundary_256db6a28c`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_256db6a28c`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_256db6a28c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 416. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?id=0_cff_marker_id_numeric_boundary_6487745561`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_6487745561`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_6487745561` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 417. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?id=1%22_cff_marker_id_sqli_probe_5041431eae`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_5041431eae`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_5041431eae` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 418. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?id=1%27_cff_marker_id_sqli_probe_081cc2fae2`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_081cc2fae2`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_081cc2fae2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 419. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?id=1_cff_marker_id_numeric_boundary_53749b9175`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_53749b9175`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_53749b9175` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 420. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?id=999999_cff_marker_id_numeric_boundary_786966d4e4`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_786966d4e4`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_786966d4e4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 421. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?moodlewsrestformat=%27_cff_marker_moodlewsrestformat_sqli_probe_da06fefe05`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_moodlewsrestformat_sqli_probe_da06fefe05`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_sqli_probe_da06fefe05` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 422. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?moodlewsrestformat=%3Ccff_marker_moodlewsrestformat_xss_reflection_probe_0bd2d0b3b2%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_moodlewsrestformat_xss_reflection_probe_0bd2d0b3b2&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_reflection_probe_0bd2d0b3b2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 423. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?moodlewsrestformat=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_eef7ab6e96%27%29%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_eef7ab6e96&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_eef7ab6e96` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 424. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?moodlewsrestformat=%3Cscript%3Ealert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_9a1f532977%27%29%3C%2Fscript%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_9a1f532977&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_9a1f532977` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 425. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?moodlewsrestformat=cff_marker_moodlewsrestformat_text_canary_3be07d8833`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_moodlewsrestformat_text_canary_3be07d8833`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_text_canary_3be07d8833` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 426. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?page=-1_cff_marker_page_numeric_boundary_97df56af6c`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_97df56af6c`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_97df56af6c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 427. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?page=0_cff_marker_page_numeric_boundary_013b83b852`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_013b83b852`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_013b83b852` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 428. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?page=1%22_cff_marker_page_sqli_probe_6dfcce3208`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_6dfcce3208`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_6dfcce3208` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 429. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?page=1%27_cff_marker_page_sqli_probe_1e7d4687a2`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_1e7d4687a2`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_1e7d4687a2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 430. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?page=1_cff_marker_page_numeric_boundary_a2a91044d2`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_a2a91044d2`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_a2a91044d2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 431. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?page=999999_cff_marker_page_numeric_boundary_0dd92b3aab`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_0dd92b3aab`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_0dd92b3aab` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 432. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?q=%27_cff_marker_q_sqli_probe_7ee7067cf6`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_7ee7067cf6`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_sqli_probe_7ee7067cf6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 433. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?q=%3Ccff_marker_q_xss_reflection_probe_813a52f57d%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_813a52f57d&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_reflection_probe_813a52f57d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 434. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_q_xss_trigger_probe_253ec50330%27%29%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_q_xss_trigger_probe_253ec50330&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_trigger_probe_253ec50330` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 435. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?q=%3Cscript%3Ealert%28%27cff_marker_q_xss_trigger_probe_64368bfea9%27%29%3C%2Fscript%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_q_xss_trigger_probe_64368bfea9&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_trigger_probe_64368bfea9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 436. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?q=cff_marker_q_text_canary_e47323314a`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_e47323314a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_text_canary_e47323314a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 437. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?search=%27_cff_marker_search_sqli_probe_0b990abf7c`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_0b990abf7c`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_0b990abf7c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 438. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?search=%3Ccff_marker_search_xss_reflection_probe_317c056f62%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_317c056f62&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_317c056f62` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 439. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_a80bc92298%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_a80bc92298&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_a80bc92298` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 440. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_8d90d8553a%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_8d90d8553a&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_8d90d8553a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 441. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?search=cff_marker_search_text_canary_5e0aa06550`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_5e0aa06550`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_text_canary_5e0aa06550` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 442. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?section=-1_cff_marker_section_numeric_boundary_9ca5884c9a`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_9ca5884c9a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_9ca5884c9a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 443. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?section=0_cff_marker_section_numeric_boundary_d376409f78`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_d376409f78`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_d376409f78` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 444. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?section=1%22_cff_marker_section_sqli_probe_3dc045c05e`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_3dc045c05e`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_3dc045c05e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 445. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?section=1%27_cff_marker_section_sqli_probe_205dd43608`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_205dd43608`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_205dd43608` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 446. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?section=1_cff_marker_section_numeric_boundary_4f0d03cc34`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_4f0d03cc34`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_4f0d03cc34` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 447. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?section=999999_cff_marker_section_numeric_boundary_ff3517ba1b`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_ff3517ba1b`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_ff3517ba1b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 448. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?sesskey=cff_marker_sesskey_token_canary_8ceb5e7d08`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_8ceb5e7d08`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_canary_8ceb5e7d08` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 449. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?sesskey=cff_marker_sesskey_token_empty_d7c6aa9e35`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_d7c6aa9e35`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_empty_d7c6aa9e35` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 450. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_4ddff7450a`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_4ddff7450a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_invalid_4ddff7450a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 451. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?user=-1_cff_marker_user_numeric_boundary_827ec941a3`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_827ec941a3`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_827ec941a3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 452. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?user=0_cff_marker_user_numeric_boundary_20cca409ba`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_20cca409ba`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_20cca409ba` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 453. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?user=1%22_cff_marker_user_sqli_probe_af9ffc38d7`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_af9ffc38d7`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_af9ffc38d7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 454. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?user=1%27_cff_marker_user_sqli_probe_1741f9496a`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_1741f9496a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_1741f9496a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 455. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?user=1_cff_marker_user_numeric_boundary_b5692a10b4`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_b5692a10b4`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_b5692a10b4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 456. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?user=999999_cff_marker_user_numeric_boundary_2b0a64dcb6`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_2b0a64dcb6`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_2b0a64dcb6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 457. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?userid=-1_cff_marker_userid_numeric_boundary_9ead0bd2c6`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_9ead0bd2c6`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_9ead0bd2c6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 458. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?userid=0_cff_marker_userid_numeric_boundary_26b37ed08c`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_26b37ed08c`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_26b37ed08c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 459. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?userid=1%22_cff_marker_userid_sqli_probe_bea5b53289`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_bea5b53289`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_bea5b53289` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 460. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?userid=1%27_cff_marker_userid_sqli_probe_a6d31cc860`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_a6d31cc860`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_a6d31cc860` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 461. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?userid=1_cff_marker_userid_numeric_boundary_8fe8162811`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_8fe8162811`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_8fe8162811` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 462. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?userid=999999_cff_marker_userid_numeric_boundary_07d5d1b6eb`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_07d5d1b6eb`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_07d5d1b6eb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 463. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?wsfunction=%27_cff_marker_wsfunction_sqli_probe_30f98d5796`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_30f98d5796`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_sqli_probe_30f98d5796` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 464. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_892d0f3fad%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_892d0f3fad&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_reflection_probe_892d0f3fad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 465. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?wsfunction=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_wsfunction_xss_trigger_probe_3288f0c511%27%29%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_3288f0c511&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_trigger_probe_3288f0c511` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 466. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?wsfunction=%3Cscript%3Ealert%28%27cff_marker_wsfunction_xss_trigger_probe_85797361b1%27%29%3C%2Fscript%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_85797361b1&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_trigger_probe_85797361b1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 467. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?wsfunction=cff_marker_wsfunction_text_canary_d75be29922`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_d75be29922`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_text_canary_d75be29922` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 468. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?wstoken=cff_marker_wstoken_token_canary_518d70d3a5`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_518d70d3a5`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_canary_518d70d3a5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 469. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?wstoken=cff_marker_wstoken_token_empty_589e1d34c7`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_589e1d34c7`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_empty_589e1d34c7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 470. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/roles?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_77964dddeb`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_77964dddeb`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_invalid_77964dddeb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 471. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?component=%27_cff_marker_component_sqli_probe_22281cd530`
- Parameter: `component` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_component_sqli_probe_22281cd530`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_sqli_probe_22281cd530` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 472. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?component=%3Ccff_marker_component_xss_reflection_probe_51a5d6e381%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_component_xss_reflection_probe_51a5d6e381&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_reflection_probe_51a5d6e381` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 473. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?component=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_component_xss_trigger_probe_62f96195bf%27%29%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_component_xss_trigger_probe_62f96195bf&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_trigger_probe_62f96195bf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 474. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?component=%3Cscript%3Ealert%28%27cff_marker_component_xss_trigger_probe_9ffa59d235%27%29%3C%2Fscript%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_component_xss_trigger_probe_9ffa59d235&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_trigger_probe_9ffa59d235` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 475. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?component=cff_marker_component_text_canary_8d3730d0ee`
- Parameter: `component` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_component_text_canary_8d3730d0ee`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_text_canary_8d3730d0ee` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 476. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?contextid=-1_cff_marker_contextid_numeric_boundary_fe362d799d`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_contextid_numeric_boundary_fe362d799d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_fe362d799d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 477. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?contextid=0_cff_marker_contextid_numeric_boundary_d6437db404`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_contextid_numeric_boundary_d6437db404`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_d6437db404` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 478. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?contextid=1%22_cff_marker_contextid_sqli_probe_5d5be9b299`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_contextid_sqli_probe_5d5be9b299`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_5d5be9b299` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 479. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?contextid=1%27_cff_marker_contextid_sqli_probe_cefd7cdbca`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_contextid_sqli_probe_cefd7cdbca`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_cefd7cdbca` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 480. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?contextid=1_cff_marker_contextid_numeric_boundary_04f39b0265`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_contextid_numeric_boundary_04f39b0265`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_04f39b0265` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 481. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?contextid=999999_cff_marker_contextid_numeric_boundary_2c9a18a6b1`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_contextid_numeric_boundary_2c9a18a6b1`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_2c9a18a6b1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 482. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?course=-1_cff_marker_course_numeric_boundary_6171ff9c12`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_6171ff9c12`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_6171ff9c12` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 483. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?course=0_cff_marker_course_numeric_boundary_4a1bc05c6b`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_4a1bc05c6b`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_4a1bc05c6b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 484. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?course=1%22_cff_marker_course_sqli_probe_5e954aea69`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_5e954aea69`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_5e954aea69` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 485. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?course=1%27_cff_marker_course_sqli_probe_289f834b45`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_289f834b45`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_289f834b45` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 486. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?course=1_cff_marker_course_numeric_boundary_f70f70d677`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_f70f70d677`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_f70f70d677` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 487. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?course=999999_cff_marker_course_numeric_boundary_fe31c24469`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_fe31c24469`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_fe31c24469` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 488. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?courseid=-1_cff_marker_courseid_numeric_boundary_23b0ffab78`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_23b0ffab78`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_23b0ffab78` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 489. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?courseid=0_cff_marker_courseid_numeric_boundary_18769ba1c0`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_18769ba1c0`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_18769ba1c0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 490. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?courseid=1%22_cff_marker_courseid_sqli_probe_40145317be`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_40145317be`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_40145317be` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 491. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?courseid=1%27_cff_marker_courseid_sqli_probe_a8812753d6`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_a8812753d6`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_a8812753d6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 492. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?courseid=1_cff_marker_courseid_numeric_boundary_9c0ea6934f`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_9c0ea6934f`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_9c0ea6934f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 493. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?courseid=999999_cff_marker_courseid_numeric_boundary_056640bb6d`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_056640bb6d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_056640bb6d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 494. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?filearea=cff_marker_filearea_path_canary_a2965b639c`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filearea_path_canary_a2965b639c`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filearea_path_canary_a2965b639c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 495. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?filename=cff_marker_filename_path_canary_94cd2003e2`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filename_path_canary_94cd2003e2`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filename_path_canary_94cd2003e2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 496. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?filepath=cff_marker_filepath_path_canary_9a22c0d719`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filepath_path_canary_9a22c0d719`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filepath_path_canary_9a22c0d719` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 497. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?id=-1_cff_marker_id_numeric_boundary_fab2dd6b7f`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_fab2dd6b7f`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_fab2dd6b7f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 498. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?id=0_cff_marker_id_numeric_boundary_73abf71030`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_73abf71030`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_73abf71030` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 499. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?id=1%22_cff_marker_id_sqli_probe_96a38c91e0`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_96a38c91e0`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_96a38c91e0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 500. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?id=1%27_cff_marker_id_sqli_probe_185982bb77`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_185982bb77`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_185982bb77` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 501. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?id=1_cff_marker_id_numeric_boundary_5a995a31c9`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_5a995a31c9`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_5a995a31c9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 502. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?id=999999_cff_marker_id_numeric_boundary_d0974a8e9e`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_d0974a8e9e`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_d0974a8e9e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 503. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?itemid=-1_cff_marker_itemid_numeric_boundary_16dc64889b`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_itemid_numeric_boundary_16dc64889b`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_16dc64889b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 504. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?itemid=0_cff_marker_itemid_numeric_boundary_08fd21fd32`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_itemid_numeric_boundary_08fd21fd32`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_08fd21fd32` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 505. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?itemid=1%22_cff_marker_itemid_sqli_probe_52cd8ca740`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_itemid_sqli_probe_52cd8ca740`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_52cd8ca740` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 506. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?itemid=1%27_cff_marker_itemid_sqli_probe_8f2892d5e8`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_itemid_sqli_probe_8f2892d5e8`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_8f2892d5e8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 507. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?itemid=1_cff_marker_itemid_numeric_boundary_99988d7680`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_itemid_numeric_boundary_99988d7680`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_99988d7680` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 508. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?itemid=999999_cff_marker_itemid_numeric_boundary_ec8a74c67d`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_itemid_numeric_boundary_ec8a74c67d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_ec8a74c67d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 509. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?moodlewsrestformat=%27_cff_marker_moodlewsrestformat_sqli_probe_4c260d7405`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_moodlewsrestformat_sqli_probe_4c260d7405`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_sqli_probe_4c260d7405` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 510. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?moodlewsrestformat=%3Ccff_marker_moodlewsrestformat_xss_reflection_probe_408643b9f2%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_moodlewsrestformat_xss_reflection_probe_408643b9f2&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_reflection_probe_408643b9f2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 511. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?moodlewsrestformat=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_4005585e7c%27%29%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_4005585e7c&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_4005585e7c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 512. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?moodlewsrestformat=%3Cscript%3Ealert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_480ccfcf68%27%29%3C%2Fscript%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_480ccfcf68&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_480ccfcf68` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 513. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?moodlewsrestformat=cff_marker_moodlewsrestformat_text_canary_b086f12d61`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_moodlewsrestformat_text_canary_b086f12d61`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_text_canary_b086f12d61` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 514. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?page=-1_cff_marker_page_numeric_boundary_f78e148794`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_f78e148794`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_f78e148794` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 515. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?page=0_cff_marker_page_numeric_boundary_c6b96765ef`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_c6b96765ef`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_c6b96765ef` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 516. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?page=1%22_cff_marker_page_sqli_probe_e34744c4eb`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_e34744c4eb`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_e34744c4eb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 517. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?page=1%27_cff_marker_page_sqli_probe_2893d5916d`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_2893d5916d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_2893d5916d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 518. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?page=1_cff_marker_page_numeric_boundary_febc15db79`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_febc15db79`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_febc15db79` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 519. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?page=999999_cff_marker_page_numeric_boundary_1678911c21`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_1678911c21`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_1678911c21` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 520. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?q=%27_cff_marker_q_sqli_probe_ec2c37c1b1`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_ec2c37c1b1`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_sqli_probe_ec2c37c1b1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 521. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?q=%3Ccff_marker_q_xss_reflection_probe_10c7ab62e8%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_10c7ab62e8&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_reflection_probe_10c7ab62e8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 522. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_q_xss_trigger_probe_f7436d8902%27%29%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_q_xss_trigger_probe_f7436d8902&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_trigger_probe_f7436d8902` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 523. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?q=%3Cscript%3Ealert%28%27cff_marker_q_xss_trigger_probe_fe60c5ffc1%27%29%3C%2Fscript%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_q_xss_trigger_probe_fe60c5ffc1&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_trigger_probe_fe60c5ffc1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 524. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?q=cff_marker_q_text_canary_4d547c2293`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_4d547c2293`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_text_canary_4d547c2293` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 525. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?search=%27_cff_marker_search_sqli_probe_f27b2dfadf`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_f27b2dfadf`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_f27b2dfadf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 526. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?search=%3Ccff_marker_search_xss_reflection_probe_851d6a4f83%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_851d6a4f83&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_851d6a4f83` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 527. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_7bbf36240e%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_7bbf36240e&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_7bbf36240e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 528. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_35a2594c09%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_35a2594c09&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_35a2594c09` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 529. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?search=cff_marker_search_text_canary_b3f2b493bb`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_b3f2b493bb`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_text_canary_b3f2b493bb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 530. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?section=-1_cff_marker_section_numeric_boundary_40c0e3641f`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_40c0e3641f`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_40c0e3641f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 531. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?section=0_cff_marker_section_numeric_boundary_89ec812e8a`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_89ec812e8a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_89ec812e8a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 532. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?section=1%22_cff_marker_section_sqli_probe_1c53bc5d16`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_1c53bc5d16`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_1c53bc5d16` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 533. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?section=1%27_cff_marker_section_sqli_probe_a8a0b527db`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_a8a0b527db`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_a8a0b527db` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 534. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?section=1_cff_marker_section_numeric_boundary_b36a671bed`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_b36a671bed`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_b36a671bed` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 535. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?section=999999_cff_marker_section_numeric_boundary_090c3cd9ce`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_090c3cd9ce`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_090c3cd9ce` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 536. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?sesskey=cff_marker_sesskey_token_canary_8ab53215c5`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_8ab53215c5`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_canary_8ab53215c5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 537. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?sesskey=cff_marker_sesskey_token_empty_d14194d1e9`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_d14194d1e9`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_empty_d14194d1e9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 538. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_8e2c1b5834`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_8e2c1b5834`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_invalid_8e2c1b5834` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 539. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?user=-1_cff_marker_user_numeric_boundary_27bfaf4e52`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_27bfaf4e52`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_27bfaf4e52` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 540. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?user=0_cff_marker_user_numeric_boundary_5c5a6e7afa`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_5c5a6e7afa`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_5c5a6e7afa` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 541. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?user=1%22_cff_marker_user_sqli_probe_fd7040b5f9`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_fd7040b5f9`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_fd7040b5f9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 542. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?user=1%27_cff_marker_user_sqli_probe_1da81618d2`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_1da81618d2`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_1da81618d2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 543. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?user=1_cff_marker_user_numeric_boundary_f8475a3f95`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_f8475a3f95`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_f8475a3f95` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 544. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?user=999999_cff_marker_user_numeric_boundary_2f56dc7a4d`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_2f56dc7a4d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_2f56dc7a4d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 545. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?userid=-1_cff_marker_userid_numeric_boundary_276d6322be`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_276d6322be`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_276d6322be` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 546. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?userid=0_cff_marker_userid_numeric_boundary_ed6f5b30d7`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_ed6f5b30d7`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_ed6f5b30d7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 547. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?userid=1%22_cff_marker_userid_sqli_probe_10e81bb1a2`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_10e81bb1a2`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_10e81bb1a2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 548. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?userid=1%27_cff_marker_userid_sqli_probe_3b43f77fbe`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_3b43f77fbe`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_3b43f77fbe` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 549. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?userid=1_cff_marker_userid_numeric_boundary_1b5c878fe2`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_1b5c878fe2`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_1b5c878fe2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 550. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?userid=999999_cff_marker_userid_numeric_boundary_e31d57a0ad`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_e31d57a0ad`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_e31d57a0ad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 551. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?wsfunction=%27_cff_marker_wsfunction_sqli_probe_839248cc27`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_839248cc27`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_sqli_probe_839248cc27` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 552. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_9b192f286d%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_9b192f286d&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_reflection_probe_9b192f286d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 553. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?wsfunction=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_wsfunction_xss_trigger_probe_bfd9c2224d%27%29%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_bfd9c2224d&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_trigger_probe_bfd9c2224d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 554. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?wsfunction=%3Cscript%3Ealert%28%27cff_marker_wsfunction_xss_trigger_probe_f85f636238%27%29%3C%2Fscript%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_f85f636238&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_trigger_probe_f85f636238` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 555. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?wsfunction=cff_marker_wsfunction_text_canary_8ca8ee0b9a`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_8ca8ee0b9a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_text_canary_8ca8ee0b9a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 556. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?wstoken=cff_marker_wstoken_token_canary_87b606cd28`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_87b606cd28`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_canary_87b606cd28` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 557. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?wstoken=cff_marker_wstoken_token_empty_45246088a6`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_45246088a6`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_empty_45246088a6` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 558. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin/tool?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_159de65879`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_159de65879`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_invalid_159de65879` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 559. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?component=%27_cff_marker_component_sqli_probe_880a4981f9`
- Parameter: `component` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_component_sqli_probe_880a4981f9`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_sqli_probe_880a4981f9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 560. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?component=%3Ccff_marker_component_xss_reflection_probe_e20cd014fa%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_component_xss_reflection_probe_e20cd014fa&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_reflection_probe_e20cd014fa` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 561. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?component=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_component_xss_trigger_probe_a2190775de%27%29%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_component_xss_trigger_probe_a2190775de&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_trigger_probe_a2190775de` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 562. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?component=%3Cscript%3Ealert%28%27cff_marker_component_xss_trigger_probe_b2fce17d2e%27%29%3C%2Fscript%3E`
- Parameter: `component` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_component_xss_trigger_probe_b2fce17d2e&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_xss_trigger_probe_b2fce17d2e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 563. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?component=cff_marker_component_text_canary_d42b5fa551`
- Parameter: `component` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_component_text_canary_d42b5fa551`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_component_text_canary_d42b5fa551` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 564. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?contextid=-1_cff_marker_contextid_numeric_boundary_af35fe26e9`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_contextid_numeric_boundary_af35fe26e9`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_af35fe26e9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 565. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?contextid=0_cff_marker_contextid_numeric_boundary_590a6a0e59`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_contextid_numeric_boundary_590a6a0e59`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_590a6a0e59` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 566. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?contextid=1%22_cff_marker_contextid_sqli_probe_b65f6314f1`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_contextid_sqli_probe_b65f6314f1`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_b65f6314f1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 567. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?contextid=1%27_cff_marker_contextid_sqli_probe_16e44f6c52`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_contextid_sqli_probe_16e44f6c52`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_16e44f6c52` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 568. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?contextid=1_cff_marker_contextid_numeric_boundary_c9852ba745`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_contextid_numeric_boundary_c9852ba745`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_c9852ba745` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 569. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?contextid=999999_cff_marker_contextid_numeric_boundary_3394baa0e5`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_contextid_numeric_boundary_3394baa0e5`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_contextid_numeric_boundary_3394baa0e5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 570. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?course=-1_cff_marker_course_numeric_boundary_78a00cc82d`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_course_numeric_boundary_78a00cc82d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_78a00cc82d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 571. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?course=0_cff_marker_course_numeric_boundary_59ad1fae12`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_course_numeric_boundary_59ad1fae12`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_59ad1fae12` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 572. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?course=1%22_cff_marker_course_sqli_probe_04eae5b296`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_04eae5b296`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_04eae5b296` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 573. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?course=1%27_cff_marker_course_sqli_probe_b45048ffcc`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_b45048ffcc`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_b45048ffcc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 574. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?course=1_cff_marker_course_numeric_boundary_0cb52a3c3d`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_course_numeric_boundary_0cb52a3c3d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_0cb52a3c3d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 575. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?course=999999_cff_marker_course_numeric_boundary_ebe12c467c`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_course_numeric_boundary_ebe12c467c`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_course_numeric_boundary_ebe12c467c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 576. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?courseid=-1_cff_marker_courseid_numeric_boundary_e3853db033`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_courseid_numeric_boundary_e3853db033`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_e3853db033` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 577. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?courseid=0_cff_marker_courseid_numeric_boundary_01ab534d8e`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_courseid_numeric_boundary_01ab534d8e`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_01ab534d8e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 578. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?courseid=1%22_cff_marker_courseid_sqli_probe_63266371a3`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_63266371a3`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_63266371a3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 579. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?courseid=1%27_cff_marker_courseid_sqli_probe_f9eb15f017`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_f9eb15f017`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_f9eb15f017` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 580. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?courseid=1_cff_marker_courseid_numeric_boundary_b6d054621b`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_courseid_numeric_boundary_b6d054621b`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_b6d054621b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 581. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?courseid=999999_cff_marker_courseid_numeric_boundary_45ca005df9`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_courseid_numeric_boundary_45ca005df9`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_courseid_numeric_boundary_45ca005df9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 582. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?filearea=cff_marker_filearea_path_canary_c1043ae36b`
- Parameter: `filearea` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filearea_path_canary_c1043ae36b`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filearea_path_canary_c1043ae36b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 583. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?filename=cff_marker_filename_path_canary_05668a4718`
- Parameter: `filename` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filename_path_canary_05668a4718`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filename_path_canary_05668a4718` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 584. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?filepath=cff_marker_filepath_path_canary_0577b46e48`
- Parameter: `filepath` | Param type: `path`
- Payload type: `path_canary` | Payload: `cff_marker_filepath_path_canary_0577b46e48`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_filepath_path_canary_0577b46e48` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 585. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?id=-1_cff_marker_id_numeric_boundary_edbe213dc2`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_id_numeric_boundary_edbe213dc2`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_edbe213dc2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 586. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?id=0_cff_marker_id_numeric_boundary_5b7342a48d`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_id_numeric_boundary_5b7342a48d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_5b7342a48d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 587. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?id=1%22_cff_marker_id_sqli_probe_2f843406ee`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_2f843406ee`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_2f843406ee` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 588. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?id=1%27_cff_marker_id_sqli_probe_f403790b5a`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_f403790b5a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_f403790b5a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 589. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?id=1_cff_marker_id_numeric_boundary_48e4d8196b`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_id_numeric_boundary_48e4d8196b`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_48e4d8196b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 590. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?id=999999_cff_marker_id_numeric_boundary_8fa6b98037`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_id_numeric_boundary_8fa6b98037`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_id_numeric_boundary_8fa6b98037` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 591. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?itemid=-1_cff_marker_itemid_numeric_boundary_565156c9e7`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_itemid_numeric_boundary_565156c9e7`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_565156c9e7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 592. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?itemid=0_cff_marker_itemid_numeric_boundary_57f34f3158`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_itemid_numeric_boundary_57f34f3158`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_57f34f3158` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 593. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?itemid=1%22_cff_marker_itemid_sqli_probe_b51e3d1fe3`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_itemid_sqli_probe_b51e3d1fe3`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_b51e3d1fe3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 594. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?itemid=1%27_cff_marker_itemid_sqli_probe_f0cdf45e93`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_itemid_sqli_probe_f0cdf45e93`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_f0cdf45e93` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 595. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?itemid=1_cff_marker_itemid_numeric_boundary_2f22c8a22a`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_itemid_numeric_boundary_2f22c8a22a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_2f22c8a22a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 596. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?itemid=999999_cff_marker_itemid_numeric_boundary_1c560b2213`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_itemid_numeric_boundary_1c560b2213`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_itemid_numeric_boundary_1c560b2213` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 597. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?moodlewsrestformat=%27_cff_marker_moodlewsrestformat_sqli_probe_9e83e32eb8`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_moodlewsrestformat_sqli_probe_9e83e32eb8`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_sqli_probe_9e83e32eb8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 598. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?moodlewsrestformat=%3Ccff_marker_moodlewsrestformat_xss_reflection_probe_9a5cde3169%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_moodlewsrestformat_xss_reflection_probe_9a5cde3169&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_reflection_probe_9a5cde3169` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 599. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?moodlewsrestformat=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_89e512d328%27%29%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_89e512d328&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_89e512d328` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 600. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?moodlewsrestformat=%3Cscript%3Ealert%28%27cff_marker_moodlewsrestformat_xss_trigger_probe_c32a9d2fb2%27%29%3C%2Fscript%3E`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_moodlewsrestformat_xss_trigger_probe_c32a9d2fb2&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_xss_trigger_probe_c32a9d2fb2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 601. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?moodlewsrestformat=cff_marker_moodlewsrestformat_text_canary_52c7b05596`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_moodlewsrestformat_text_canary_52c7b05596`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_text_canary_52c7b05596` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 602. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?page=-1_cff_marker_page_numeric_boundary_2c76fe803a`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_page_numeric_boundary_2c76fe803a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_2c76fe803a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 603. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?page=0_cff_marker_page_numeric_boundary_72f41ead91`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_page_numeric_boundary_72f41ead91`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_72f41ead91` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 604. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?page=1%22_cff_marker_page_sqli_probe_6a0717b150`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_6a0717b150`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_6a0717b150` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 605. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?page=1%27_cff_marker_page_sqli_probe_c3ad3b0da8`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_c3ad3b0da8`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_c3ad3b0da8` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 606. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?page=1_cff_marker_page_numeric_boundary_b253a9c81a`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_page_numeric_boundary_b253a9c81a`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_b253a9c81a` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 607. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?page=999999_cff_marker_page_numeric_boundary_777ee40329`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_page_numeric_boundary_777ee40329`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_page_numeric_boundary_777ee40329` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 608. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?q=%27_cff_marker_q_sqli_probe_aed96c3b25`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_aed96c3b25`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_sqli_probe_aed96c3b25` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 609. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?q=%3Ccff_marker_q_xss_reflection_probe_4f91560fb2%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_q_xss_reflection_probe_4f91560fb2&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_reflection_probe_4f91560fb2` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 610. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_q_xss_trigger_probe_dbebb922eb%27%29%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_q_xss_trigger_probe_dbebb922eb&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_trigger_probe_dbebb922eb` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 611. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?q=%3Cscript%3Ealert%28%27cff_marker_q_xss_trigger_probe_99e76d5ae3%27%29%3C%2Fscript%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_q_xss_trigger_probe_99e76d5ae3&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_xss_trigger_probe_99e76d5ae3` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 612. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?q=cff_marker_q_text_canary_b912ba7673`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_q_text_canary_b912ba7673`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_q_text_canary_b912ba7673` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 613. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?search=%27_cff_marker_search_sqli_probe_9396b77681`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_9396b77681`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_9396b77681` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 614. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?search=%3Ccff_marker_search_xss_reflection_probe_2fe6374852%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_search_xss_reflection_probe_2fe6374852&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_reflection_probe_2fe6374852` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 615. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?search=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_search_xss_trigger_probe_1c4cc37a60%27%29%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_search_xss_trigger_probe_1c4cc37a60&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_1c4cc37a60` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 616. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?search=%3Cscript%3Ealert%28%27cff_marker_search_xss_trigger_probe_6167a4eba0%27%29%3C%2Fscript%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_search_xss_trigger_probe_6167a4eba0&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_xss_trigger_probe_6167a4eba0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 617. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?search=cff_marker_search_text_canary_b0b9e738f9`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_search_text_canary_b0b9e738f9`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_search_text_canary_b0b9e738f9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 618. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?section=-1_cff_marker_section_numeric_boundary_0e5d929f58`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_section_numeric_boundary_0e5d929f58`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_0e5d929f58` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 619. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?section=0_cff_marker_section_numeric_boundary_4a45bea001`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_section_numeric_boundary_4a45bea001`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_4a45bea001` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 620. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?section=1%22_cff_marker_section_sqli_probe_2918b81770`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_2918b81770`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_2918b81770` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 621. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?section=1%27_cff_marker_section_sqli_probe_0f82da5f18`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_0f82da5f18`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_0f82da5f18` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 622. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?section=1_cff_marker_section_numeric_boundary_101f12c491`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_section_numeric_boundary_101f12c491`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_101f12c491` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 623. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?section=999999_cff_marker_section_numeric_boundary_2b90d415e5`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_section_numeric_boundary_2b90d415e5`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_section_numeric_boundary_2b90d415e5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 624. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?sesskey=cff_marker_sesskey_token_canary_a6f61b1255`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_sesskey_token_canary_a6f61b1255`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_canary_a6f61b1255` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 625. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?sesskey=cff_marker_sesskey_token_empty_1bcef83d25`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_sesskey_token_empty_1bcef83d25`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_empty_1bcef83d25` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 626. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?sesskey=invalid_token_value_cff_marker_sesskey_token_invalid_f2e2d3d453`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_sesskey_token_invalid_f2e2d3d453`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_sesskey_token_invalid_f2e2d3d453` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 627. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?user=-1_cff_marker_user_numeric_boundary_d07bfea18d`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_user_numeric_boundary_d07bfea18d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_d07bfea18d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 628. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?user=0_cff_marker_user_numeric_boundary_792c8a2b23`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_user_numeric_boundary_792c8a2b23`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_792c8a2b23` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 629. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?user=1%22_cff_marker_user_sqli_probe_efeeebc518`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_efeeebc518`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_efeeebc518` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 630. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?user=1%27_cff_marker_user_sqli_probe_ccd31a515e`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_ccd31a515e`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_ccd31a515e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 631. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?user=1_cff_marker_user_numeric_boundary_06a50d33b7`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_user_numeric_boundary_06a50d33b7`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_06a50d33b7` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 632. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?user=999999_cff_marker_user_numeric_boundary_aaa99a707d`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_user_numeric_boundary_aaa99a707d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_user_numeric_boundary_aaa99a707d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 633. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?userid=-1_cff_marker_userid_numeric_boundary_506f7cb1ce`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1_cff_marker_userid_numeric_boundary_506f7cb1ce`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_506f7cb1ce` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 634. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?userid=0_cff_marker_userid_numeric_boundary_d90669e6ab`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0_cff_marker_userid_numeric_boundary_d90669e6ab`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_d90669e6ab` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 635. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?userid=1%22_cff_marker_userid_sqli_probe_fffbe0e603`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_fffbe0e603`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_fffbe0e603` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 636. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?userid=1%27_cff_marker_userid_sqli_probe_8435c44ecf`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_8435c44ecf`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_8435c44ecf` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 637. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?userid=1_cff_marker_userid_numeric_boundary_b43e9b0f60`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1_cff_marker_userid_numeric_boundary_b43e9b0f60`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_b43e9b0f60` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 638. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?userid=999999_cff_marker_userid_numeric_boundary_2b55aa6c83`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999_cff_marker_userid_numeric_boundary_2b55aa6c83`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_userid_numeric_boundary_2b55aa6c83` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 639. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?wsfunction=%27_cff_marker_wsfunction_sqli_probe_66354805a1`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_66354805a1`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_sqli_probe_66354805a1` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 640. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?wsfunction=%3Ccff_marker_wsfunction_xss_reflection_probe_8de914b503%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_marker_wsfunction_xss_reflection_probe_8de914b503&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_reflection_probe_8de914b503` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 641. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?wsfunction=%3Cimg+src%3Dx+onerror%3Dalert%28%27cff_marker_wsfunction_xss_trigger_probe_ebb57b6f79%27%29%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;img src=x onerror=alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_ebb57b6f79&#x27;)&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_trigger_probe_ebb57b6f79` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 642. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?wsfunction=%3Cscript%3Ealert%28%27cff_marker_wsfunction_xss_trigger_probe_00e5a43d2f%27%29%3C%2Fscript%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_trigger_probe` | Payload: `&lt;script&gt;alert(&#x27;cff_marker_wsfunction_xss_trigger_probe_00e5a43d2f&#x27;)&lt;/script&gt;`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_xss_trigger_probe_00e5a43d2f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 643. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?wsfunction=cff_marker_wsfunction_text_canary_6d72d8ea01`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_marker_wsfunction_text_canary_6d72d8ea01`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wsfunction_text_canary_6d72d8ea01` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 644. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?wstoken=cff_marker_wstoken_token_canary_bce1bd8b2d`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_marker_wstoken_token_canary_bce1bd8b2d`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_canary_bce1bd8b2d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 645. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?wstoken=cff_marker_wstoken_token_empty_5cbed3c6d5`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: `cff_marker_wstoken_token_empty_5cbed3c6d5`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_empty_5cbed3c6d5` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 646. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `60`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/admin?wstoken=invalid_token_value_cff_marker_wstoken_token_invalid_210cdf653e`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value_cff_marker_wstoken_token_invalid_210cdf653e`
- Response: HTTP `301` / Length `682` / Type `text/html`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Marker: `cff_marker_wstoken_token_invalid_210cdf653e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `682`
  - Content-Type: `text/html`
  - Reason: status=301; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 647. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?component=%27_cff_marker_component_sqli_probe_8cc73ec852`
- Parameter: `component` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_component_sqli_probe_8cc73ec852`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_component_sqli_probe_8cc73ec852` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 648. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?contextid=1%22_cff_marker_contextid_sqli_probe_865d0df76f`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_contextid_sqli_probe_865d0df76f`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_865d0df76f` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 649. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?contextid=1%27_cff_marker_contextid_sqli_probe_d2da516a7b`
- Parameter: `contextid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_contextid_sqli_probe_d2da516a7b`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_contextid_sqli_probe_d2da516a7b` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 650. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?course=1%22_cff_marker_course_sqli_probe_0e87c0d544`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_course_sqli_probe_0e87c0d544`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_0e87c0d544` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 651. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?course=1%27_cff_marker_course_sqli_probe_762a0c3a11`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_course_sqli_probe_762a0c3a11`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_course_sqli_probe_762a0c3a11` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 652. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?courseid=1%22_cff_marker_courseid_sqli_probe_b7051e74ba`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_courseid_sqli_probe_b7051e74ba`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_b7051e74ba` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 653. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?courseid=1%27_cff_marker_courseid_sqli_probe_e09fe7c1d9`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_courseid_sqli_probe_e09fe7c1d9`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_courseid_sqli_probe_e09fe7c1d9` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 654. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?id=1%22_cff_marker_id_sqli_probe_de396874ad`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_id_sqli_probe_de396874ad`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_de396874ad` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 655. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?id=1%27_cff_marker_id_sqli_probe_8fff23f981`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_id_sqli_probe_8fff23f981`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_id_sqli_probe_8fff23f981` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 656. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?itemid=1%22_cff_marker_itemid_sqli_probe_852bc1fc85`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_itemid_sqli_probe_852bc1fc85`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_852bc1fc85` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 657. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?itemid=1%27_cff_marker_itemid_sqli_probe_0381ea65cc`
- Parameter: `itemid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_itemid_sqli_probe_0381ea65cc`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_itemid_sqli_probe_0381ea65cc` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 658. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?moodlewsrestformat=%27_cff_marker_moodlewsrestformat_sqli_probe_68f1889ba0`
- Parameter: `moodlewsrestformat` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_moodlewsrestformat_sqli_probe_68f1889ba0`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_moodlewsrestformat_sqli_probe_68f1889ba0` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 659. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?page=1%22_cff_marker_page_sqli_probe_62443d287c`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_page_sqli_probe_62443d287c`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_62443d287c` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 660. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?page=1%27_cff_marker_page_sqli_probe_e1f8ec52c4`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_page_sqli_probe_e1f8ec52c4`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_page_sqli_probe_e1f8ec52c4` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 661. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?q=%27_cff_marker_q_sqli_probe_188d02ee37`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_q_sqli_probe_188d02ee37`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_q_sqli_probe_188d02ee37` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 662. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?search=%27_cff_marker_search_sqli_probe_9497e25556`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_search_sqli_probe_9497e25556`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_search_sqli_probe_9497e25556` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 663. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?section=1%22_cff_marker_section_sqli_probe_abb3fc1285`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_section_sqli_probe_abb3fc1285`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_abb3fc1285` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 664. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?section=1%27_cff_marker_section_sqli_probe_cd4fa7137d`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_section_sqli_probe_cd4fa7137d`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_section_sqli_probe_cd4fa7137d` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 665. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?user=1%22_cff_marker_user_sqli_probe_b8b2e41036`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_user_sqli_probe_b8b2e41036`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_b8b2e41036` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 666. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?user=1%27_cff_marker_user_sqli_probe_5e921fe83e`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_user_sqli_probe_5e921fe83e`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_user_sqli_probe_5e921fe83e` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 667. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?userid=1%22_cff_marker_userid_sqli_probe_83985a7402`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;_cff_marker_userid_sqli_probe_83985a7402`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_83985a7402` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 668. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?userid=1%27_cff_marker_userid_sqli_probe_5f81376f90`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;_cff_marker_userid_sqli_probe_5f81376f90`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_userid_sqli_probe_5f81376f90` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 669. Parameter behavior anomaly
- Kind: `parameter`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Chưa có marker xác nhận; finding dựa trên feedback/anomaly của response.
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `https://learn.ctseducation.org/?wsfunction=%27_cff_marker_wsfunction_sqli_probe_624c7eef54`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;_cff_marker_wsfunction_sqli_probe_624c7eef54`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Marker: `cff_marker_wsfunction_sqli_probe_624c7eef54` | Reflected: `False` | Hits: `0`
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 670. Interesting path / response anomaly
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

### 671. Interesting path / response anomaly
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

### 672. Interesting path / response anomaly
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

### 673. Interesting path / response anomaly
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

### 674. Interesting path / response anomaly
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

### 675. Interesting path / response anomaly
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

### 676. Interesting path / response anomaly
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

### 677. Interesting path / response anomaly
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

### 678. Interesting path / response anomaly
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

### 679. Interesting path / response anomaly
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

### 680. Interesting path / response anomaly
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

### 681. Interesting path / response anomaly
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

### 682. Interesting path / response anomaly
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

### 683. Interesting path / response anomaly
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

### 684. Interesting path / response anomaly
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

### 685. Interesting path / response anomaly
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

### 686. Interesting path / response anomaly
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

### 687. Interesting path / response anomaly
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

### 688. Interesting path / response anomaly
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

### 689. Interesting path / response anomaly
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

### 690. Interesting path / response anomaly
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

### 691. Interesting path / response anomaly
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

### 692. Interesting path / response anomaly
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

### 693. Interesting path / response anomaly
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

### 694. Interesting path / response anomaly
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

### 695. Interesting path / response anomaly
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

### 696. Interesting path / response anomaly
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

### 697. Interesting path / response anomaly
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

### 698. Interesting path / response anomaly
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

### 699. Interesting path / response anomaly
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

### 700. Interesting path / response anomaly
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

### 701. Interesting path / response anomaly
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

### 702. Interesting path / response anomaly
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

### 703. Interesting path / response anomaly
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

### 704. Interesting path / response anomaly
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

### 705. Interesting path / response anomaly
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

### 706. Interesting path / response anomaly
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

### 707. Interesting path / response anomaly
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

### 708. Interesting path / response anomaly
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

### 709. Interesting path / response anomaly
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

### 710. Interesting path / response anomaly
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

### 711. Interesting path / response anomaly
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

### 712. Interesting path / response anomaly
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

### 713. Interesting path / response anomaly
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

### 714. Interesting path / response anomaly
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

### 715. Interesting path / response anomaly
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

### 716. Interesting path / response anomaly
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

### 717. Interesting path / response anomaly
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

### 718. Interesting path / response anomaly
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

### 719. Interesting path / response anomaly
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

### 720. Interesting path / response anomaly
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

### 721. Interesting path / response anomaly
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

### 722. Interesting path / response anomaly
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

### 723. Interesting path / response anomaly
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

### 724. Interesting path / response anomaly
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

### 725. Interesting path / response anomaly
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

### 726. Interesting path / response anomaly
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

### 727. Interesting path / response anomaly
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

### 728. Interesting path / response anomaly
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

### 729. Interesting path / response anomaly
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

### 730. Interesting path / response anomaly
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

### 731. Interesting path / response anomaly
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

### 732. Interesting path / response anomaly
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

### 733. Interesting path / response anomaly
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

### 734. Interesting path / response anomaly
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

### 735. Interesting path / response anomaly
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

### 736. Interesting path / response anomaly
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

### 737. Interesting path / response anomaly
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

### 738. Interesting path / response anomaly
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

### 739. Interesting path / response anomaly
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

### 740. Interesting path / response anomaly
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

### 741. Interesting path / response anomaly
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

### 742. Interesting path / response anomaly
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

### 743. Interesting path / response anomaly
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

### 744. Interesting path / response anomaly
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

### 745. Interesting path / response anomaly
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

### 746. Interesting path / response anomaly
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

### 747. Interesting path / response anomaly
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

### 748. Interesting path / response anomaly
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

### 749. Interesting path / response anomaly
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

### 750. Interesting path / response anomaly
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

### 751. Interesting path / response anomaly
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

### 752. Interesting path / response anomaly
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

### 753. Interesting path / response anomaly
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

### 754. Interesting path / response anomaly
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

### 755. Interesting path / response anomaly
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

### 756. Interesting path / response anomaly
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

### 757. Interesting path / response anomaly
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

### 758. Interesting path / response anomaly
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

### 759. Interesting path / response anomaly
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

### 760. Interesting path / response anomaly
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

### 761. Interesting path / response anomaly
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

### 762. Interesting path / response anomaly
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

### 763. Interesting path / response anomaly
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

### 764. Interesting path / response anomaly
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

### 765. Interesting path / response anomaly
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

### 766. Interesting path / response anomaly
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

### 767. Interesting path / response anomaly
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

### 768. Interesting path / response anomaly
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

### 769. Interesting path / response anomaly
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

### 770. Interesting path / response anomaly
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

### 771. Interesting path / response anomaly
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

### 772. Interesting path / response anomaly
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

### 773. Interesting path / response anomaly
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

### 774. Interesting path / response anomaly
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

### 775. Interesting path / response anomaly
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

### 776. Interesting path / response anomaly
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

### 777. Interesting path / response anomaly
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

### 778. Interesting path / response anomaly
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

### 779. Interesting path / response anomaly
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

### 780. Interesting path / response anomaly
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

### 781. Interesting path / response anomaly
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

### 782. Interesting path / response anomaly
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

### 783. Interesting path / response anomaly
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

### 784. Interesting path / response anomaly
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

### 785. Interesting path / response anomaly
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

### 786. Interesting path / response anomaly
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

### 787. Interesting path / response anomaly
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

### 788. Interesting path / response anomaly
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

### 789. Interesting path / response anomaly
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

### 790. Interesting path / response anomaly
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

### 791. Interesting path / response anomaly
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

### 792. Interesting path / response anomaly
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

### 793. Interesting path / response anomaly
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

### 794. Interesting path / response anomaly
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

### 795. Interesting path / response anomaly
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

### 796. Interesting path / response anomaly
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

### 797. Interesting path / response anomaly
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

### 798. Interesting path / response anomaly
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

### 799. Interesting path / response anomaly
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

### 800. Interesting path / response anomaly
- Kind: `path`
- Confirmation: `possible` | Level: `possible` | Confidence: `50`
- Confirmation reason: Finding dựa trên response anomaly, chưa có marker xác nhận.
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `https://learn.ctseducation.org/index.php`
- Response: HTTP `200` / Length `44156` / Type `text/html; charset=utf-8`
- Title: Home | CTS EDUCATION - MOODLE
- Evidence: status=200; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `44156`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta

