# Context Feedback Fuzzer Report

- Target: `http://elearn.ahuc.edu.eg/moodle/`
- Detected Platform: **moodle**
- Platform type: `LMS`
- Requests sent: `400`
- Safety: GET-only, same-host scope, rate-limited, authorization flag required.
- Server technology hint: `php` / `apache`

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

## Fingerprint scores

- wordpress: 0
- joomla: 2
- drupal: 0
- liferay: 0
- sharepoint: 0
- moodle: 61

## Findings

Các finding dưới đây là giả thuyết nguy cơ bug dựa trên phản hồi server, không phải xác nhận khai thác thành công hay chấm severity.

### 1. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?course=-1`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 2. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?course=0`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 3. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?course=1`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 4. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?course=999999`
- Parameter: `course` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 5. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?courseid=-1`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 6. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?courseid=0`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 7. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?courseid=1`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 8. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?courseid=999999`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 9. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?id=-1`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 10. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?id=0`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 11. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?id=1`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 12. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?id=999999`
- Parameter: `id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 13. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?page=-1`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 14. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?page=0`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 15. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?page=1`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 16. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?page=999999`
- Parameter: `page` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 17. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?q=%22cff_canary_9x7`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 18. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?q=%27cff_canary_9x7`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 19. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?q=%3Ccff_canary_9x7%3E`
- Parameter: `q` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_canary_9x7&gt;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 20. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?q=cff_canary_9x7`
- Parameter: `q` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 21. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?redirect=%2F%2Fexample.com%2Fcff_canary_9x7`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 22. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?redirect=https%3A%2F%2Fexample.com%2Fcff_canary_9x7`
- Parameter: `redirect` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 23. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?returnurl=%2F%2Fexample.com%2Fcff_canary_9x7`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 24. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?returnurl=https%3A%2F%2Fexample.com%2Fcff_canary_9x7`
- Parameter: `returnurl` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 25. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?search=%22cff_canary_9x7`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 26. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?search=%27cff_canary_9x7`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 27. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?search=%3Ccff_canary_9x7%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_canary_9x7&gt;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 28. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?search=cff_canary_9x7`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 29. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?section=-1`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 30. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?section=0`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 31. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?section=1`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 32. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?section=999999`
- Parameter: `section` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 33. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?sesskey=`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_empty` | Payload: ``
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 34. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?sesskey=cff_canary_9x7`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 35. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?sesskey=invalid_token_value`
- Parameter: `sesskey` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 36. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?user=-1`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 37. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?user=0`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 38. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?user=1`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 39. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?user=999999`
- Parameter: `user` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 40. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?userid=-1`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 41. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?userid=0`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 42. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?userid=1`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 43. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?userid=999999`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 44. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?wsfunction=%22cff_canary_9x7`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 45. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?wsfunction=%27cff_canary_9x7`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 46. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?wsfunction=%3Ccff_canary_9x7%3E`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_canary_9x7&gt;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 47. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?wsfunction=cff_canary_9x7`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 48. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?wstoken=`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_empty` | Payload: ``
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 49. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?wstoken=cff_canary_9x7`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_canary` | Payload: `cff_canary_9x7`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 50. Verbose Error Disclosure / input handling error
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Verbose Error Disclosure / input handling error
- URL: `http://elearn.ahuc.edu.eg/moodle/?wstoken=invalid_token_value`
- Parameter: `wstoken` | Param type: `token`
- Payload type: `token_invalid` | Payload: `invalid_token_value`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: debug/error keyword appeared in response
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; debug/error keyword appeared in response

### 51. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/ajax.php`
- Response: HTTP `200` / Length `142` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `142`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path; API-like endpoint

### 52. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?course=1%22`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 53. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?course=1%27`
- Parameter: `course` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 54. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?courseid=1%22`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 55. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?courseid=1%27`
- Parameter: `courseid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 56. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?id=1%22`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 57. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?id=1%27`
- Parameter: `id` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 58. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?page=1%22`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 59. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?page=1%27`
- Parameter: `page` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 60. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?q=%27`
- Parameter: `q` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 61. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?search=%27`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 62. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?section=1%22`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 63. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?section=1%27`
- Parameter: `section` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 64. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?user=1%22`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 65. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?user=1%27`
- Parameter: `user` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 66. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?userid=1%22`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 67. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?userid=1%27`
- Parameter: `userid` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 68. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://elearn.ahuc.edu.eg/moodle/?wsfunction=%27`
- Parameter: `wsfunction` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 69. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/environment.xml`
- Response: HTTP `200` / Length `139832` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `139832`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 70. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/mnet/trustedhosts.html`
- Response: HTTP `200` / Length `2317` / Type `text/html`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2317`
  - Content-Type: `text/html`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 71. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/module.js`
- Response: HTTP `200` / Length `6849` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `6849`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 72. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/role_schema.xml`
- Response: HTTP `200` / Length `3028` / Type `application/xml`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3028`
  - Content-Type: `application/xml`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 73. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/tests/behat/override_roles_highlighting.feature`
- Response: HTTP `200` / Length `893` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `893`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 74. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/local/settings/autocomplete.mustache`
- Response: HTTP `200` / Length `2811` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2811`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 75. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting.mustache`
- Response: HTTP `200` / Length `3554` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3554`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 76. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configcheckbox.mustache`
- Response: HTTP `200` / Length `1418` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1418`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 77. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configcolourpicker.mustache`
- Response: HTTP `200` / Length `1790` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1790`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 78. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configdirectory.mustache`
- Response: HTTP `200` / Length `1339` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1339`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 79. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configduration.mustache`
- Response: HTTP `200` / Length `1873` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1873`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 80. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configempty.mustache`
- Response: HTTP `200` / Length `1068` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1068`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 81. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configexecutable.mustache`
- Response: HTTP `200` / Length `1334` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1334`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 82. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configfile.mustache`
- Response: HTTP `200` / Length `1880` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1880`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 83. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configfilesize.mustache`
- Response: HTTP `200` / Length `1869` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1869`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 84. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_confightmleditor.mustache`
- Response: HTTP `200` / Length `1236` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1236`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 85. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configmulticheckbox.mustache`
- Response: HTTP `200` / Length `1657` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1657`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 86. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configmultiselect.mustache`
- Response: HTTP `200` / Length `1704` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1704`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 87. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configmultiselect_optgroup.mustache`
- Response: HTTP `200` / Length `2673` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2673`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 88. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configpasswordunmask.mustache`
- Response: HTTP `200` / Length `2771` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2771`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 89. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configselect.mustache`
- Response: HTTP `200` / Length `1581` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1581`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 90. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configselect_optgroup.mustache`
- Response: HTTP `200` / Length `2552` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2552`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 91. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configtext.mustache`
- Response: HTTP `200` / Length `1628` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1628`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 92. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configtextarea.mustache`
- Response: HTTP `200` / Length `1518` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1518`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 93. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_configtime.mustache`
- Response: HTTP `200` / Length `2293` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2293`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 94. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_courselist_frontpage.mustache`
- Response: HTTP `200` / Length `1684` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1684`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 95. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_description.mustache`
- Response: HTTP `200` / Length `1379` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1379`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 96. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_devicedetectregex.mustache`
- Response: HTTP `200` / Length `1848` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1848`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 97. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_emoticons.mustache`
- Response: HTTP `200` / Length `2221` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2221`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 98. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_encryptedpassword.mustache`
- Response: HTTP `200` / Length `2391` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2391`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 99. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_filetypes.mustache`
- Response: HTTP `200` / Length `1826` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1826`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 100. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_flag.mustache`
- Response: HTTP `200` / Length `1263` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1263`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 101. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_gradecat_combo.mustache`
- Response: HTTP `200` / Length `1900` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1900`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 102. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_heading.mustache`
- Response: HTTP `200` / Length `1263` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1263`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 103. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_manage_plugins.mustache`
- Response: HTTP `200` / Length `3990` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3990`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 104. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/setting_special_calendar_weekend.mustache`
- Response: HTTP `200` / Length `1808` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1808`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 105. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/settings.mustache`
- Response: HTTP `200` / Length `2050` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2050`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 106. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/settings_search_results.mustache`
- Response: HTTP `200` / Length `2707` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2707`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 107. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/tasklogs.mustache`
- Response: HTTP `200` / Length `1523` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1523`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 108. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tests/behat/browse_users.feature`
- Response: HTTP `200` / Length `3120` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3120`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 109. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tests/behat/enable_multiple_accounts_use_same_email.feature`
- Response: HTTP `200` / Length `3416` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3416`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 110. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tests/behat/filter_users.feature`
- Response: HTTP `200` / Length `5665` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `5665`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 111. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tests/behat/filter_users_settings.feature`
- Response: HTTP `200` / Length `9997` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `9997`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 112. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tests/behat/invalid_allcountrycodes.feature`
- Response: HTTP `200` / Length `1443` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1443`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 113. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tests/behat/language_settings.feature`
- Response: HTTP `200` / Length `1386` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1386`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 114. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tests/behat/manage_tokens.feature`
- Response: HTTP `200` / Length `3894` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `3894`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 115. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tests/behat/purge_caches.feature`
- Response: HTTP `200` / Length `1429` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1429`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 116. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tests/behat/search_areas.feature`
- Response: HTTP `200` / Length `1046` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1046`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 117. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tests/behat/set_admin_settings_value.feature`
- Response: HTTP `200` / Length `895` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `895`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 118. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tests/behat/webservice_users.feature`
- Response: HTTP `200` / Length `1499` / Type ``
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1499`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 119. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics/amd/build/log_info.min.js.map`
- Response: HTTP `200` / Length `2671` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2671`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 120. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics/amd/build/model.min.js`
- Response: HTTP `200` / Length `4043` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `4043`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 121. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics/amd/build/model.min.js.map`
- Response: HTTP `200` / Length `12589` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `12589`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 122. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics/amd/build/potential-contexts.min.js.map`
- Response: HTTP `200` / Length `2752` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `2752`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 123. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics/amd/src/log_info.js`
- Response: HTTP `200` / Length `1936` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1936`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 124. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics/amd/src/model.js`
- Response: HTTP `200` / Length `8848` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `8848`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 125. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics/amd/src/potential-contexts.js`
- Response: HTTP `200` / Length `1934` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `1934`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 126. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/login/index.php`
- Response: HTTP `200` / Length `23573` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system: Log in to the site
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `23573`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 127. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/classes/form/purge_caches.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 128. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/classes/form/testoutgoingmailconf_form.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 129. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/classes/local/externalpage/accesscallback.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 130. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/classes/local/settings/autocomplete.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 131. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/classes/local/settings/filesize.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 132. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/classes/privacy/provider.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 133. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/adhoc_task.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 134. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/alternative_component_cache.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 135. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/automated_backups.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 136. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/backup.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 137. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/build_theme_css.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 138. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/cfg.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 139. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/check_database_schema.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 140. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/checks.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 141. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/cron.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 142. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/dashboard_reset.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 143. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/fix_course_sequence.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 144. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/fix_deleted_users.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 145. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/fix_orphaned_calendar_events.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 146. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/fix_orphaned_question_categories.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 147. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/generate_key.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 148. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/install.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 149. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/install_database.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 150. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/kill_all_sessions.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 151. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/maintenance.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 152. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/mysql_collation.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 153. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/mysql_compressed_rows.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 154. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/purge_caches.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 155. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/reset_password.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 156. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/restore_backup.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 157. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/scheduled_task.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 158. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/svgtool.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 159. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/uninstall_plugins.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 160. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli/upgrade.php`
- Response: HTTP `200` / Length `63` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `63`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 161. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cron.php`
- Response: HTTP `200` / Length `84` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `84`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 162. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/lib.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 163. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/mailout-debugger.php`
- Response: HTTP `200` / Length `15` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `15`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 164. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/mnet/peer_forms.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 165. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/mnet/profilefields_form.php`
- Response: HTTP `200` / Length `42` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 166. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/mnet/services_form.php`
- Response: HTTP `200` / Length `42` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 167. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/mnet/tabs.php`
- Response: HTTP `200` / Length `42` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `42`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 168. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/process_email.php`
- Response: HTTP `200` / Length `37` / Type `text/html; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `37`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 169. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/registration/forms.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 170. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/registration/lib.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 171. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/admins_existing_selector.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 172. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/admins_potential_selector.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 173. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/allow_assign_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 174. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/allow_override_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 175. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/allow_role_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 176. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/allow_switch_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 177. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/allow_view_page.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 178. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/assign_user_selector_base.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 179. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/capability_table_base.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 180. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/capability_table_with_risks.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 181. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/check_capability_table.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 182. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/check_users_selector.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 183. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/define_role_table_advanced.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 184. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/define_role_table_basic.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 185. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/existing_role_holders.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 186. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/override_permissions_table_advanced.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 187. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/permission_allow_form.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 188. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/permission_prohibit_form.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 189. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/permissions_table.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 190. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/potential_assignees_below_course.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 191. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/potential_assignees_course_and_above.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 192. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/preset.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 193. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/preset_form.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 194. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/privacy/provider.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 195. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/view_role_definition_table.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 196. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/lib.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 197. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/managetabs.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 198. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings/analytics.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 199. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings/competency.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 200. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings/development.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 201. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings/h5p.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 202. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings/language.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 203. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings/license.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 204. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings/location.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 205. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings/messaging.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 206. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings/mnet.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 207. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings/moodleservices.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 208. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings/security.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 209. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings/server.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 210. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings/subsystems.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 211. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings/userfeedback.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 212. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tests/behat/display_short_names.feature`
- Response: HTTP `200` / Length `858` / Type ``
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `858`
  - Content-Type: ``
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 213. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics/amd/build/log_info.min.js`
- Response: HTTP `200` / Length `804` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `804`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 214. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics/amd/build/potential-contexts.min.js`
- Response: HTTP `200` / Length `778` / Type `text/javascript`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `778`
  - Content-Type: `text/javascript`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 215. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics/classes/clihelper.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=UTF-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 216. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/config.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=utf-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `0`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; sensitive-looking path

### 217. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/lib/ajax/service.php`
- Response: HTTP `200` / Length `191` / Type `application/json; charset=utf-8`
- Evidence: status=200; different from 404 baseline; API-like endpoint
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `191`
  - Content-Type: `application/json; charset=utf-8`
  - Reason: status=200; different from 404 baseline; API-like endpoint

### 218. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin`
- Response: HTTP `301` / Length `331` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `331`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 219. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/classes`
- Response: HTTP `301` / Length `339` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `339`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 220. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/classes/form`
- Response: HTTP `301` / Length `344` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `344`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 221. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/classes/local`
- Response: HTTP `301` / Length `345` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `345`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 222. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/classes/local/externalpage`
- Response: HTTP `301` / Length `358` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `358`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 223. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/classes/local/settings`
- Response: HTTP `301` / Length `354` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `354`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 224. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/classes/privacy`
- Response: HTTP `301` / Length `347` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `347`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 225. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/cli`
- Response: HTTP `301` / Length `335` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `335`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 226. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/mnet`
- Response: HTTP `301` / Length `336` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `336`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 227. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/registration`
- Response: HTTP `301` / Length `344` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `344`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 228. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles`
- Response: HTTP `301` / Length `337` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `337`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 229. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes`
- Response: HTTP `301` / Length `345` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `345`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 230. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/classes/privacy`
- Response: HTTP `301` / Length `353` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `353`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 231. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/tests`
- Response: HTTP `301` / Length `343` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `343`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 232. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/roles/tests/behat`
- Response: HTTP `301` / Length `349` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `349`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 233. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/settings`
- Response: HTTP `301` / Length `340` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `340`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 234. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates`
- Response: HTTP `301` / Length `341` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `341`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 235. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/local`
- Response: HTTP `301` / Length `347` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `347`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 236. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/templates/local/settings`
- Response: HTTP `301` / Length `356` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `356`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 237. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tests`
- Response: HTTP `301` / Length `337` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `337`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 238. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tests/behat`
- Response: HTTP `301` / Length `343` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `343`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 239. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool`
- Response: HTTP `301` / Length `336` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `336`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 240. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics`
- Response: HTTP `301` / Length `346` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `346`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 241. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics/amd`
- Response: HTTP `301` / Length `350` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `350`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 242. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics/amd/build`
- Response: HTTP `301` / Length `356` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `356`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 243. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics/amd/src`
- Response: HTTP `301` / Length `354` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `354`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 244. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/admin/tool/analytics/classes`
- Response: HTTP `301` / Length `354` / Type `text/html; charset=iso-8859-1`
- Title: 301 Moved Permanently
- Evidence: status=301; different from 404 baseline; sensitive-looking path
- Why detected / Feedback analysis:
  - Response status: `301`
  - Response length: `354`
  - Content-Type: `text/html; charset=iso-8859-1`
  - Reason: status=301; different from 404 baseline; sensitive-looking path

### 245. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/course/index.php`
- Response: HTTP `200` / Length `30759` / Type `text/html; charset=utf-8`
- Title: AHUC eLearning: Course categories
- Evidence: status=200; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `30759`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta

### 246. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://elearn.ahuc.edu.eg/moodle/index.php`
- Response: HTTP `200` / Length `31687` / Type `text/html; charset=utf-8`
- Title: AL Hayah University eLearing system
- Evidence: status=200; different from 404 baseline; length delta
- Why detected / Feedback analysis:
  - Response status: `200`
  - Response length: `31687`
  - Content-Type: `text/html; charset=utf-8`
  - Reason: status=200; different from 404 baseline; length delta

