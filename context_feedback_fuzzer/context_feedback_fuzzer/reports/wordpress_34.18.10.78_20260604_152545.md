# Context Feedback Fuzzer Report

- Target: `http://34.18.10.78/`
- Detected CMS: **wordpress**
- Requests sent: `400`
- Safety: GET-only, same-host scope, rate-limited, authorization flag required.
- Server technology hint: `php` / `apache`

## Wordlist generation mechanism

Tool tạo wordlist theo 3 lớp: CMS paths từ profile/wordlist, extension paths theo server technology, và payload values theo loại parameter.

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

## Fingerprint scores

- wordpress: 17
- joomla: 0
- drupal: 0
- liferay: 0
- sharepoint: 0

## Findings

Các finding dưới đây là giả thuyết nguy cơ bug dựa trên phản hồi server, không phải xác nhận khai thác thành công hay chấm severity.

### 1. Possible SQL Injection
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://34.18.10.78/readme.html?p=1%22`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 2. Possible SQL Injection
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Possible SQL Injection
- URL: `http://34.18.10.78/readme.html?p=1%27`
- Parameter: `p` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: SQL-like error keyword appeared in response
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape; SQL-like error keyword appeared in response

### 3. Input Reflection
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Input Reflection
- URL: `http://34.18.10.78/?log=%22cff_canary_9x7`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_canary_9x7`
- Response: HTTP `200` / Length `97562` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: canary value was reflected but appears transformed or encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value was reflected but appears transformed or encoded

### 4. Input Reflection
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Input Reflection
- URL: `http://34.18.10.78/?log=%27cff_canary_9x7`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_canary_9x7`
- Response: HTTP `200` / Length `97562` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: canary value was reflected but appears transformed or encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value was reflected but appears transformed or encoded

### 5. Input Reflection
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Input Reflection
- URL: `http://34.18.10.78/?log=%3Ccff_canary_9x7%3E`
- Parameter: `log` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_canary_9x7&gt;`
- Response: HTTP `200` / Length `97590` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: canary value was reflected but appears transformed or encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value was reflected but appears transformed or encoded

### 6. Input Reflection
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Input Reflection
- URL: `http://34.18.10.78/?s=%22cff_canary_9x7`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_canary_9x7`
- Response: HTTP `200` / Length `61935` / Type `text/html; charset=UTF-8`
- Title: Search Results for “&quot;cff_canary_9x7” – WordPress on Google Compute Engine
- Evidence: canary value was reflected but appears transformed or encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value was reflected but appears transformed or encoded

### 7. Input Reflection
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Input Reflection
- URL: `http://34.18.10.78/?s=%27cff_canary_9x7`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_canary_9x7`
- Response: HTTP `200` / Length `61935` / Type `text/html; charset=UTF-8`
- Title: Search Results for “&#x27;cff_canary_9x7” – WordPress on Google Compute Engine
- Evidence: canary value was reflected but appears transformed or encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value was reflected but appears transformed or encoded

### 8. Input Reflection
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Input Reflection
- URL: `http://34.18.10.78/?s=%3Ccff_canary_9x7%3E`
- Parameter: `s` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_canary_9x7&gt;`
- Response: HTTP `200` / Length `61965` / Type `text/html; charset=UTF-8`
- Title: Search Results for “&lt;cff_canary_9x7&gt;” – WordPress on Google Compute Engine
- Evidence: canary value was reflected but appears transformed or encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value was reflected but appears transformed or encoded

### 9. Input Reflection
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Input Reflection
- URL: `http://34.18.10.78/?search=%22cff_canary_9x7`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&quot;cff_canary_9x7`
- Response: HTTP `200` / Length `99313` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: canary value was reflected but appears transformed or encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value was reflected but appears transformed or encoded

### 10. Input Reflection
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Input Reflection
- URL: `http://34.18.10.78/?search=%27cff_canary_9x7`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&#x27;cff_canary_9x7`
- Response: HTTP `200` / Length `99313` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: canary value was reflected but appears transformed or encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value was reflected but appears transformed or encoded

### 11. Input Reflection
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu/nguy cơ: Input Reflection
- URL: `http://34.18.10.78/?search=%3Ccff_canary_9x7%3E`
- Parameter: `search` | Param type: `text`
- Payload type: `xss_reflection_probe` | Payload: `&lt;cff_canary_9x7&gt;`
- Response: HTTP `200` / Length `99331` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: canary value was reflected but appears transformed or encoded
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape; canary value was reflected but appears transformed or encoded

### 12. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/readme.html?p=-1`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 13. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/readme.html?p=0`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 14. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/readme.html?p=1`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 15. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/readme.html?p=999999`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 16. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/readme.html?page_id=-1`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 17. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/readme.html?page_id=0`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 18. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/readme.html?page_id=1`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 19. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/readme.html?page_id=999999`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `999999`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path; parameter changed response shape

### 20. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?action=%27`
- Parameter: `action` | Param type: `action`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Response: HTTP `200` / Length `97452` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 21. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?action=cff_canary_9x7`
- Parameter: `action` | Param type: `action`
- Payload type: `action_canary` | Payload: `cff_canary_9x7`
- Response: HTTP `200` / Length `97556` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 22. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?action=invalid_action`
- Parameter: `action` | Param type: `action`
- Payload type: `text_canary` | Payload: `invalid_action`
- Response: HTTP `200` / Length `97556` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 23. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?author=0`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Response: HTTP `200` / Length `99217` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 24. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?author=1`
- Parameter: `author` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Response: HTTP `200` / Length `99768` / Type `text/html; charset=UTF-8`
- Title: admin – WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 25. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?author=1%22`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&quot;`
- Response: HTTP `200` / Length `99786` / Type `text/html; charset=UTF-8`
- Title: admin – WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 26. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?author=1%27`
- Parameter: `author` | Param type: `numeric`
- Payload type: `sqli_probe` | Payload: `1&#x27;`
- Response: HTTP `200` / Length `99786` / Type `text/html; charset=UTF-8`
- Title: admin – WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 27. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?cat=-1`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Response: HTTP `200` / Length `100577` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 28. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?cat=0`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Response: HTTP `200` / Length `99199` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 29. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?cat=1`
- Parameter: `cat` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Response: HTTP `200` / Length `78025` / Type `text/html; charset=UTF-8`
- Title: Uncategorized – WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 30. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?log=%27`
- Parameter: `log` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Response: HTTP `200` / Length `97422` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 31. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?log=cff_canary_9x7`
- Parameter: `log` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_canary_9x7`
- Response: HTTP `200` / Length `97526` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 32. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?nonce=%27`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Response: HTTP `200` / Length `97442` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 33. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?nonce=12345`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345`
- Response: HTTP `200` / Length `97456` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 34. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?nonce=cff_canary_9x7`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_canary_9x7`
- Response: HTTP `200` / Length `97546` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 35. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?nonce=true`
- Parameter: `nonce` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true`
- Response: HTTP `200` / Length `97446` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 36. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?p=-1`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `-1`
- Response: HTTP `200` / Length `65144` / Type `text/html; charset=UTF-8`
- Title: Page not found – WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 37. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?p=0`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Response: HTTP `200` / Length `99187` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 38. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?p=1`
- Parameter: `p` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `1`
- Response: HTTP `200` / Length `68180` / Type `text/html; charset=UTF-8`
- Title: Hello world! – WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 39. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?page_id=0`
- Parameter: `page_id` | Param type: `numeric`
- Payload type: `numeric_boundary` | Payload: `0`
- Response: HTTP `200` / Length `99223` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 40. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?pwd=%27`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Response: HTTP `200` / Length `97422` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 41. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?pwd=12345`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_number` | Payload: `12345`
- Response: HTTP `200` / Length `97436` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 42. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?pwd=cff_canary_9x7`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_canary` | Payload: `cff_canary_9x7`
- Response: HTTP `200` / Length `97526` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 43. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?pwd=true`
- Parameter: `pwd` | Param type: `generic`
- Payload type: `generic_bool` | Payload: `true`
- Response: HTTP `200` / Length `97426` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 44. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?redirect_to=%2F%2Fexample.com%2Fcff_canary_9x7`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `//example.com/cff_canary_9x7`
- Response: HTTP `200` / Length `97794` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 45. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?redirect_to=https%3A%2F%2Fexample.com%2Fcff_canary_9x7`
- Parameter: `redirect_to` | Param type: `redirect`
- Payload type: `redirect_probe` | Payload: `https://example.com/cff_canary_9x7`
- Response: HTTP `200` / Length `97870` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 46. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?s=%27`
- Parameter: `s` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Response: HTTP `200` / Length `75033` / Type `text/html; charset=UTF-8`
- Title: Search Results for “&#x27;” – WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 47. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?s=cff_canary_9x7`
- Parameter: `s` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_canary_9x7`
- Response: HTTP `200` / Length `61873` / Type `text/html; charset=UTF-8`
- Title: Search Results for “cff_canary_9x7” – WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 48. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?search=%27`
- Parameter: `search` | Param type: `text`
- Payload type: `sqli_probe` | Payload: `&#x27;`
- Response: HTTP `200` / Length `99229` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 49. Parameter behavior anomaly
- Kind: `parameter`
- Kết luận nguy cơ: Có dấu hiệu phản hồi bất thường khi fuzz parameter
- URL: `http://34.18.10.78/?search=cff_canary_9x7`
- Parameter: `search` | Param type: `text`
- Payload type: `text_canary` | Payload: `cff_canary_9x7`
- Response: HTTP `200` / Length `99295` / Type `text/html; charset=UTF-8`
- Title: WordPress on Google Compute Engine
- Evidence: status=200; different from 404 baseline; length delta; parameter changed response shape
- Reason: status=200; different from 404 baseline; length delta; parameter changed response shape

### 50. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/license.txt`
- Response: HTTP `200` / Length `19903` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 51. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/readme.html`
- Response: HTTP `200` / Length `7406` / Type `text/html`
- Title: WordPress › ReadMe
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 52. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/`
- Response: HTTP `200` / Length `22626` / Type `text/html;charset=UTF-8`
- Title: Index of /wp-admin/css
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 53. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/color-picker-rtl.css`
- Response: HTTP `200` / Length `3957` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 54. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/color-picker-rtl.min.css`
- Response: HTTP `200` / Length `3201` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 55. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/color-picker.css`
- Response: HTTP `200` / Length `3919` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 56. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/color-picker.min.css`
- Response: HTTP `200` / Length `3198` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 57. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/customize-controls-rtl.css`
- Response: HTTP `200` / Length `72569` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 58. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/customize-controls-rtl.min.css`
- Response: HTTP `200` / Length `60473` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 59. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/customize-controls.css`
- Response: HTTP `200` / Length `72491` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 60. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/customize-controls.min.css`
- Response: HTTP `200` / Length `60430` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 61. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/dashboard-rtl.css`
- Response: HTTP `200` / Length `30439` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 62. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/dashboard.css`
- Response: HTTP `200` / Length `30409` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 63. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/install-rtl.css`
- Response: HTTP `200` / Length `6497` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 64. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/install.css`
- Response: HTTP `200` / Length `6464` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 65. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/install.min.css`
- Response: HTTP `200` / Length `5266` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 66. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/login-rtl.css`
- Response: HTTP `200` / Length `8291` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 67. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/login.css`
- Response: HTTP `200` / Length `8253` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 68. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/media-rtl.css`
- Response: HTTP `200` / Length `28190` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 69. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/media-rtl.min.css`
- Response: HTTP `200` / Length `22694` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 70. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/media.css`
- Response: HTTP `200` / Length `28139` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 71. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/media.min.css`
- Response: HTTP `200` / Length `22678` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 72. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/widgets-rtl.css`
- Response: HTTP `200` / Length `17887` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 73. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/widgets.css`
- Response: HTTP `200` / Length `17850` / Type `text/css`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 74. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/`
- Response: HTTP `200` / Length `20124` / Type `text/html;charset=UTF-8`
- Title: Index of /wp-admin/images
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 75. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/arrows-2x.png`
- Response: HTTP `200` / Length `863` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 76. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/date-button-2x.gif`
- Response: HTTP `200` / Length `996` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 77. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/icons32-2x.png`
- Response: HTTP `200` / Length `21770` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 78. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/icons32-vs-2x.png`
- Response: HTTP `200` / Length `21396` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 79. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/icons32-vs.png`
- Response: HTTP `200` / Length `8007` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 80. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/icons32.png`
- Response: HTTP `200` / Length `8023` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 81. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/imgedit-icons-2x.png`
- Response: HTTP `200` / Length `7664` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 82. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/imgedit-icons.png`
- Response: HTTP `200` / Length `4055` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 83. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/list-2x.png`
- Response: HTTP `200` / Length `1523` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 84. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/list.png`
- Response: HTTP `200` / Length `1003` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 85. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/loading.gif`
- Response: HTTP `200` / Length `1368` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 86. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/mask.png`
- Response: HTTP `200` / Length `2001` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 87. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/media-button-2x.png`
- Response: HTTP `200` / Length `850` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 88. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/menu-2x.png`
- Response: HTTP `200` / Length `12672` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 89. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/menu-vs-2x.png`
- Response: HTTP `200` / Length `12453` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 90. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/menu-vs.png`
- Response: HTTP `200` / Length `5086` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 91. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/menu.png`
- Response: HTTP `200` / Length `5039` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 92. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/post-formats-vs.png`
- Response: HTTP `200` / Length `2450` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 93. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/post-formats.png`
- Response: HTTP `200` / Length `2157` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 94. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/post-formats32-vs.png`
- Response: HTTP `200` / Length `5111` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 95. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/post-formats32.png`
- Response: HTTP `200` / Length `5142` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 96. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/stars-2x.png`
- Response: HTTP `200` / Length `1257` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 97. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/stars.png`
- Response: HTTP `200` / Length `924` / Type `image/png`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 98. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-content/plugins/akismet/readme.txt`
- Response: HTTP `200` / Length `6329` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 99. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-content/plugins/contact-form-7/readme.txt`
- Response: HTTP `200` / Length `4825` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 100. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-content/plugins/woocommerce/readme.txt`
- Response: HTTP `200` / Length `22170` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 101. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-content/themes/twentytwentythree/readme.txt`
- Response: HTTP `200` / Length `3075` / Type `text/plain`
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 102. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-login.php`
- Response: HTTP `200` / Length `5565` / Type `text/html; charset=UTF-8`
- Title: Log In ‹ WordPress on Google Compute Engine — WordPress
- Evidence: status=200; different from 404 baseline; length delta; sensitive-looking path
- Reason: status=200; different from 404 baseline; length delta; sensitive-looking path

### 103. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/admin-footer.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 104. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/admin-functions.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 105. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/admin-header.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 106. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/admin-post.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 107. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/farbtastic-rtl.css`
- Response: HTTP `200` / Length `647` / Type `text/css`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 108. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/farbtastic.css`
- Response: HTTP `200` / Length `611` / Type `text/css`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 109. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/wp-admin-rtl.css`
- Response: HTTP `200` / Length `490` / Type `text/css`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 110. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/wp-admin-rtl.min.css`
- Response: HTTP `200` / Length `550` / Type `text/css`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 111. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/wp-admin.css`
- Response: HTTP `200` / Length `395` / Type `text/css`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 112. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/css/wp-admin.min.css`
- Response: HTTP `200` / Length `490` / Type `text/css`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 113. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/custom-background.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 114. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/custom-header.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 115. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/edit-form-advanced.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 116. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/edit-form-comment.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 117. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/edit-link-form.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 118. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/edit-tag-form.php`
- Response: HTTP `200` / Length `2` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 119. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/align-center-2x.png`
- Response: HTTP `200` / Length `147` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 120. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/align-center.png`
- Response: HTTP `200` / Length `546` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 121. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/align-left-2x.png`
- Response: HTTP `200` / Length `143` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 122. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/align-left.png`
- Response: HTTP `200` / Length `554` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 123. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/align-none-2x.png`
- Response: HTTP `200` / Length `121` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 124. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/align-none.png`
- Response: HTTP `200` / Length `417` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 125. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/align-right-2x.png`
- Response: HTTP `200` / Length `142` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 126. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/align-right.png`
- Response: HTTP `200` / Length `509` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 127. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/arrows.png`
- Response: HTTP `200` / Length `243` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 128. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/bubble_bg-2x.gif`
- Response: HTTP `200` / Length `424` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 129. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/bubble_bg.gif`
- Response: HTTP `200` / Length `398` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 130. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/comment-grey-bubble-2x.png`
- Response: HTTP `200` / Length `258` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 131. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/comment-grey-bubble.png`
- Response: HTTP `200` / Length `114` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 132. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/date-button.gif`
- Response: HTTP `200` / Length `400` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 133. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/generic.png`
- Response: HTTP `200` / Length `719` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 134. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/marker.png`
- Response: HTTP `200` / Length `360` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 135. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/media-button-image.gif`
- Response: HTTP `200` / Length `200` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 136. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/media-button-music.gif`
- Response: HTTP `200` / Length `206` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 137. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/media-button-other.gif`
- Response: HTTP `200` / Length `248` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 138. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/media-button-video.gif`
- Response: HTTP `200` / Length `133` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 139. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/media-button.png`
- Response: HTTP `200` / Length `323` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 140. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/no.png`
- Response: HTTP `200` / Length `755` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 141. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/resize-2x.gif`
- Response: HTTP `200` / Length `151` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 142. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/resize-rtl-2x.gif`
- Response: HTTP `200` / Length `150` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 143. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/resize-rtl.gif`
- Response: HTTP `200` / Length `70` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 144. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/resize.gif`
- Response: HTTP `200` / Length `64` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 145. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/se.png`
- Response: HTTP `200` / Length `120` / Type `image/png`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 146. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/sort-2x.gif`
- Response: HTTP `200` / Length `97` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 147. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/images/sort.gif`
- Response: HTTP `200` / Length `55` / Type `image/gif`
- Evidence: status=200; different from 404 baseline; sensitive-looking path
- Reason: status=200; different from 404 baseline; sensitive-looking path

### 148. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; sensitive-looking path
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 149. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/about.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; sensitive-looking path
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 150. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/admin.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; sensitive-looking path
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 151. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/async-upload.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; sensitive-looking path
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 152. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/comment.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; sensitive-looking path
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 153. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/credits.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; sensitive-looking path
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 154. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/customize.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; sensitive-looking path
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 155. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/edit-comments.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; sensitive-looking path
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 156. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/edit-tags.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; sensitive-looking path
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 157. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/edit.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; sensitive-looking path
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 158. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/export.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; sensitive-looking path
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 159. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-admin/freedoms.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline; sensitive-looking path
- Reason: status=302; different from 404 baseline; sensitive-looking path

### 160. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-content/plugins/contact-form-7/`
- Response: HTTP `200` / Length `2781` / Type `text/html;charset=UTF-8`
- Title: Index of /wp-content/plugins/contact-form-7
- Evidence: status=200; different from 404 baseline; length delta
- Reason: status=200; different from 404 baseline; length delta

### 161. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-content/plugins/woocommerce/`
- Response: HTTP `200` / Length `3538` / Type `text/html;charset=UTF-8`
- Title: Index of /wp-content/plugins/woocommerce
- Evidence: status=200; different from 404 baseline; length delta
- Reason: status=200; different from 404 baseline; length delta

### 162. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-content/themes/twentytwentythree/`
- Response: HTTP `200` / Length `2560` / Type `text/html;charset=UTF-8`
- Title: Index of /wp-content/themes/twentytwentythree
- Evidence: status=200; different from 404 baseline; length delta
- Reason: status=200; different from 404 baseline; length delta

### 163. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-content/uploads/`
- Response: HTTP `200` / Length `3922` / Type `text/html;charset=UTF-8`
- Title: Index of /wp-content/uploads
- Evidence: status=200; different from 404 baseline; length delta
- Reason: status=200; different from 404 baseline; length delta

### 164. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-includes/`
- Response: HTTP `200` / Length `63990` / Type `text/html;charset=UTF-8`
- Title: Index of /wp-includes
- Evidence: status=200; different from 404 baseline; length delta
- Reason: status=200; different from 404 baseline; length delta

### 165. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-content/`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline
- Reason: status=200; different from 404 baseline

### 166. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-content/index.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline
- Reason: status=200; different from 404 baseline

### 167. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-content/plugins/akismet/`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline
- Reason: status=200; different from 404 baseline

### 168. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-content/plugins/akismet/index.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline
- Reason: status=200; different from 404 baseline

### 169. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-cron.php`
- Response: HTTP `200` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=200; different from 404 baseline
- Reason: status=200; different from 404 baseline

### 170. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/index.php`
- Response: HTTP `301` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=301; different from 404 baseline
- Reason: status=301; different from 404 baseline

### 171. Interesting path / response anomaly
- Kind: `path`
- Kết luận nguy cơ: Có dấu hiệu endpoint đáng chú ý dựa trên phản hồi server
- URL: `http://34.18.10.78/wp-activate.php`
- Response: HTTP `302` / Length `0` / Type `text/html; charset=UTF-8`
- Evidence: status=302; different from 404 baseline
- Reason: status=302; different from 404 baseline

