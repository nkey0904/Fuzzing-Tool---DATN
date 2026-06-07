# Context Feedback Fuzzer - Topic 2

Prototype cho đề tài: **Xây dựng mô hình/công cụ kiểm thử bảo mật ứng dụng web dựa trên kỹ thuật fuzzing có ngữ cảnh và phản hồi**.

## Ý tưởng

Tool hoạt động theo 4 bước:

1. **Fingerprint ngữ cảnh CMS**: nhận diện WordPress, Joomla, Drupal, Liferay, SharePoint bằng header, cookie, HTML body và probe path.
2. **Chọn wordlist theo ngữ cảnh**: ví dụ WordPress ưu tiên `wp-content`, `wp-json`, plugin/theme; SharePoint ưu tiên `_layouts`, `_vti_bin`, `_api/web`; Liferay ưu tiên `api/jsonws`, `p_p_id`.
3. **Fuzzing an toàn**: gửi GET request tới đường dẫn và parameter với giá trị canary vô hại, không brute-force đăng nhập, không gửi payload khai thác.
4. **Feedback-driven scheduling**: endpoint có status/length/content-type khác baseline, 401/403/500, hoặc API-like sẽ được chấm điểm cao và theo dõi thêm nhẹ.

## Cài đặt

```bash
cd context_feedback_fuzzer
python -m venv .venv
.venv\Scripts\activate     # Windows
# source .venv/bin/activate # Linux/macOS
pip install -r requirements.txt
```

## Chạy thử trong lab được phép

```bash
python run.py --target http://127.0.0.1:8080 --cms auto --max-requests 300 --delay 0.2 --i-have-authorization
```

Gợi ý theo CMS:

```bash
python run.py --target http://127.0.0.1:8080 --cms wordpress --i-have-authorization
python run.py --target http://127.0.0.1:8081 --cms joomla --i-have-authorization
python run.py --target http://127.0.0.1:8082 --cms drupal --i-have-authorization
python run.py --target http://127.0.0.1:8083 --cms sharepoint --i-have-authorization
python run.py --target http://127.0.0.1:8084 --cms liferay --i-have-authorization
```

## Output

Tool sinh 2 file:

- `reports/report.json`: dữ liệu máy đọc được.
- `reports/report.md`: báo cáo tóm tắt để đưa vào bài báo cáo.

Mỗi finding gồm: loại fuzzing, CMS, URL, method, status, length, content-type, score, reason, title, hash nội dung.

## An toàn và phạm vi

- Chỉ chạy trên hệ thống bạn sở hữu hoặc có quyền kiểm thử.
- Mặc định chỉ dùng GET, cùng host với target, có `--max-requests` và `--delay`.
- Parameter fuzzing dùng canary vô hại, không có payload SQLi/XSS/RCE.
- Không bypass xác thực, không brute-force mật khẩu, không khai thác CVE.

## Cấu trúc

```text
context_feedback_fuzzer/
├── context_fuzzer/
│   ├── fuzzer.py       # engine fuzzing + feedback scoring
│   └── profiles.py     # profile CMS từ tài liệu
├── wordlists/          # các wordlist bạn upload
├── reports/            # output report
├── requirements.txt
├── run.py
└── README.md
```

## Mở rộng cho báo cáo

- Thêm profile mới trong `context_fuzzer/profiles.py`.
- Thêm rule scoring trong `score_response()`.
- Thêm parser HTML form để phát hiện parameter thực tế, nhưng vẫn nên giữ safe canary.
- Thêm dashboard Flask/FastAPI nếu cần demo giao diện.

## v1.1 cải thiện theo feedback mentor

Bản này bổ sung phần mà mentor yêu cầu: không chỉ dùng list file/dir/param đặc trưng của CMS, mà còn tạo **value wordlist/payload wordlist** theo ngữ cảnh.

### Cơ chế tạo wordlist mới

1. **CMS context wordlist**: WordPress/Joomla/Drupal/Liferay/SharePoint dùng path, file, directory, parameter đặc trưng.
2. **Server technology wordlist**: nếu fingerprint thấy PHP thì ưu tiên `.php`; Java thì `.jsp`, `.do`, `.action`; ASP.NET/IIS thì `.aspx`, `.ashx`, `.asmx`.
3. **Parameter-aware value wordlist**:
   - `id`, `user_id`, `post_id`, `page_id` → numeric boundary + SQL-shaped canary.
   - `q`, `search`, `s`, `name`, `title` → text canary + reflected-XSS canary.
   - `file`, `path`, `template`, `view` → path-shaped canary.
   - `redirect`, `url`, `next`, `return` → redirect canary.

### Feedback analyzer mới

Tool phân tích response để tạo bug hypothesis:

- Possible SQL Injection / input handling error.
- Possible Reflected XSS.
- Possible Open Redirect.
- Possible Path Handling Issue.
- Verbose Error Disclosure.

Các probe vẫn là canary an toàn, GET-only, rate-limited và yêu cầu authorization flag.
