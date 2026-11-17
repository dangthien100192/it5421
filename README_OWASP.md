# E2 — Hướng dẫn clone và chạy trên bộ dữ liệu OWASP Benchmark 

> **Windows 11, PowerShell, PyCharm, Codex qua đăng nhập ChatGPT**. Đây là quy trình cho `owasp_pipeline.py`, **không phải** pipeline demo `pipeline.py`.Codex chạy thủ công trong PyCharm; Python điều phối bộ dữ liệu, SAST và đánh giá.

## 1. Sơ đồ quy trình và lý do tách workspace

```text
OWASP BenchmarkPython (Git clone)
  ├── testcode/BenchmarkTest*.py
  └── expectedresults-0.1.csv (GROUND TRUTH)
                   |
                   v
          import-owasp --limit 200 --seed 42
                   |
       +-----------+----------------+-----------------+
       |                            |                 |
       v                            v                 v
 BLIND workspace              HYBRID workspace   EVALUATION
 samples/*.py                 samples/*.py        truth.csv
 PROMPT_DETECT.md             SAST results        hashes.json
       |                      |                   manifest.json
       v                      v
 Codex độc lập          Semgrep + Bandit (scan)
 results/ai.json              |
                              v
                       results/sast.json
                              |
                              v
                         Codex Triage
                       results/triage.json
       |                            |
       +------------+---------------+
                    |
                    v
                 evaluate
       evaluation/metrics.csv / metrics.json / coverage.json
                    |
                    v
             Codex Repair (Hybrid)
            patched/ + patch_results.json
```

**Nguyên tắc:** Blind không được đọc Semgrep, Bandit hay đáp án OWASP; Hybrid được đọc SAST nhưng không được đọc nhãn hoặc kết quả Blind; `evaluation/` chỉ dành cho người nghiên cứu và lệnh chấm điểm. Hai nhánh nên làm theo thứ tự **Blind → Hybrid** để hạn chế ảnh hưởng kết quả SAST lên đánh giá độc lập.

## 2. Chuẩn bị phần mềm

Yêu cầu có **Python, Git, PyCharm**, khả năng chạy **Semgrep/Bandit** và Codex trong PyCharm bằng đăng nhập ChatGPT. Mở PowerShell tại project:

```powershell
cd 'D:\DT\2025.B1\IT5421-CD1\E2-Codex'
python --version
git --version
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest tests -q
python -m bandit --version
semgrep --version
python owasp_pipeline.py --help
```

> **Phân biệt:** OWASP repo có file `expectedresults-0.1.csv` thuộc nguồn chính thức; file `truth.csv` do `import-owasp` tạo từ một tập con. Không tự điền nhãn hoặc dùng dự đoán Codex làm Ground Truth.

## 3. Clone nguồn OWASP BenchmarkPython

### 3.1 Clone repo về cạnh project

Tại `E2-Codex/`:

```powershell
git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git owasp-benchmark
```

Sau khi clone:

```text
E2-Codex/
├── owasp_pipeline.py
├── README_OWASP.md
└── owasp-benchmark/              # Repo ngoài dự án, không mở trong Codex Blind
    ├── .git/
    ├── testcode/
    │   ├── BenchmarkTest00001.py
    │   └── ...
    └── expectedresults-0.1.csv
```

### 3.2 Xác nhận đúng cấu trúc repo

```powershell
Test-Path .\owasp-benchmark\expectedresults-0.1.csv
Test-Path .\owasp-benchmark\testcode
Test-Path .\owasp-benchmark\testcode\BenchmarkTest00001.py
(Get-ChildItem .\owasp-benchmark\testcode -Filter 'BenchmarkTest*.py' -File).Count
Get-Content .\owasp-benchmark\expectedresults-0.1.csv -TotalCount 8
```

Ba câu `Test-Path` cần trả về `True`. Số file có thể thay đổi theo revision repo; **không giả định mọi checkout đều có cùng số lượng**. Nếu cấu trúc khác, kiểm tra repo/branch đã clone và tham số `--repo`, không tự chuyển nhãn theo phỏng đoán.

Để ghi nhận phiên bản dataset:

```powershell
git -C .\owasp-benchmark rev-parse HEAD
```

Lưu mã commit trong nhật ký thí nghiệm. Repo upstream có thể thay đổi theo thời gian; nếu cần tái lập, dùng cùng commit ở các lượt chạy.

### 3.3 Ground Truth gốc có dạng nào?

File `expectedresults-0.1.csv` sử dụng **4 trường** trên mỗi dòng dữ liệu:

```text
BenchmarkTestNNNNN,category,true|false,CWE_number
```

Dòng chú thích bắt đầu `#` được script bỏ qua. Chẳng hạn cấu trúc minh họa (không khẳng định nhãn của ID cụ thể):

```csv
# test name, category, real vulnerability, cwe
BenchmarkTest00001,pathtraver,true,22
```

`read_truth()` trong `owasp_pipeline.py` kiểm tra ID dạng `BenchmarkTest` + 5 chữ số, nhãn `true/false` và CWE dạng số; rồi chuẩn hóa thành `sample_id,category,cwe,is_vulnerable`.

## 4. Import nguồn và tạo workspace

**Lần đầu, dùng 200 testcase cố định**:

```powershell
python owasp_pipeline.py import-owasp --repo .\owasp-benchmark --limit 200 --seed 42
```

- `--repo`: thư mục repo vừa clone, trong đó có `testcode/` và `expectedresults-0.1.csv`.
- `--limit 200`: chọn 200 testcase. Giá trị `0` chọn toàn bộ số testcase có nhãn hợp lệ.
- `--seed 42`: cố định quá trình chọn mẫu; script phân nhóm theo CWE và lớp vulnerable/non-vulnerable rồi lấy mẫu luân phiên.
- `--work`: tùy chọn thay workspace mặc định, ví dụ `--work ..\E2-OWASP-run2`.

**Không gọi lại `import-owasp` nếu workspace đích đã tồn tại.** Script chủ động từ chối ghi đè nhằm bảo vệ các kết quả đã có. Muốn thử cấu hình khác, sử dụng `--work` mới:


### 4.1 Cây thư mục sau khi import

Với `E2-Codex` tại `D:\DT\2025.B1\IT5421-CD1\E2-Codex`:

```text
D:\DT\2025.B1\IT5421-CD1\
├── E2-Codex\
│   ├── owasp_pipeline.py
│   ├── README.md
│   ├── README_OWASP.md
│   └── owasp-benchmark\
│       ├── testcode\
│       └── expectedresults-0.1.csv
└── E2-OWASP-workspaces\            # Mặc định, là thư mục CÙNG CẤP E2-Codex
    ├── blind\
    │   ├── samples\                # 200 file .py chưa có nhãn
    │   ├── results\                # Codex tạo ai.json
    │   ├── patched\                # Tạo sẵn, không sửa samples
    │   ├── AGENTS.md
    │   └── PROMPT_DETECT.md         # Prompt phát hiện độc lập
    ├── hybrid\
    │   ├── samples\                # 200 file .py cùng nội dung ban đầu
    │   ├── results\                # Scanner + Codex triage outputs
    │   ├── patched\                # Chỉ chứa file được Codex vá
    │   ├── AGENTS.md
    │   ├── PROMPT_TRIAGE.md         # Prompt xác minh SAST
    │   └── PROMPT_REPAIR.md         # Prompt vá bảo mật
    └── evaluation\                # KHÔNG cho Codex mở
        ├── truth.csv               # Nhãn chuẩn của 200 mẫu đã chọn
        ├── hashes.json             # SHA-256 cho mỗi file nguồn
        └── manifest.json           # Seed, limit, số mẫu, phân bố CWE, thời điểm import
```

**Không lẫn với pipeline demo:** demo dùng `../E2-workspaces/` và tên file prompt là `prompt.txt`; OWASP dùng `../E2-OWASP-workspaces/` và tên `PROMPT_*.md`.

### 4.2 Kiểm tra sau import

```powershell
(Get-ChildItem ..\E2-OWASP-workspaces\blind\samples -Filter '*.py' -File).Count
(Get-ChildItem ..\E2-OWASP-workspaces\hybrid\samples -Filter '*.py' -File).Count
python owasp_pipeline.py verify
Get-Content ..\E2-OWASP-workspaces\evaluation\manifest.json -TotalCount 30
```

Với `--limit 200`, hai câu Count cần ra `200`; `verify` cần báo các nguồn còn nguyên vẹn. **Chỉ chạy kiểm tra nhãn trong Terminal cá nhân, không gửi `truth.csv` cho Codex.**

## 5. Codex Blind — phát hiện lỗ hổng độc lập

> **Nên làm bước này trước khi Codex xem bất cứ cảnh báo SAST nào.** Có thể chạy SAST trước bằng Python nhưng không được để Codex Blind đọc file SAST và kết quả đánh giá.

1. Trong PyCharm, **File → Open** riêng thư mục `..\E2-OWASP-workspaces\blind` như một project mới.
2. Mở JetBrains AI Assistant, chọn **Codex Agent**, đăng nhập ChatGPT nếu được yêu cầu.
3. Đọc `AGENTS.md`, sau đó gửi toàn bộ `PROMPT_DETECT.md` vào Codex.
4. Yêu cầu xử lý lần lượt **10–20 testcase/lượt**, đọc mã thật, không suy luận từ tên testcase hoặc nhãn OWASP.
5. Ghi `results/ai.json` là một **JSON array**, đủ một kết quả trên **mỗi** file, kể cả khi `cwes=[]`.
6. Không chỉnh sửa `samples/`, không truy cập repo gốc hoặc `evaluation/`, không chạy Semgrep/Bandit trong Blind.

Ví dụ schema, **không phải nhãn hoặc dự đoán thật**:

```json
[
  {"sample_id":"BenchmarkTest00001","cwes":["CWE-22"],"evidence":"Dòng mã và lập luận cụ thể"},
  {"sample_id":"BenchmarkTest00002","cwes":[],"evidence":"Chưa tìm thấy bằng chứng"}
]
```

Kiểm tra JSON và số mẫu từ Terminal `E2-Codex/`:

```powershell
python -c "import json,pathlib; w=pathlib.Path('../E2-OWASP-workspaces/blind'); d=json.loads((w/'results/ai.json').read_text(encoding='utf-8-sig')); names={p.stem for p in (w/'samples').glob('*.py')}; ids=[x['sample_id'] for x in d]; print('Records:',len(d),'Unique:',len(set(ids)),'Expected:',len(names)); print('Missing:',sorted(names-set(ids))); print('Unexpected:',sorted(set(ids)-names))"
```

Chỉ qua bước này khi `Records = Unique = Expected`, `Missing = []`, `Unexpected = []`. Nếu AI không chắc, ghi nhận không đủ bằng chứng; **không được tự cho toàn bộ mẫu chưa phân tích là an toàn**.

## 6. Semgrep + Bandit — Scan trên Hybrid

Đây là bước bạn đã chạy thành công trong lượt thực nghiệm hiện tại. Có thể thực hiện trước hoặc sau Blind về mặt kỹ thuật, nhưng **không xem/gửi cảnh báo SAST cho phiên Blind**.

Từ Terminal `E2-Codex/`:

```powershell
python owasp_pipeline.py verify
python owasp_pipeline.py scan --semgrep-config p/python
```

`scan` chạy trong thư mục `../E2-OWASP-workspaces/hybrid` trên `samples/`. Mặc định `p/python` là ruleset Semgrep; Bandit phân tích mã Python. Kết quả chuẩn hóa `sast.json` nhóm **mỗi cặp `(sample_id, CWE)` thành một bản ghi**, trong `sources` ghi từng công cụ, vị trí dòng và ID rule.

### 6.1 Cấu trúc thư mục `hybrid/results/` sau scan

```text
hybrid/results/
├── semgrep.json                # Kết quả thô Semgrep, chứa results/errors/paths
├── bandit.json                 # Kết quả thô Bandit, chứa results/errors/metrics
├── versions.json               # Phiên bản công cụ đã dùng
├── sast.json                   # Kết quả chuẩn hóa, gộp theo testcase + CWE
├── semgrep_errors.json         # Có nếu dùng hàm scan đã chỉnh để lưu log lỗi
├── bandit_errors.json          # Có nếu dùng hàm scan đã chỉnh để lưu log lỗi
├── scan_status.json            # Có nếu dùng hàm scan đã chỉnh để ghi trạng thái
└── ...                         # Các file Codex sẽ tạo ở bước sau
```

**Phân biệt phiên bản script:** bản `owasp_pipeline.py` trong ZIP v2 ban đầu sẽ **dừng khi JSON scanner có `errors`**; bản `scan()` bạn sửa trên máy đã thêm lưu log, xuất Bandit JSON trực tiếp ra file và `scan_status.json`. Các file log/status cuối bảng **không được bảo đảm có trong mọi phiên bản**. Mọi lượt phân tích phải kiểm tra `errors` và mức độ bao phủ; không coi một lượt scan lỗi parser là đầy đủ.

### 6.2 Đọc kết quả và số lượng testcase có cảnh báo

```powershell
$base = '..\E2-OWASP-workspaces\hybrid\results'
$sast = Get-Content "$base\sast.json" -Raw | ConvertFrom-Json
$sem  = Get-Content "$base\semgrep.json" -Raw | ConvertFrom-Json
$ban  = Get-Content "$base\bandit.json" -Raw | ConvertFrom-Json

"Semgrep findings: $($sem.results.Count)"
"Semgrep errors: $($sem.errors.Count)"
"Bandit findings: $($ban.results.Count)"
"Bandit errors: $($ban.errors.Count)"
"Pairs (sample_id + CWE): $($sast.Count)"
"Testcases with alert: $(($sast.sample_id | Sort-Object -Unique).Count)"
```

**Thống kê của lượt quét bạn đã gửi (17/11/2026):** Semgrep **56 findings**, Bandit **156 findings**, `sast.json` có **105 cặp testcase + CWE trên 87 testcase**. Đây là **cảnh báo SAST**, không phải 87 testcase chắc chắn có lỗ hổng. Hãy lấy số liệu từ JSON cho từng lượt chạy; đừng dùng các số này như kết quả cố định của dataset.

Xem danh sách testcase + CWE + công cụ:

```powershell
$sast | Group-Object sample_id | ForEach-Object {
    [PSCustomObject]@{
        TestCase = $_.Name
        CWE      = ($_.Group.cwe -join ', ')
        Tools    = (($_.Group.sources.tool | Sort-Object -Unique) -join ', ')
        CWEPairs = $_.Count
    }
} | Sort-Object TestCase | Format-Table -AutoSize
```

Xuất Excel-friendly CSV:

```powershell
$sast | Group-Object sample_id | ForEach-Object {
    [PSCustomObject]@{
        TestCase = $_.Name
        CWE      = ($_.Group.cwe -join ', ')
        Tools    = (($_.Group.sources.tool | Sort-Object -Unique) -join ', ')
        CWEPairs = $_.Count
    }
} | Sort-Object TestCase | Export-Csv '.\SAST_Testcases.csv' -NoTypeInformation -Encoding UTF8
```

### 6.3 Khi scanner không ra JSON hoặc báo parser error

- **Bandit:** lỗi `json.decoder.JSONDecodeError: Expecting value` tại `json.loads(ban)` nghĩa là stdout không có JSON hợp lệ. Có thể chạy độc lập: `python -m bandit -r ..\E2-OWASP-workspaces\hybrid\samples -f json -o bandit_debug.json`, rồi mở JSON và đọc stderr. Bản hàm `scan()` đã sửa trên máy bạn đưa `-o` trực tiếp vào `hybrid/results/bandit.json` và đọc từ file.
- **Semgrep:** `errors` kiểu `Syntax error`, chẳng hạn `guess was unexpected`, là lỗi parser của Semgrep. Bạn đã kiểm tra `python -m py_compile` và thấy **21 file hợp lệ với Python**, nhưng chưa khẳng định Semgrep đã quét đầy đủ tất cả các file đó. Giữ log, xem `paths.scanned` và phạm vi ảnh hưởng, không chỉnh nguồn OWASP theo phỏng đoán.
- Nếu phải chạy scan ở hệ điều hành khác, copy **cả hai** file raw `semgrep.json` và `bandit.json` vào `hybrid/results/`, sau đó `python owasp_pipeline.py normalize`. Với script ZIP v2 gốc, `normalize` **từ chối** JSON chứa `errors` khác rỗng.

## 7. Codex Hybrid — xác minh 105 cặp testcase + CWE

1. **Đóng Blind**, mở riêng `..\E2-OWASP-workspaces\hybrid` bằng PyCharm.
2. Mở `AGENTS.md` và gửi `PROMPT_TRIAGE.md` vào Codex; chỉ cho đọc `samples/` và `results/sast.json`.
3. Yêu cầu xử lý theo lô **10–20 cặp/lượt** rồi hợp nhất thành một JSON array `results/triage.json`.
4. Với **mỗi** cặp `(sample_id, cwe)` trong SAST, đưa ra một trong 3 trạng thái: `CONFIRMED`, `FALSE_POSITIVE`, `UNCERTAIN` và giải thích bằng chứng.
5. Không đọc `evaluation/truth.csv`, không đọc Blind `ai.json`, không tự thêm cặp CWE khác SAST, không sửa `samples/`.

Schema:

```json
[
  {"sample_id":"BenchmarkTest00058","cwe":"CWE-327","status":"CONFIRMED","explanation":"Phân tích mã nguồn và bối cảnh"}
]
```

Ví dụ chỉ minh họa định dạng, không phải kết luận kiểm chứng.

Đếm số cặp trong `triage.json`:

```powershell
python -c "import json,pathlib; w=pathlib.Path('../E2-OWASP-workspaces/hybrid/results'); s=json.loads((w/'sast.json').read_text(encoding='utf-8-sig')); t=json.loads((w/'triage.json').read_text(encoding='utf-8-sig')); ks={(x['sample_id'],x['cwe']) for x in s}; kt=[(x['sample_id'],x['cwe']) for x in t]; print('SAST:',len(ks),'Triage:',len(t),'Unique:',len(set(kt)),'Missing:',len(ks-set(kt)),'Extra:',len(set(kt)-ks))"
```

Với dữ liệu hiện tại, mục tiêu là **105 bản ghi duy nhất**, không phải 87. **87** là số testcase có cảnh báo, còn **105** là số cặp testcase+CWE cần phân loại.

## 8. Evaluation — đối chiếu Ground Truth

Chỉ chạy sau khi `blind/results/ai.json` và `hybrid/results/triage.json` đầy đủ:

```powershell
python owasp_pipeline.py verify
python owasp_pipeline.py evaluate
```

Script kiểm tra số mẫu AI, tính duy nhất và tính hợp lệ của CWE; kiểm tra `triage` khớp chính xác mọi cặp của SAST; sau đó tạo:

```text
evaluation/
├── truth.csv                     # Đã tạo từ import
├── hashes.json                   # Đã tạo từ import
├── manifest.json                 # Đã tạo từ import
├── metrics.json                  # TP, FP, FN, TN, precision, recall, FNR, F1
├── metrics.csv                   # Kết quả trên từng phương pháp
└── coverage.json                 # Số mẫu, phân bố CWE, UNCERTAIN, quy tắc scoring
```

Phương pháp được chấm:

| Khóa trong `metrics.json` | Ý nghĩa |
|---|---|
| `Semgrep` | Chỉ các cặp CWE từ Semgrep |
| `Bandit` | Chỉ các cặp CWE từ Bandit |
| `AI_independent` | Dự đoán riêng của Codex Blind |
| `SAST_union` | Hợp các cặp từ Semgrep và Bandit |
| `SAST_plus_Codex` | SAST sau khi loại các cặp Codex kết luận `FALSE_POSITIVE`; vẫn giữ `UNCERTAIN` |

**Quy tắc đánh giá thực tế trong source:** mỗi dòng `truth.csv` có **một CWE mục tiêu**; chỉ dự đoán trùng cả `(sample_id, CWE mục tiêu)` được xem là phát hiện của testcase đó. CWE khác có thể được ghi nhận trong raw JSON nhưng **không tính TP cho CWE mục tiêu**. Nếu một scanner không xử lý được file, không được coi file đó là trường hợp âm tính hợp lệ mà không ghi rõ giới hạn đánh giá.

Công thức:

```text
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
FNR       = FN / (FN + TP)
F1        = 2TP / (2TP + FP + FN)
```

`evaluate` **không tự kiểm chứng Codex đã lập luận đúng** và **không kiểm định bản vá**. Không nên công bố kết quả từ lượt scan còn lỗi parser/bỏ qua file mà không mô tả, phân tích độ bao phủ.

## 9. Codex Repair — tạo bản vá và kiểm tra độc lập

Trong PyCharm đang mở workspace `hybrid`, gửi `PROMPT_REPAIR.md`:

- Chọn những trường hợp Codex triage đã phân loại `CONFIRMED` để thử nghiệm bản vá.
- Sao chép file cần sửa từ `samples/` sang `patched/`, sửa ở bản sao, giữ nguyên API/chức năng cần thiết.
- Ghi `results/patch_results.json` kèm testcase, CWE, thay đổi, trạng thái test và bằng chứng.
- Chạy kiểm tra cú pháp, bộ test chức năng và test bảo mật độc lập khi có phụ thuộc phù hợp.
- Nếu chưa chứng minh được bản vá an toàn, ghi `NOT_VALIDATED`, không tự khẳng định thành công chỉ vì SAST không cảnh báo.

Ví dụ kiểm tra cú pháp một bản vá:

```powershell
python -m py_compile ..\E2-OWASP-workspaces\hybrid\patched\BenchmarkTest00058.py
```

Chỉ chạy mẫu lệnh nếu file patch tương ứng thực sự tồn tại. **Không** dùng `python validate_patch.py` để chấm OWASP: script đó dành cho demo S001. Mã OWASP có thể cần package/helper/resource của repo gốc để kiểm thử runtime; việc `py_compile` thành công chỉ xác nhận cú pháp, không chứng minh lỗi đã được vá.

## 10. Tổng hợp lệnh thường dùng

Chạy từ `E2-Codex/`:

```powershell
# Xem cách sử dụng
python owasp_pipeline.py --help

# Lần đầu: clone + import 200 mẫu
git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git owasp-benchmark
python owasp_pipeline.py import-owasp --repo .\owasp-benchmark --limit 200 --seed 42

# Kiểm tra toàn vẹn trước/sau các bước
python owasp_pipeline.py verify

# Chạy quét SAST trên hybrid
python owasp_pipeline.py scan --semgrep-config p/python

# Chỉ chuẩn hóa lại nếu đã có cả 2 file scanner JSON hợp lệ
python owasp_pipeline.py normalize

# Sau khi Codex tạo đủ blind/results/ai.json và hybrid/results/triage.json
python owasp_pipeline.py evaluate
```

Nếu dùng `--work` tùy chọn thì phải truyền cùng một đường dẫn vào **mọi lệnh** (`import-owasp`, `scan`, `normalize`, `verify`, `evaluate`). `--limit 0` chọn toàn bộ nhãn có trong phiên bản repo; chọn một workspace mới, không ghi đè lượt chạy 200 mẫu.

## 12. Nguồn tham khảo

- [OWASP BenchmarkPython — GitHub](https://github.com/OWASP-Benchmark/BenchmarkPython)
- [OWASP Benchmark — project](https://owasp.org/www-project-benchmark/)
- [JetBrains — Codex Agent](https://www.jetbrains.com/help/ai-assistant/codex-agent.html)
