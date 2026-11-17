# E2 - AI phát hiện và vá lỗ hổng so với công cụ phân tích tĩnh (Codex GPT vs Bandit & Semgrep)


> **Mục tiêu:** So sánh khả năng phát hiện lỗ hổng của **Semgrep**, **Bandit**, **Codex độc lập (Blind)** và **SAST + Codex (Hybrid)**; sau đó thử nghiệm sinh bản vá bằng Codex. Dự án dùng **Codex tích hợp trong PyCharm với tài khoản ChatGPT Plus**. Các script Python xử lý dữ liệu, chạy công cụ SAST, chuẩn hóa và chấm điểm; **không tự động gọi Codex**.

## 1. Chọn đúng quy trình

Dự án có **hai pipeline độc lập**, không được dùng lẫn workspace hoặc file kết quả:

| Pipeline | Script | Dữ liệu | Workspace mặc định | Dùng khi nào |
|---|---|---|---|---|
| **Demo** | `pipeline.py` | 6 file Python tự tạo trong `demo_source/` | `../E2-workspaces/` | Kiểm tra logic pipeline ở quy mô nhỏ |
| **Nghiên cứu OWASP** | `owasp_pipeline.py` | OWASP Benchmark Python v0.1, clone bên ngoài | `../E2-OWASP-workspaces/` | Thực nghiệm chính thức và tính chỉ số |

**Nếu đang làm thí nghiệm OWASP 200 testcase:** đi thẳng đến **[README_OWASP.md](README_OWASP.md)**. README này giải thích kiến trúc chung và cách thử demo.

## 2. Cấu trúc thư mục project

```text
E2-Codex/                        # Thư mục gốc, mở trong PyCharm để chạy pipeline
├── README.md                    # Tài liệu hiện tại
├── README_OWASP.md              # Hướng dẫn OWASP từ clone đến evaluation
├── owasp_pipeline.py            # Nhập OWASP / scan / normalize / verify / evaluate
├── pipeline.py                  # Pipeline demo 6 mẫu
├── validate_patch.py            # Kiểm thử bản vá S001 của DEMO, không áp cho OWASP
├── requirements.txt             # bandit, semgrep, pytest
├── AGENTS.md                    # Quy tắc cho Codex ở nhánh demo
├── prompts/
│   ├── detect.txt               # Prompt Codex Blind — demo
│   ├── triage.txt               # Prompt Codex Hybrid — demo
│   └── repair.txt               # Prompt tạo patch — demo
├── rules/
│   └── e2.yml                   # Rules Semgrep DEMO, không phải bộ rules OWASP đầy đủ
├── demo_source/
│   └── S001.py ... S006.py      # 6 testcase minh họa
├── private/
│   └── demo_truth.csv           # Nhãn đúng của demo; KHÔNG đưa cho Codex
├── tests/
│   ├── test_pipeline.py         # Kiểm thử pipeline demo
│   └── test_owasp_pipeline.py   # Kiểm thử pipeline OWASP bằng dữ liệu giả lập
├── QA.md
└── QA_OWASP.md
```

Các workspace thí nghiệm được tạo **cạnh** `E2-Codex`, không nằm bên trong dự án. Khi mở agent Codex, chỉ mở **một** workspace `blind` hoặc `hybrid`, tránh lộ đáp án từ `evaluation`.

### Workspace demo sau `python pipeline.py prepare`

```text
D:/DT/2025.B1/IT5421-CD1/
├── E2-Codex/
└── E2-workspaces/
    ├── blind/
    │   ├── samples/             # Bản sao 6 file Python
    │   ├── results/             # Codex ghi ai.json
    │   ├── patched/             # Thư mục dự phòng; không dùng để ghi source gốc
    │   ├── AGENTS.md
    │   └── prompt.txt           # Nội dung prompts/detect.txt
    ├── hybrid/
    │   ├── samples/             # Bản sao 6 file Python, giữ nguyên
    │   ├── results/             # semgrep.json, bandit.json, sast.json, triage.json...
    │   ├── patched/             # Chỉ chứa mã đã vá
    │   ├── AGENTS.md
    │   ├── prompt.txt           # Nội dung prompts/triage.txt
    │   └── repair.txt           # Nội dung prompts/repair.txt
    └── evaluation/
        ├── truth.csv            # Đáp án chuẩn; không cho Codex đọc
        ├── hashes.json          # SHA-256 của mã nguồn ban đầu
        ├── metrics.json         # Sau khi evaluate
        └── metrics.csv          # Sau khi evaluate
```

**Workspace OWASP có tên prompt khác với demo:** `PROMPT_DETECT.md`, `PROMPT_TRIAGE.md`, `PROMPT_REPAIR.md`. Xem cây thư mục đầy đủ trong [README_OWASP.md](README_OWASP.md).

## 3. Chuẩn bị môi trường Windows / PyCharm

**Yêu cầu:** Git (nếu dùng OWASP), Python, PyCharm, tài khoản ChatGPT có thể truy cập Codex trong JetBrains, mạng để lấy Semgrep rules lần đầu (khi dùng `p/python`). Đảm bảo lệnh `semgrep` thực thi được trong đúng Terminal/venv. Nếu bản Semgrep trên Windows gặp lỗi, có thể dùng môi trường Linux/WSL tương thích; phải ghi nhận môi trường thực nghiệm.

Mở **Terminal tại `E2-Codex/`**, thực hiện:

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest tests -q
python -m bandit --version
semgrep --version
```

Nếu PowerShell không cho phép chạy `Activate.ps1`, có thể gọi trực tiếp `\.venv\Scripts\python.exe` thay cho `python`, hoặc chỉnh ExecutionPolicy theo chính sách máy. Tránh cài lẫn vào Python hệ thống. Trên Linux/WSL: `source .venv/bin/activate`.

**Lưu ý phiên bản:** `requirements.txt` trong bản phát hành này pin `bandit==1.8.6`, `semgrep==1.150.0`, `pytest==8.3.5`. Nếu bạn đã nâng cấp Semgrep/Bandit để xử lý lỗi parser hoặc JSON, hãy ghi phiên bản thực tế (`versions.json`) và cố định môi trường trước khi đánh giá.

## 4. Chạy thử pipeline DEMO: từng bước

> Nếu đã có `../E2-workspaces/`, **không chạy lại `prepare`** trên cùng đường dẫn: lệnh chủ động dừng để không ghi đè kết quả. Hãy sao lưu/đổi tên workspace cũ nếu muốn làm lại.

### Bước D1 — Tạo workspace demo

```powershell
python pipeline.py prepare
```

- Đọc `demo_source/*.py` và `private/demo_truth.csv`.
- Kiểm tra mỗi file có đúng một nhãn.
- Sao chép mã nguồn sang `blind/samples/` và `hybrid/samples/`.
- Tách đáp án vào `evaluation/truth.csv`; tạo hash SHA-256 trong `evaluation/hashes.json`.
- **Chưa có quét SAST hay gọi Codex ở bước này.**

### Bước D2 — Codex Blind (không có SAST)

1. Trong PyCharm, **mở riêng** `../E2-workspaces/blind` bằng **File → Open**.
2. Trong AI Chat, chọn agent Codex, đăng nhập bằng ChatGPT; đưa nội dung `prompt.txt` cho Codex.
3. Yêu cầu Codex đọc mọi file `samples/*.py`, phân tích độc lập và ghi `results/ai.json` dưới dạng **JSON array**.
4. Mỗi mẫu cần đúng một bản ghi, kể cả không phát hiện lỗ hổng (`"cwes": []`).

Ví dụ **minh họa schema**, không phải kết quả thực nghiệm:

```json
[
  {"sample_id": "S001", "cwes": ["CWE-89"], "evidence": "S001.py:..."},
  {"sample_id": "S002", "cwes": [], "evidence": "Không đủ bằng chứng"}
]
```

Kiểm tra số bản ghi từ project gốc:

```powershell
python -c "import json,pathlib; p=pathlib.Path('../E2-workspaces/blind/results/ai.json'); d=json.loads(p.read_text(encoding='utf-8-sig')); print('Records:',len(d),'Unique:',len({x['sample_id'] for x in d}))"
```

### Bước D3 — Quét SAST demo

Quay về Terminal `E2-Codex/`:

```powershell
python pipeline.py scan
```

Script chạy Semgrep theo `rules/e2.yml` và Bandit, tạo `../E2-workspaces/hybrid/results/semgrep.json`, `bandit.json`, `sast.json`, `versions.json`. **Không chạy demo scan cho tập OWASP**; tập OWASP dùng `owasp_pipeline.py scan` và `p/python`.

### Bước D4 — Codex Hybrid

1. Mở riêng `../E2-workspaces/hybrid` trong PyCharm.
2. Đưa nội dung `prompt.txt` cho Codex; cho phép đọc `results/sast.json` và `samples/` **nhưng không đọc `evaluation/` hoặc Blind**.
3. Ghi `results/triage.json`. Với mỗi cặp `(sample_id, cwe)` trong SAST phải có đúng một kết luận: `CONFIRMED`, `FALSE_POSITIVE` hoặc `UNCERTAIN`.

Ví dụ:

```json
[{"sample_id":"S001","cwe":"CWE-89","status":"CONFIRMED","evidence":"..."}]
```

### Bước D5 — Đánh giá

Khi `ai.json` và `triage.json` đã đủ bản ghi:

```powershell
python pipeline.py evaluate
```

Đọc `../E2-workspaces/evaluation/metrics.json` và `metrics.csv`. Chỉ so sánh đúng cặp **testcase + CWE mục tiêu**; Codex `UNCERTAIN` được giữ như cảnh báo dương trong kết quả Hybrid bảo thủ.

### Bước D6 — Thử vá mã nguồn demo

Trong workspace `hybrid`, gửi `repair.txt` cho Codex, yêu cầu chỉ sửa bản sao trong `patched/`, **không sửa `samples/`**. Với **mẫu demo S001**, có thể kiểm tra theo script có sẵn:

```powershell
python validate_patch.py
```

`validate_patch.py` không phải bộ kiểm thử chung cho OWASP. Không coi “Semgrep/Bandit không cảnh báo” là bằng chứng một bản vá an toàn.

## 5. Quy trình nghiên cứu OWASP (đề tài chính)

Toàn bộ quy trình được hướng dẫn, kèm lệnh kiểm tra và cây thư mục, trong **[README_OWASP.md](README_OWASP.md)**:

```powershell
# 1) Clone OWASP -> 2) Import 200 mẫu -> 3) SAST ->
# 4) Codex Blind -> 5) Codex Hybrid -> 6) Evaluation -> 7) Repair
python owasp_pipeline.py --help
```

Lưu ý: các bước Blind và Hybrid là **thao tác thủ công bằng Codex trong PyCharm**, không phải lệnh Python tự gọi AI. Phần **Repair** chưa có công cụ chấm bản vá hoàn toàn tự động trên toàn bộ OWASP corpus.

## 6. Đọc kết quả và hiểu các chỉ số

| Chỉ số | Diễn giải |
|---|---|
| TP | Dự đoán có đúng CWE mục tiêu và mẫu thực sự có lỗ hổng |
| FP | Dự đoán có CWE mục tiêu nhưng nhãn của mẫu là không có lỗ hổng |
| FN | Không phát hiện CWE mục tiêu trên mẫu có lỗ hổng |
| TN | Không phát hiện CWE mục tiêu trên mẫu không có lỗ hổng |
| Precision | `TP / (TP + FP)` |
| Recall | `TP / (TP + FN)` |
| F1 | `2TP / (2TP + FP + FN)` |

Chỉ số trên áp dụng theo **CWE đích** được gán cho từng testcase, không đồng nghĩa khẳng định mã nguồn không có bất kỳ vấn đề bảo mật nào khác. Không được suy đoán mẫu thiếu kết quả là an toàn. `UNCERTAIN` trong Hybrid được giữ như cảnh báo; Hybrid chỉ lọc cảnh báo SAST nên Recall theo cách đánh giá này không thể vượt `SAST_union`.

## 7. An toàn, tính khách quan và khắc phục lỗi nhanh

- **Chống lộ nhãn:** không mở project cha bao gồm `blind/`, `hybrid/`, `evaluation/` trong phiên Codex; không đưa `truth.csv`, `expectedresults-0.1.csv`, lịch sử Git upstream hoặc kết quả Blind vào Hybrid.
- **Giữ nguyên mã nguồn:** không cho agent sửa `samples/`; hash ban đầu dùng để phát hiện thay đổi. Lưu bản vá riêng trong `patched/`.
- **Kết quả SAST:** số *findings* khác số *testcase*. `sast.json` nhóm theo `(sample_id, CWE)`, gộp nguồn Semgrep/Bandit. Lỗi parser, file không quét được hoặc lỗi môi trường cần được ghi nhận riêng; không âm thầm coi như âm tính.
- **Bandit lỗi JSON:** nếu `json.loads` nhận stdout rỗng, dùng đầu ra file `bandit.json` và xem `stderr`. Trong các bản script đã được chỉnh sửa tại máy người dùng, phải đối chiếu với mã thực tế trước khi áp dụng hướng dẫn lỗi.
- **Nguồn và phiên bản:** lưu commit OWASP, seed, giới hạn mẫu, phiên bản Python/Semgrep/Bandit, bộ rules, prompt và phiên bản/môi trường Codex để tái lập thực nghiệm.
- **Chạy mã không tin cậy:** patch/test bằng máy ảo hoặc container cô lập, không có secret; tránh cấp mạng hoặc quyền hệ thống không cần thiết.

## 8. Tài liệu tham khảo

- [README_OWASP.md](README_OWASP.md) — hướng dẫn chi tiết cho OWASP
- [OWASP BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython) — nguồn mã và nhãn chuẩn
- [OWASP Benchmark](https://owasp.org/www-project-benchmark/) — giới thiệu bộ benchmark
- [JetBrains Codex Agent](https://www.jetbrains.com/help/ai-assistant/codex-agent.html) — tích hợp PyCharm
