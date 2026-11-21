# Hướng dẫn chạy trên OWASP BenchmarkPython

Các lệnh chạy từ thư mục project. Workspace mặc định: `../E2-OWASP-workspaces/`.

```text
1. clone ─► 2. import-owasp ─► 3. scan ─► 4. chạy từng AI ─► 5. evaluate
```

## 1. Clone bộ dữ liệu

```powershell
git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git owasp-benchmark
git -C .\owasp-benchmark rev-parse HEAD    # ghi lại commit để tái lập
```

Repo cần có `testcode/BenchmarkTest*.py` và `expectedresults-0.1.csv` (đáp án).

## 2. Tạo workspace

```powershell
python owasp_pipeline.py import-owasp --repo .\owasp-benchmark --limit 200 --seed 42
python owasp_pipeline.py verify
```

| Tham số | Ý nghĩa |
|---|---|
| `--limit` | Số testcase (`0` = tất cả), chọn phân tầng theo CWE và nhãn |
| `--seed` | Cố định việc chọn mẫu |
| `--agents` | Các AI cần tạo workspace, mặc định `codex,claude`. Luôn có `codex` |
| `--work` | Đổi thư mục workspace. Nếu dùng, phải truyền cho **mọi** lệnh |

Kết quả:

```text
E2-OWASP-workspaces/
├── blind_codex/       samples/  results/  patched/  AGENTS.md  PROMPT_DETECT.md
├── hybrid_codex/      samples/  results/  patched/  AGENTS.md  PROMPT_TRIAGE.md  PROMPT_REPAIR.md
├── blind_claude/      như blind_codex/, kèm CLAUDE.md và .claude/settings.json
├── hybrid_claude/     như hybrid_codex/, kèm CLAUDE.md và .claude/settings.json
└── evaluation/        truth.csv  hashes.json  manifest.json
```

- Thêm Claude vào một lượt chạy đã có: `python owasp_pipeline.py add-agent claude`.
- Thêm AI khác: tạo `blind_<tên>/` và `hybrid_<tên>/` theo cấu trúc trên, chép `samples/` và `results/sast.json` từ `hybrid_codex/`. `verify` và `evaluate` sẽ tự nhận.
- `verify` kiểm tra `samples/` của mọi workspace còn nguyên bản gốc (SHA-256). Nên chạy trước và sau mỗi bước.

## 3. Quét SAST

```powershell
python owasp_pipeline.py scan --semgrep-config p/python
```

Quét một lần trong `hybrid_codex/`, rồi sao `sast.json` sang các `hybrid_<tên>/` khác. Kết quả trong `hybrid_codex/results/`:

| File | Nội dung |
|---|---|
| `sast.json` | Cảnh báo đã chuẩn hóa, mỗi cặp `(sample_id, CWE)` một bản ghi |
| `semgrep.json`, `bandit.json` | Kết quả thô |
| `scan_status.json`, `semgrep_coverage.json` | Trạng thái quét, các file Semgrep không phân tích được |
| `versions.json` | Phiên bản công cụ |

## 4. Chạy từng AI

Với mỗi AI, làm lần lượt 3 bước. Mỗi bước mở **phiên mới** và chỉ mở **đúng workspace** của bước đó.

| Bước | Workspace | Gửi prompt | AI ghi ra |
|---|---|---|---|
| Blind | `blind_<tên>/` | `PROMPT_DETECT.md` | `results/ai.json` |
| Hybrid | `hybrid_<tên>/` | `PROMPT_TRIAGE.md` | `results/triage.json` |
| Repair | `hybrid_<tên>/` | `PROMPT_REPAIR.md` | `patched/`, `results/patch_results.json` |

Cách mở:

- **Codex:** PyCharm → File → Open workspace → AI Assistant → Codex Agent.
- **Claude:** `cd ..\E2-OWASP-workspaces\blind_claude` rồi chạy `claude`. Claude Code tự áp dụng `CLAUDE.md` và `.claude/settings.json` (chặn web, chặn đọc `evaluation/` và workspace khác, chặn sửa `samples/`).

Định dạng kết quả:

```jsonc
// results/ai.json — một bản ghi cho MỌI file trong samples/, không thấy lỗi thì "cwes": []
[{"sample_id": "BenchmarkTest00001", "cwes": ["CWE-22"], "evidence": "..."}]

// results/triage.json — một bản ghi cho MỖI cặp trong sast.json
// status: CONFIRMED | FALSE_POSITIVE | UNCERTAIN
[{"sample_id": "BenchmarkTest00001", "cwe": "CWE-22", "status": "CONFIRMED", "explanation": "..."}]
```

Ghi lại model, phiên bản và ngày chạy của từng AI.

## 5. Đánh giá

```powershell
python owasp_pipeline.py evaluate
```

Lệnh tự tìm mọi AI có workspace `blind_<tên>/`, `hybrid_<tên>/` để chấm và so sánh.

Kết quả trong `evaluation/`:

| File | Nội dung |
|---|---|
| `metrics.json`, `metrics.csv` | TP, FP, FN, TN, precision, recall, FNR, F1 của từng phương pháp |
| `comparison.json` | Bảng so sánh các AI, xếp hạng theo F1 |
| `agreement.json` | Mức đồng thuận giữa từng cặp AI (Cohen's kappa); chỉ có khi ≥ 2 AI |
| `coverage.json` | AI được chấm, AI thiếu kết quả, phân bố CWE, số `UNCERTAIN` |

Các phương pháp:

| Phương pháp | Ý nghĩa |
|---|---|
| `Semgrep`, `Bandit`, `SAST_union` | Cảnh báo SAST |
| `<AI>_independent` | Kết quả Blind của AI |
| `SAST_plus_<AI>` | SAST bỏ đi các cặp AI kết luận `FALSE_POSITIVE` |
| `Union_<AIs>_independent` | Ít nhất một AI phát hiện |
| `Intersection_<AIs>_independent` | Mọi AI cùng phát hiện |
| `SAST_plus_<AIs>_consensus` | Chỉ bỏ cảnh báo khi **mọi** AI kết luận `FALSE_POSITIVE` |

Một dự đoán chỉ được tính khi khớp **(testcase, CWE mục tiêu)** của đáp án.
