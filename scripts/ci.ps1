# Windows PowerShell 入口，与 scripts/ci.sh 和 GitHub Actions 保持同一套 Rust 命令。
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

function Step($name, [scriptblock]$body) {
    Write-Host "`n=== $name ===" -ForegroundColor Cyan
    & $body
    if ($LASTEXITCODE -ne 0) { throw "$name 失败（exit=$LASTEXITCODE）" }
}

Step '格式' { cargo fmt --all -- --check }
Step 'Clippy' { cargo clippy --workspace --all-targets -- -D warnings }
Step '构建' { cargo build --workspace }
Step '测试' {
    cargo test --workspace -- --test-threads=1 2>&1 | Tee-Object -FilePath 'target/ci-tests.log'
    if ($LASTEXITCODE -ne 0) { cargo run --offline -q -p dev-tools -- ci-failures target/ci-tests.log; throw '测试失败' }
}
Step 'Rust 源码与协议门禁' {
    cargo run --offline -q -p dev-tools -- gates
    cargo run --offline -q -p dev-tools -- package --selftest
}
Step '回归门禁' {
    cargo run --offline -q -p dev-tools -- baseline
    cargo run --offline -q -p dev-tools -- verify-dicts
}

if (Test-Path 'corpus\req.jsonl') {
    Step '真实语料门禁' { cargo run --offline -q -p dev-tools -- train --corpus corpus --out target/train-real }
} else {
    Write-Host "`n=== 跳过真实语料门禁（未发现 corpus\req.jsonl） ===" -ForegroundColor Yellow
}

Step 'Rust 语料门禁机制（合成夹具）' {
    cargo run --offline -q -p dev-tools -- smoke-corpus --out target/smoke-corpus
    cargo run --offline -q -p dev-tools -- train --corpus target/smoke-corpus --out target/smoke-out --smoke --sizes 512,1024,2048
}

Step 'Rust 有界长稳压测' {
    cargo run --offline -q -p dev-tools -- soak --duration 60 --interval 5 --rate 60 --server-cache-mb 1 --ttl-secs 6 --ceiling-only --out target/soak/ci.json
}

Write-Host "`n全部检查通过。" -ForegroundColor Green
