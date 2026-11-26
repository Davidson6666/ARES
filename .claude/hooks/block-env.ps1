# Bloqueia edicao de arquivos .env (exceto .env.example).
# Regra: segredos nunca no repositorio (CLAUDE.md, secao 9.1).
# Entrada: JSON do Claude Code via stdin. Saida 2 = bloqueia a ferramenta.

$raw = [Console]::In.ReadToEnd()
try {
    $data = $raw | ConvertFrom-Json
} catch {
    exit 0
}

$path = $data.tool_input.file_path
if (-not $path) { exit 0 }

$name = Split-Path -Leaf $path
if (($name -match '^\.env(\..+)?$') -and ($name -ne '.env.example')) {
    [Console]::Error.WriteLine("Bloqueado: '$name' contem segredos. Edite .env manualmente; use .env.example para nomes e valores ficticios.")
    exit 2
}

exit 0
