# Praetor convenience runner (Windows PowerShell)
param(
    [Parameter(Position = 0)]
    [ValidateSet("demo", "test", "serve", "install")]
    [string]$Task = "demo"
)

switch ($Task) {
    "install" { python -m pip install -r requirements.txt }
    "demo"    { python demo.py }
    "test"    { python -m pytest -q }
    "serve"   { python -m uvicorn praetor.server:app --reload --port 8088 }
}
