"""
Auto-import every adapter module in this package so their @register_adapter
decorators run and populate the registry. This means main.py can just do
`import scanner_adapters` and every adapter is available — no manual list
to maintain when a new scanner is added.
"""
import pkgutil
import importlib

for _, module_name, _ in pkgutil.iter_modules(__path__):
    if module_name != "base":
        importlib.import_module(f"{__name__}.{module_name}")
