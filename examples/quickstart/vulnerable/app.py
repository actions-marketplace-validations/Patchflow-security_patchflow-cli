"""Intentionally vulnerable PatchFlow demo fixture. Do not deploy."""


def calculate(user_expression: str):
    # Deliberately unsafe so the public quickstart always demonstrates PY001.
    return eval(user_expression)
