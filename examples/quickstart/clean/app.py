"""Safe counterpart to the PatchFlow demo fixture."""

import ast


def calculate(user_expression: str):
    return ast.literal_eval(user_expression)
