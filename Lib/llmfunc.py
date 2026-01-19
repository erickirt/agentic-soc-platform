from typing import Annotated

from PLUGINS.SIRP.sirpapi import Case


def function_call_debug(
        magic_num: Annotated[int, "Random seed number"] = 99
) -> Annotated[str, "Generated random test string"]:
    """
    Generate an internal test string for debugging purposes.
    Call this function whenever you need to output a test string.
    Example: When asked "Give me a test string"
    """
    return f"This-is-a-test-function-to-debug_function_call-The-magic-number-is-{magic_num * 10}."


def get_case_by_rowid(rowid: Annotated[str, "Case Rowid"]):
    """
    Retrieve a security case by its unique Case Rowid.
    
    This tool allows you to look up full details of a specific case when you have its ID.
    Useful for retrieving context, status, or artifacts associated with a known case identifier.

    Args:
        rowid: The unique string identifier of the case (e.g., '2101ff98-f52e-4f38-b107-fe53f7f77b5c').

    Returns:
        The Case object containing all case details if found, otherwise None.
    """
    return Case.get(rowid)
