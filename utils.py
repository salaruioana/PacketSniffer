import string

def is_mostly_printable(text, threshold=0.9):
    """
    Returns True if the given text is mostly composed of printable characters.
    Args:
        text (str): The input text to check.
        threshold (float): Percentage of printable characters required.
    Returns:
        bool
    """
    if not text:
        return False

    printable_chars = set(string.printable)
    num_printable = sum(1 for c in text if c in printable_chars)

    return (num_printable / len(text)) >= threshold