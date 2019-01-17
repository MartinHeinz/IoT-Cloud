def is_number(s):
    try:
        int(s)
        return True
    except ValueError:
        return False
