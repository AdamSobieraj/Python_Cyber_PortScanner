def check_if_number(input_string):
    try:
        float(input_string)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    check_if_number("10")
