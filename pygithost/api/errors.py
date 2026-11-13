"""Public API failures. Never return internal exception text to clients."""


class APIError(Exception):
    def __init__(self, status, code, message, *, headers=()):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = list(headers)
