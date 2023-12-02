from flask import request

class BankLibrary:
    def __init__(self, User, secrets):
        self.User = User
        self.secrets = secrets

    def generate_unique_account_number(self):
        """
        Generate a unique account number.
        """
        while True:
            account_number = self.secrets.token_hex(6).upper()
            if not self.User.query.filter_by(account_number=account_number).first():
                return account_number

   